//! The riscv32imac signing-policy engine.
//!
//! Reuses `vanadium_common::vm` — the same interpreter the Vanadium VM runs V-Apps
//! with — over in-RAM memory. The app is itself interpreted RISC-V, so this is
//! nested interpretation: a policy instruction costs on the order of hundreds of
//! the app's own. Hence the accelerated ecalls and the step budget.

pub mod abi;
pub mod ecalls;
pub mod image;
pub mod memory;

use vanadium_common::{
    constants::PAGE_SIZE,
    vm::{Cpu, CpuError, MemorySegment},
};

use crate::policy::{host::PolicyHost, PolicyEngine, PolicyError, SigningDecision};

use ecalls::{PolicyEcallError, PolicyEcallHandler};
use image::{Image, CODE_START, DATA_START, STACK_START};
use memory::PolicyMemory;

pub struct RiscvEngine;

impl PolicyEngine for RiscvEngine {
    const ENGINE_ID: u8 = common::psbt::signing_policy::ENGINE_ID_RISCV;
    const ENGINE_VERSION: u8 = 0;

    fn validate(program: &[u8]) -> Result<(), PolicyError> {
        let image = Image::parse(program)?;
        if image.abi_version != Self::ENGINE_VERSION {
            return Err(PolicyError::InvalidImage);
        }
        Ok(())
    }

    fn evaluate(
        program: &[u8],
        host: &mut dyn PolicyHost,
    ) -> Result<SigningDecision, PolicyError> {
        let image = Image::parse(program)?;
        if image.abi_version != Self::ENGINE_VERSION {
            return Err(PolicyError::InvalidImage);
        }
        Sandbox::new(&image)?.run(host)
    }
}

/// One policy program, instantiated for one transaction.
///
/// Owns the three memory backings. The data segment's tail holds the shared state,
/// which is zeroed once here and preserved across every invocation; everything else
/// is restored before each one.
struct Sandbox<'a> {
    image: Image<'a>,
    code: PolicyMemory<'a>,
    data: PolicyMemory<'a>,
    stack: PolicyMemory<'a>,
}

impl<'a> Sandbox<'a> {
    fn new(image: &Image<'a>) -> Result<Self, PolicyError> {
        Ok(Self {
            image: *image,
            code: PolicyMemory::code(image.code()),
            // The backing is zero-filled, which is exactly the initial shared state.
            data: PolicyMemory::rw(image::n_pages(image.data_len) as usize),
            stack: PolicyMemory::rw(image::n_pages(image.stack_len) as usize),
        })
    }

    /// Invoke the program once per attempt, then once for deferred checks, folding
    /// every verdict with `min`.
    fn run(&mut self, host: &mut dyn PolicyHost) -> Result<SigningDecision, PolicyError> {
        let attempt_count = host.attempts().len();
        let attempt_count_u32 =
            u32::try_from(attempt_count).map_err(|_| PolicyError::ExecutionFailed)?;
        let mut budget = self.image.total_budget(attempt_count_u32);

        let mut verdict = SigningDecision::ApproveSilently;
        for k in 0..=attempt_count {
            let is_final = k == attempt_count;
            let attempt_index = if is_final { None } else { Some(k as u32) };

            let args = if is_final {
                [abi::NO_INPUT, attempt_count_u32, attempt_count_u32, 0]
            } else {
                let attempt = host.attempts()[k];
                [
                    attempt.input_index,
                    k as u32,
                    attempt_count_u32,
                    attempt.is_musig as u32,
                ]
            };

            let decision = self.invoke(host, attempt_index, args, &mut budget)?;
            verdict = verdict.min(decision);
        }
        Ok(verdict)
    }

    /// A single invocation. Restores everything except the shared state, then runs to
    /// `EXIT`.
    fn invoke(
        &mut self,
        host: &mut dyn PolicyHost,
        attempt_index: Option<u32>,
        args: [u32; 4],
        budget: &mut u64,
    ) -> Result<SigningDecision, PolicyError> {
        let image = self.image;
        self.reset()?;

        // Disjoint field borrows: each segment needs its own `&mut` backing store.
        let Sandbox {
            code, data, stack, ..
        } = self;

        let code_seg = MemorySegment::new(CODE_START, image.code_len, code)
            .map_err(|_| PolicyError::InvalidImage)?;
        let data_seg = MemorySegment::new(DATA_START, image.data_len, data)
            .map_err(|_| PolicyError::InvalidImage)?;
        let stack_seg = MemorySegment::new(STACK_START, image.stack_len, stack)
            .map_err(|_| PolicyError::InvalidImage)?;

        let mut cpu = Cpu::new(
            CODE_START + image.entrypoint,
            code_seg,
            data_seg,
            stack_seg,
        );
        // The stack grows down from its end, kept 4-byte aligned.
        cpu.regs[2] = (STACK_START + image.stack_len - 4) & !3;
        cpu.regs[10] = args[0]; // a0
        cpu.regs[11] = args[1]; // a1
        cpu.regs[12] = args[2]; // a2
        cpu.regs[13] = args[3]; // a3

        let mut handler = PolicyEcallHandler::new(host, attempt_index);

        loop {
            if *budget == 0 {
                return Err(PolicyError::BudgetExhausted);
            }
            *budget -= 1;

            // A `pc` that has left the code segment fails here, so falling off the
            // end of the program is caught without a separate check.
            let instr = cpu
                .fetch_instruction::<PolicyEcallError>()
                .map_err(|_| PolicyError::ExecutionFailed)?;

            match cpu.execute(instr, Some(&mut handler)) {
                Ok(()) => {}
                Err(CpuError::EcallError(PolicyEcallError::Exit(decision))) => {
                    return Ok(decision)
                }
                Err(_) => return Err(PolicyError::ExecutionFailed),
            }
        }
    }

    /// Restore `.data` from the image, zero `.bss` and the stack, and leave the
    /// shared state untouched.
    ///
    /// This is the whole persistence contract: after this returns, the shared state
    /// is the only thing that carries over from a previous invocation.
    fn reset(&mut self) -> Result<(), PolicyError> {
        let image = self.image;
        let state_offset = image.state_offset();

        let mut data_seg = MemorySegment::new(DATA_START, image.data_len, &mut self.data)
            .map_err(|_| PolicyError::InvalidImage)?;

        let init = image.data_init();
        if !init.is_empty() {
            data_seg
                .write_buffer(DATA_START, init)
                .map_err(|_| PolicyError::InvalidImage)?;
        }
        // Zero the .bss region: everything between the initialized data and the
        // shared state.
        let bss_start = DATA_START + image.data_init_len;
        let bss_end = DATA_START + state_offset;
        zero_range(&mut data_seg, bss_start, bss_end)?;

        let mut stack_seg = MemorySegment::new(STACK_START, image.stack_len, &mut self.stack)
            .map_err(|_| PolicyError::InvalidImage)?;
        zero_range(
            &mut stack_seg,
            STACK_START,
            STACK_START + image.stack_len,
        )?;

        Ok(())
    }
}

/// Zero `[start, end)` in a segment, a page at a time.
fn zero_range<M: vanadium_common::vm::PagedMemory>(
    seg: &mut MemorySegment<'_, M>,
    start: u32,
    end: u32,
) -> Result<(), PolicyError> {
    const ZEROS: [u8; PAGE_SIZE] = [0; PAGE_SIZE];
    let mut addr = start;
    while addr < end {
        let chunk = core::cmp::min((end - addr) as usize, PAGE_SIZE);
        seg.write_buffer(addr, &ZEROS[..chunk])
            .map_err(|_| PolicyError::InvalidImage)?;
        addr += chunk as u32;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
