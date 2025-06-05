use core::cell::RefCell;

use alloc::rc::Rc;
use common::client_commands::SectionKind;
use ledger_device_sdk::io;
use subtle::ConstantTimeEq;

use alloc::vec::Vec;
use common::manifest::Manifest;
use common::vm::{Cpu, MemorySegment};

use super::lib::outsourced_mem::OutsourcedMemory;
use crate::aes::{AesCtr, AesKey};
use crate::handlers::lib::ecall::{CommEcallError, CommEcallHandler};
use crate::handlers::lib::vapp::get_vapp_hmac;
use crate::{println, AppSW};

const BASE_N_CODE_PAGES: usize = 8;
const BASE_N_DATA_PAGES: usize = 8;
const BASE_N_STACK_PAGES: usize = 8;

pub fn handler_start_vapp(comm: &mut io::Comm) -> Result<Vec<u8>, AppSW> {
    let data_raw = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let (manifest, provided_hmac) =
        postcard::take_from_bytes::<Manifest>(data_raw).map_err(|_| AppSW::IncorrectData)?;

    if provided_hmac.len() != 32 {
        return Err(AppSW::IncorrectData);
    }

    let vapp_hmac = get_vapp_hmac(&manifest);

    // It's critical to use a constant time comparison to prevent timing attacks
    if provided_hmac.ct_ne(&vapp_hmac).into() {
        return Err(AppSW::SignatureFail);
    }

    println!("Running app with Manifest: {:?}", manifest);
    println!("hmac: {:?}", provided_hmac);

    let comm = Rc::new(RefCell::new(comm));

    let aes_ctr = Rc::new(RefCell::new(AesCtr::new(
        AesKey::new_random().map_err(|_| AppSW::VMRuntimeError)?,
    )));

    let n_extra_pages: usize = env!("VANADIUM_N_EXTRA_CACHE_PAGES")
        .parse::<usize>()
        .unwrap_or(0);

    let extra_code_pages = n_extra_pages / 3;
    let extra_data_pages = n_extra_pages / 3;
    let extra_stack_pages = n_extra_pages - extra_code_pages - extra_data_pages;

    let mut code_mem = OutsourcedMemory::new(
        comm.clone(),
        BASE_N_CODE_PAGES + extra_code_pages,
        true,
        SectionKind::Code,
        manifest.n_code_pages(),
        manifest.code_merkle_root.into(),
        aes_ctr.clone(),
    );
    let code_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.code_start,
        manifest.code_end - manifest.code_start,
        &mut code_mem,
    )
    .unwrap();

    let mut data_mem = OutsourcedMemory::new(
        comm.clone(),
        BASE_N_DATA_PAGES + extra_data_pages,
        false,
        SectionKind::Data,
        manifest.n_data_pages(),
        manifest.data_merkle_root.into(),
        aes_ctr.clone(),
    );
    let data_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.data_start,
        manifest.data_end - manifest.data_start,
        &mut data_mem,
    )
    .unwrap();

    let mut stack_mem = OutsourcedMemory::new(
        comm.clone(),
        BASE_N_STACK_PAGES + extra_stack_pages,
        false,
        SectionKind::Stack,
        manifest.n_stack_pages(),
        manifest.stack_merkle_root.into(),
        aes_ctr.clone(),
    );
    let stack_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.stack_start,
        manifest.stack_end - manifest.stack_start,
        &mut stack_mem,
    )
    .unwrap();

    let mut cpu = Cpu::new(manifest.entrypoint, code_seg, data_seg, stack_seg);

    // x2 is the stack pointer, that grows backwards from the end of the stack
    // we make sure it's aligned to a multiple of 4
    cpu.regs[2] = (manifest.stack_end - 4) & !3;
    assert!(cpu.pc % 2 == 0, "Unaligned entrypoint");

    let mut ecall_handler = CommEcallHandler::new(comm.clone(), &manifest);

    #[cfg(feature = "metrics")]
    let mut instr_count = 0;

    loop {
        // Handle instruction fetch errors
        let instr = match cpu.fetch_instruction::<CommEcallError>() {
            Ok(instr) => instr,
            Err(e) => {
                println!("Error fetching instruction: {:?}", e);
                return Err(AppSW::VMRuntimeError);
            }
        };

        #[cfg(feature = "trace_full")]
        {
            #[cfg(feature = "trace_colors")]
            crate::print!("\x1b[93m");

            crate::println!("{:?}", cpu);
            #[cfg(feature = "trace_colors")]

            crate::print!("\x1b[0m");
        }

        #[cfg(feature = "trace")]
        {
            #[cfg(feature = "trace_colors")]
            crate::print!("\x1b[32m");

            // Print the instruction, but check if it's compressed
            let (decoded_op, len) = common::riscv::decode::decode(instr);
            if len == 2 {
                let instr_lo = (instr & 0xffffu32) as u16;
                crate::println!("{:08x?}: {:04x?} -> {:?}", cpu.pc, instr_lo, decoded_op);
            } else {
                crate::println!("{:08x?}: {:08x?} -> {:?}", cpu.pc, instr, decoded_op);
            }

            #[cfg(feature = "trace_colors")]
            crate::print!("\x1b[0m");
        }

        let result = cpu.execute(instr, Some(&mut ecall_handler));

        #[cfg(feature = "metrics")]
        {
            instr_count += 1;
        }

        match result {
            Ok(_) => {}
            Err(common::vm::CpuError::EcallError(e)) => match e {
                CommEcallError::Exit(status) => {
                    #[cfg(feature = "metrics")]
                    {
                        let n_loads =
                            code_mem.n_page_loads + data_mem.n_page_loads + stack_mem.n_page_loads;
                        let n_commits = code_mem.n_page_commits
                            + data_mem.n_page_commits
                            + stack_mem.n_page_commits;
                        println!("Vanadium ran {} instructions", instr_count);
                        println!("Number of page loads:   {}", n_loads);
                        println!("Number of page commits: {}", n_commits);
                    }
                    println!("Exiting with status {}", status);
                    return Ok(status.to_be_bytes().to_vec());
                }
                CommEcallError::Panic => {
                    println!("V-App panicked");
                    return Err(AppSW::VAppPanic);
                }
                CommEcallError::GenericError(e) => {
                    println!("Runtime error: {}", e);
                    return Err(AppSW::VMRuntimeError);
                }
                e => {
                    println!("CommEcallError: {:?}", e);
                    return Err(AppSW::VMRuntimeError);
                }
            },
            Err(common::vm::CpuError::MemoryError(e)) => {
                println!("Memory error: {}", e);
                return Err(AppSW::VMRuntimeError);
            }
            Err(common::vm::CpuError::GenericError(e)) => {
                println!("Error executing instruction: {}", e);
                return Err(AppSW::VMRuntimeError);
            }
        }
    }
}
