use core::cell::RefCell;

use alloc::rc::Rc;
use common::client_commands::SectionKind;
use ledger_device_sdk::io;

use alloc::vec::Vec;
use common::manifest::Manifest;
use common::vm::{Cpu, MemorySegment};

use super::lib::outsourced_mem::OutsourcedMemory;
use crate::handlers::lib::ecall::{CommEcallError, CommEcallHandler};
use crate::{println, AppSW};

pub fn handler_start_vapp(comm: &mut io::Comm) -> Result<Vec<u8>, AppSW> {
    let data_raw = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    let (manifest, hmac) =
        postcard::take_from_bytes::<Manifest>(data_raw).map_err(|_| AppSW::IncorrectData)?;

    if hmac.len() != 32 {
        return Err(AppSW::IncorrectData);
    }

    // TODO: actually check the HMAC (and use a constant-time comparison)
    if hmac != [0x42u8; 32] {
        return Err(AppSW::SignatureFail);
    }

    println!("Running app with Manifest: {:?}", manifest);
    println!("hmac: {:?}", hmac);

    let comm = Rc::new(RefCell::new(comm));

    let mut code_mem = OutsourcedMemory::new(comm.clone(), 12, true, SectionKind::Code);
    let code_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.code_start,
        manifest.code_end - manifest.code_start,
        &mut code_mem,
    )
    .unwrap();

    let mut data_mem = OutsourcedMemory::new(comm.clone(), 12, false, SectionKind::Data);
    let data_seg = MemorySegment::<OutsourcedMemory>::new(
        manifest.data_start,
        manifest.data_end - manifest.data_start,
        &mut data_mem,
    )
    .unwrap();

    let mut stack_mem = OutsourcedMemory::new(comm.clone(), 12, false, SectionKind::Stack);
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

    assert!(cpu.pc % 4 == 0, "Unaligned entrypoint");

    let mut ecall_handler = CommEcallHandler::new(comm.clone(), &manifest);

    #[cfg(feature = "metrics")]
    let mut instr_count = 0;

    loop {
        // TODO: handle errors
        let instr = cpu
            .fetch_instruction::<CommEcallError>()
            .expect("Failed to fetch instruction");

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

            crate::println!(
                "{:08x?}: {:08x?} -> {:?}",
                cpu.pc,
                instr,
                common::riscv::decode::decode(instr)
            );

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
