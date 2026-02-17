use core::cell::RefCell;

use alloc::vec::Vec;
use alloc::{boxed::Box, rc::Rc};

use common::client_commands::SectionKind;
use common::manifest::Manifest;
use common::vm::{Cpu, MemorySegment};

use super::lib::{
    ecall::{CommEcallError, CommEcallHandler},
    evict::{LruEvictionStrategy, TwoQEvictionStrategy},
    outsourced_mem::OutsourcedMemory,
};
use crate::{
    aes::{AesCtr, AesKey},
    hash::Sha256Hasher,
    println,
    vapp::VAppStore,
    AppSW, COMM_BUFFER_SIZE,
};

#[cfg(feature = "metrics")]
use super::get_metrics::set_last_metrics;
#[cfg(feature = "metrics")]
use common::metrics::VAppMetrics;

pub fn handler_start_vapp(
    command: ledger_device_sdk::io::Command<COMM_BUFFER_SIZE>,
) -> Result<Vec<u8>, AppSW> {
    let data_raw = command.get_data();

    let (manifest, rest) =
        postcard::take_from_bytes::<Manifest>(data_raw).map_err(|_| AppSW::IncorrectData)?;

    if rest.len() != 0 {
        return Err(AppSW::IncorrectData); // extra data
    }

    manifest.validate().map_err(|_| AppSW::IncorrectData)?; // ensure manifest is valid

    // Compute the vapp_hash and verify the app is registered
    let vapp_hash = manifest.get_vapp_hash::<Sha256Hasher, 32>();

    if !VAppStore::is_registered(&vapp_hash) {
        return Err(AppSW::SignatureFail); // App not registered
    }

    let comm = command.into_comm();
    let comm = Rc::new(RefCell::new(comm));

    let aes_ctr = Rc::new(RefCell::new(AesCtr::new(
        AesKey::new_random().map_err(|_| AppSW::VMRuntimeError)?,
    )));

    // Base number of pages for code, data and stack, computed based on the BASE_HEAP_SIZE of Nano X
    const BASE_CODE_PAGES: usize = 24;
    const BASE_DATA_PAGES: usize = 8;
    const BASE_STACK_PAGES: usize = 8;

    // Based on the total available heap size, we allocate more pages to the caches
    let base_heap_size = crate::BASE_HEAP_SIZE; // smallest heap size, tailored for Nano X

    assert!(crate::HEAP_SIZE >= base_heap_size);
    let additional_heap = crate::HEAP_SIZE - base_heap_size;

    // compute how many additional pages we can allocate with the extra available heap
    const CACHED_PAGE_SIZE: usize = OutsourcedMemory::<COMM_BUFFER_SIZE>::size_per_page()
        + TwoQEvictionStrategy::size_per_page();
    let n_additional_pages = additional_heap / CACHED_PAGE_SIZE;

    // Divide the additional pages among code, data and stack; we privilege the code cache.
    // We assign floor(n / 6) to data, floor(n / 6) to stack, and the rest to code
    let n_additional_data_pages = n_additional_pages / 6;
    let n_additional_stack_pages = n_additional_pages / 6;
    let n_additional_code_pages =
        n_additional_pages - n_additional_data_pages - n_additional_stack_pages;

    let n_code_cache_pages = BASE_CODE_PAGES + n_additional_code_pages;
    let n_data_cache_pages = BASE_DATA_PAGES + n_additional_data_pages;
    let n_stack_cache_pages = BASE_STACK_PAGES + n_additional_stack_pages;

    let mut code_mem = OutsourcedMemory::new(
        comm.clone(),
        n_code_cache_pages,
        true,
        SectionKind::Code,
        manifest.n_code_pages(),
        manifest.code_merkle_root.into(),
        aes_ctr.clone(),
        Box::new(TwoQEvictionStrategy::new(
            n_code_cache_pages,
            n_code_cache_pages / 4,
            n_code_cache_pages / 2,
        )),
        &vapp_hash,
    );
    let code_seg = MemorySegment::<OutsourcedMemory<'_, COMM_BUFFER_SIZE>>::new(
        manifest.code_start,
        manifest.code_end - manifest.code_start,
        &mut code_mem,
    )
    .unwrap();

    let mut data_mem = OutsourcedMemory::new(
        comm.clone(),
        n_data_cache_pages,
        false,
        SectionKind::Data,
        manifest.n_data_pages(),
        manifest.data_merkle_root.into(),
        aes_ctr.clone(),
        Box::new(LruEvictionStrategy::new(n_data_cache_pages)),
        &vapp_hash,
    );
    let data_seg = MemorySegment::<OutsourcedMemory<'_, COMM_BUFFER_SIZE>>::new(
        manifest.data_start,
        manifest.data_end - manifest.data_start,
        &mut data_mem,
    )
    .unwrap();

    let mut stack_mem = OutsourcedMemory::new(
        comm.clone(),
        n_stack_cache_pages,
        false,
        SectionKind::Stack,
        manifest.n_stack_pages(),
        manifest.stack_merkle_root.into(),
        aes_ctr.clone(),
        Box::new(LruEvictionStrategy::new(n_stack_cache_pages)),
        &vapp_hash,
    );
    let stack_seg = MemorySegment::<OutsourcedMemory<'_, COMM_BUFFER_SIZE>>::new(
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

    let mut ecall_handler =
        CommEcallHandler::new(comm.clone(), vapp_hash, manifest.n_storage_slots);

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

        #[cfg(feature = "trace_cpu")]
        crate::trace!("CPU State", "light_yellow", "{:?}", cpu);

        #[cfg(feature = "trace")]
        {
            // Print the instruction, but check if it's compressed
            let (decoded_op, len) = common::riscv::decode::decode(instr);
            let instruction = if len == 2 {
                let instr_lo = (instr & 0xffffu32) as u16;
                alloc::format!("{:08x?}: {:04x?} -> {:?}", cpu.pc, instr_lo, decoded_op)
            } else {
                alloc::format!("{:08x?}: {:08x?} -> {:?}", cpu.pc, instr, decoded_op)
            };

            crate::trace!("Instruction", "green", "{}", instruction);
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

                        // Store metrics for retrieval via GetMetrics command
                        let mut vapp_name = [0u8; common::manifest::APP_NAME_MAX_LEN];
                        let name_bytes = manifest.get_app_name().as_bytes();
                        let copy_len = name_bytes.len().min(common::manifest::APP_NAME_MAX_LEN);
                        vapp_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

                        set_last_metrics(VAppMetrics {
                            vapp_name,
                            vapp_hash,
                            instruction_count: instr_count,
                            page_loads: n_loads as u32,
                            page_commits: n_commits as u32,
                        });
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
