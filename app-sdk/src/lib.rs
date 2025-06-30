#![cfg_attr(target_arch = "riscv32", no_main, no_std)]

extern crate alloc;

#[cfg(not(target_arch = "riscv32"))]
extern crate lazy_static;

use alloc::vec::Vec;

pub mod app;
pub mod bignum;
pub mod comm;
pub mod curve;
pub mod hash;
pub mod rand;
pub mod ux;

pub use app::App;

mod ecalls;

#[cfg(target_arch = "riscv32")]
mod ecalls_riscv;

#[cfg(not(target_arch = "riscv32"))]
mod ecalls_native;

mod ux_generated;

use ecalls::{Ecall, EcallsInterface};

#[cfg(target_arch = "riscv32")]
use embedded_alloc::Heap;

#[cfg(target_arch = "riscv32")]
const HEAP_SIZE: usize = 65536;
#[cfg(target_arch = "riscv32")]
static mut HEAP_MEM: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[cfg(target_arch = "riscv32")]
#[global_allocator]
static HEAP: Heap = Heap::empty();

#[cfg(target_arch = "riscv32")]
fn init_heap() {
    unsafe {
        #[allow(static_mut_refs)]
        HEAP.init(HEAP_MEM.as_mut_ptr() as usize, HEAP_SIZE);
    }
}

// embedded-alloc requires an implementation of critical_section::Impl
use critical_section::RawRestoreState;

struct CriticalSection;
critical_section::set_impl!(CriticalSection);

/// Default empty implementation as we don't have concurrency.
unsafe impl critical_section::Impl for CriticalSection {
    unsafe fn acquire() -> RawRestoreState {}
    unsafe fn release(_restore_state: RawRestoreState) {}
}

// Allocator initialization for riscv32 targets
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub extern "C" fn rust_init_heap() {
    init_heap();
}

pub fn fatal(msg: &str) -> ! {
    Ecall::fatal(msg.as_ptr(), msg.len());
}

pub fn exit(status: i32) -> ! {
    Ecall::exit(status);
}

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    let message = if let Some(location) = info.location() {
        alloc::format!(
            "Panic occurred in file '{}' at line {}: {}",
            location.file(),
            location.line(),
            info.message()
        )
    } else {
        alloc::format!("Panic occurred: {}", info.message())
    };
    fatal(&message); // does not return
}

pub fn xrecv(size: usize) -> Vec<u8> {
    // We allocate a buffer with the requested size, but we don't initialize its content.
    // xrecv guarantees that recv_size have been overwritten with the received data, and we
    // do not access any further data.
    let mut buffer = Vec::with_capacity(size);
    let recv_size = Ecall::xrecv(buffer.as_mut_ptr(), size);
    unsafe {
        buffer.set_len(size);
    }
    buffer[0..recv_size].to_vec()
}

pub fn xrecv_to(buf: &mut [u8]) -> usize {
    Ecall::xrecv(buf.as_mut_ptr(), buf.len())
}

pub fn xsend(buffer: &[u8]) {
    Ecall::xsend(buffer.as_ptr(), buffer.len() as usize)
}

/// Initialization boilerplate for the application that is called before the main function, for
/// targets that need it.
#[macro_export]
macro_rules! bootstrap {
    () => {
        #[cfg(target_arch = "riscv32")]
        #[no_mangle]
        pub fn _start() {
            $crate::rust_init_heap();
            main()
        }
    };
}
