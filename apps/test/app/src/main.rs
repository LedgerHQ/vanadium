#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

extern crate alloc;

mod commands;
mod handlers;

use commands::Command;
use handlers::*;

// Temporary to force the creation of a data section
#[used]
#[no_mangle]
pub static mut APP_NAME: [u8; 32] = *b"Test\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

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

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn _start() {
    app_main()
}

#[cfg(not(target_arch = "riscv32"))]
fn main() {
    app_main();
}

pub fn app_main() {
    sdk::rust_init_heap();

    // sdk::ux::ux_idle();

    let res = sdk::ux::show_confirm_reject("Title", "Text", "Confirm", "Reject");

    if res {
        sdk::ux::show_info(sdk::ux::Icon::Success, "Oh yeah!");
    } else {
        sdk::ux::show_info(sdk::ux::Icon::Failure, "Oh no!");
    }
    // for _ in 0..10 {
    //     // wait about 1 seconds
    //     sdk::ux::get_event();
    // }

    // sdk::ux::show_info(sdk::ux::Icon::Success, "Oh yes!");

    loop {
        let msg = sdk::xrecv(256);

        if msg.is_empty() {
            sdk::exit(0);
        }

        let Ok(command) = Command::try_from(msg[0]) else {
            panic!("Unknown command");
        };

        let response = match command {
            Command::Reverse => {
                let mut data = msg[1..].to_vec();
                data.reverse();
                data
            }
            Command::AddNumbers => {
                // sum all the numbers from 0 to n
                if msg.len() != 5 {
                    panic!("Invalid input");
                }
                let n = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
                let mut result: u64 = 0;
                for i in 0..=n {
                    result += i as u64;
                }
                result.to_be_bytes().to_vec()
            }
            Command::Base58Encode => handle_base58_encode(&msg[1..]),
            Command::Sha256 => handle_sha256(&msg[1..]),
            Command::CountPrimes => handle_count_primes(&msg[1..]),
            Command::Panic => {
                let panic_msg = core::str::from_utf8(&msg[1..]).unwrap();
                panic!("{}", panic_msg);
            }
        };

        sdk::xsend(&response);
    }
}
