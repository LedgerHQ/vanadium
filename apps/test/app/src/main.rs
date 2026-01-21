#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

use alloc::vec;

mod commands;
mod handlers;

use commands::Command;
use handlers::*;

sdk::bootstrap!();

pub fn main() {
    sdk::ux::ux_idle();

    loop {
        let msg = sdk::xrecv(256);
        if msg.is_empty() {
            continue;
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
            Command::ShowUxScreen => handle_show_ux_screen(&msg[1..]),
            Command::DeviceProp => {
                if msg.len() != 5 {
                    panic!("Invalid input for device properties");
                }
                let property_id = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
                sdk::get_device_property(property_id).to_be_bytes().to_vec()
            }
            Command::Print => {
                let print_msg = core::str::from_utf8(&msg[1..]).unwrap();
                sdk::println!("{}", print_msg);
                vec![]
            }
            Command::Panic => {
                let panic_msg = core::str::from_utf8(&msg[1..]).unwrap();
                panic!("{}", panic_msg);
            }
            Command::Exit => {
                sdk::exit(0);
            }
        };

        sdk::xsend(&response);
    }
}
