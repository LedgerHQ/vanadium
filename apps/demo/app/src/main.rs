#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

extern crate alloc;

use alloc::vec::Vec;
use sdk::App;

sdk::bootstrap!();

fn process_message(_app: &mut App, msg: &[u8]) -> Vec<u8> {
    if msg.is_empty() {
        sdk::exit(0);
    }
    msg.to_vec()
}

pub fn main() {
    App::new(process_message).run();
}
