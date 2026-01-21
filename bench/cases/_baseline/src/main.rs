// This test does nothing, and is only used to measure the overhead of running an empty program.
// It is used to make the measurements more accurate for the other tests, by providing the baseline running time.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let _n_reps = u64::from_be_bytes(msg);

    sdk::exit(0);
}
