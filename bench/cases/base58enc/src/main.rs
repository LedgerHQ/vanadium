// This test computes the cost of encoding 32 bytes to base58 using the `bs58` crate.,

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut data = [0u8; 32].to_vec();
    for _ in 0..n_reps {
        data = bs58::encode(&data[0..32]).into_vec();
    }

    core::hint::black_box(data);

    sdk::exit(0);
}
