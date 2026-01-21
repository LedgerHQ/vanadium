// This test computes the SHA256 hash of a message repeatedly, using the SHA256 implementation from the `sha2` crate.
// It does not use the SDK's hash functionality, which would avoid most of the VM's slowdown by using ECALLs.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use sha2::Digest;

extern crate alloc;

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut data = [0u8; 32].to_vec();
    for _ in 0..n_reps {
        data = sha2::Sha256::digest(&data).to_vec();
    }

    core::hint::black_box(data);

    sdk::exit(0);
}
