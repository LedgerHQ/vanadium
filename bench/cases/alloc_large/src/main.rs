// This benchmark stresses the allocator by creating (and immediately dropping)
// a handful of very large Vec instances, emphasizing big heap allocations.
// This should be dominated by the cost of page swaps.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use alloc::vec::Vec;

extern crate alloc;

sdk::bootstrap!();

const BASE_VEC_LEN: usize = 2 * 1024; // 2 KiB
const LEN_VARIATIONS: usize = 4;
const LEN_STEP: usize = 1 * 1024; // 1 KiB increments

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut checksum: u64 = 0;

    for rep in 0..n_reps {
        let seed = rep as u8;

        let len = BASE_VEC_LEN + (rep as usize % LEN_VARIATIONS) * LEN_STEP;
        let mut data = Vec::with_capacity(len);

        for i in 0..len {
            let value = seed.wrapping_add((rep as u8).wrapping_mul(17));
            data.push(value.wrapping_add(i as u8));
        }

        checksum ^= data.iter().fold(0u64, |acc, &byte| acc + byte as u64);
        core::hint::black_box(&data);
        // `data` drops here before the next iteration, forcing frequent allocations.
    }

    core::hint::black_box(checksum);

    sdk::exit(0);
}
