// This benchmark stresses the allocator by creating (and immediately dropping)
// many short-lived Vec instances filled with small amounts of data.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use alloc::vec::Vec;

extern crate alloc;

sdk::bootstrap!();

const VECS_PER_REPETITION: usize = 64;
const BASE_VEC_LEN: usize = 16;
const LEN_VARIATIONS: usize = 8;

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut checksum: u64 = 0;

    for rep in 0..n_reps {
        let seed = rep as u8;

        // Create many vectors with varying length (but generally small)
        for vec_index in 0..VECS_PER_REPETITION {
            let len = BASE_VEC_LEN + (vec_index % LEN_VARIATIONS);
            let mut data = Vec::with_capacity(len);

            for i in 0..len {
                let value = seed.wrapping_add((vec_index as u8).wrapping_mul(17));
                data.push(value.wrapping_add(i as u8));
            }

            checksum ^= data.iter().fold(0u64, |acc, &byte| acc + byte as u64);
            core::hint::black_box(&data);
            // `data` drops here before the next iteration, forcing frequent allocations.
        }
    }

    core::hint::black_box(checksum);

    sdk::exit(0);
}
