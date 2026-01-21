// This test computes the number of primes up to 4000 using the Sieve of Eratosthenes algorithm.
// It measure a relatively memory-intensive operation, which will cause a significant number of page loads and commits.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

use alloc::vec;

sdk::bootstrap!();

fn count_primes(n: u32) -> u32 {
    if n < 2 {
        return 0;
    }

    let mut is_prime = vec![true; (n + 1) as usize];
    is_prime[0] = false;
    is_prime[1] = false;

    let mut i = 2;
    let mut square = 4;
    loop {
        if square > n {
            break;
        }
        if is_prime[i as usize] {
            let mut multiple = i * i;
            while multiple <= n {
                is_prime[multiple as usize] = false;
                multiple += i;
            }
        }
        square += 2 * i + 1;
        i += 1;
    }

    // Count the primes
    is_prime.iter().filter(|&&p| p).count() as u32
}

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut res_sum = 0;
    for _ in 0..n_reps {
        res_sum += count_primes(4000);
    }

    core::hint::black_box(res_sum);

    sdk::exit(0);
}
