// This benchmark measures the cost of scalar multiplication of points in the Secp256k1 curve

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use hex_literal::hex;
use sdk::bignum::{BigNum, ModulusProvider};

extern crate alloc;

sdk::bootstrap!();

#[derive(Debug, Clone, Copy)]
struct M;
impl ModulusProvider<32> for M {
    const M: [u8; 32] = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
}

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut a = M.new_big_num_mod(hex!(
        "a247598432980432940980983408039480095809832048509809580984320985"
    ));
    let b = &BigNum::from_be_bytes(hex!(
        "22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7"
    ));

    //repeatedly raise a to the power of b
    for _ in 0..n_reps {
        a = a.pow(&b);
    }

    core::hint::black_box(a);

    sdk::exit(0);
}
