// This benchmark measures the cost of multiplication of 256-bit numbers

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use hex_literal::hex;
use sdk::bignum::ModulusProvider;

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
    let b = M.new_big_num_mod(hex!(
        "7390984098209380980948098230840982340294098092384092834923840923"
    ));

    //repeatedly multiply a by b
    for _ in 0..n_reps {
        a = &a * &b;
    }

    core::hint::black_box(a);

    sdk::exit(0);
}
