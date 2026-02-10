// This benchmark measures the cost of scalar multiplication of points in the Secp256k1 curve

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use hex_literal::hex;
use sdk::curve::Secp256k1Point;

extern crate alloc;

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut p = Secp256k1Point::new(
        hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
    );
    let scalar = hex!("22445566778899aabbccddeeff0011223344556677889900aabbccddeeff0011");

    //repeatedly multiply p by scalar
    for _ in 0..n_reps {
        p = &p * &scalar;
    }

    core::hint::black_box(p);

    sdk::exit(0);
}
