// This benchmark measures the cost of deriving a child xpub from a parent xpub

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

extern crate alloc;

use alloc::vec;

use bitcoin::bip32::{ChildNumber, Xpub};
use hex_literal::hex;

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let tpub_bin = hex!("043587cf03751b8765800000007054e6aa7050c1aa7ae5e14b78a66bae6f188f52a805e5700cc6b9647b32df6902668c624fdbf81d0e9d3601d5da195e0d06e48e3f5021d9269774bd0a9e5f2cbe");
    let mut tpub = Xpub::decode(&tpub_bin).unwrap();

    let secp = bitcoin::secp256k1::Secp256k1::new();

    for _rep in 0..n_reps {
        tpub = tpub
            .derive_pub(&secp, &vec![ChildNumber::from(42)])
            .unwrap();
        core::hint::black_box(&tpub);
    }

    sdk::exit(0);
}
