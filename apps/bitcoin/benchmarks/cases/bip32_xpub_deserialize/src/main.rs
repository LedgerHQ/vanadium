// This benchmark measures the cost of decoding an Xpub from its binary representation

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use bitcoin::bip32::Xpub;
use hex_literal::hex;

extern crate alloc;

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let tpub_bin = hex!("043587cf03751b8765800000007054e6aa7050c1aa7ae5e14b78a66bae6f188f52a805e5700cc6b9647b32df6902668c624fdbf81d0e9d3601d5da195e0d06e48e3f5021d9269774bd0a9e5f2cbe");

    for _rep in 0..n_reps {
        let tpub = Xpub::decode(&tpub_bin).unwrap();
        core::hint::black_box(&tpub);
    }

    sdk::exit(0);
}
