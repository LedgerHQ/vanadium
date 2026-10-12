// This benchmark tests the cost of paying to a silent payment code, once the signer knows the sum
// `a` of the private keys of the eligible inputs (BIP-352, BIP-375): the input hash, the ECDH
// share and its DLEQ proof (BIP-374), the shared secret and the key of one output.

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use bitcoin::{hashes::Hash, OutPoint, Txid};
use common::silent_payments::{self as sp, Secp256k1, Secp256k1Scalar, SilentPaymentCode};

sdk::bootstrap!();

pub fn main() {
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    // the first address of the BIP-352 test vectors
    let (_, code) = SilentPaymentCode::from_address("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").unwrap();
    let a = Secp256k1Scalar::from_be_bytes(&[0x42; 32]).unwrap();
    let outpoints = [OutPoint {
        txid: Txid::from_byte_array([1; 32]),
        vout: 0,
    }];
    let g = Secp256k1::get_generator();

    for _rep in 0..n_reps {
        let input_hash = sp::input_hash(&outpoints, &(&g * &a)).unwrap();
        let share = sp::ecdh_share(&a, code.scan());
        let proof = sp::generate_proof(&a, code.scan(), &[7; 32], &g, None).unwrap();
        let secret = sp::shared_secret(&input_hash, &share).unwrap();
        let output_key = sp::output_key(&secret, code.spend(), 0).unwrap();
        core::hint::black_box((&proof, &output_key));
    }

    sdk::exit(0);
}
