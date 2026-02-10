// This test computes a Schnorr signature using the app-sdk (therefore, with the appropriate ECALLs).

#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use sdk::curve::Secp256k1;

extern crate alloc;

sdk::bootstrap!();

pub fn main() {
    let private_key_raw = [0x01; 32];
    let private_key = sdk::curve::EcfpPrivateKey::<Secp256k1, 32>::new(private_key_raw);
    let msg: [u8; 8] = sdk::xrecv(8).try_into().expect("Expected 8 bytes");
    let n_reps = u64::from_be_bytes(msg);

    let mut data = [0u8; 32];

    for _ in 0..n_reps {
        let sig = private_key
            .schnorr_sign(&data, None)
            .expect("Signing failed");
        // copy the first 32 bytes of the signature back into data, so that the next iteration will sign new data
        data.copy_from_slice(&sig[..32]);
    }

    core::hint::black_box(data);

    sdk::exit(0);
}
