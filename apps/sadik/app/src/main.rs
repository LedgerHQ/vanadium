#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

use sdk::{
    bignum::{BigNum, BigNumMod, Modulus},
    curve::{Curve as _, EcfpPrivateKey, EcfpPublicKey, Secp256k1Point},
    hash::Hasher,
};

extern crate alloc;

use alloc::{string::ToString, vec, vec::Vec};
use common::{Command, Curve, ECPointOperation, HashId};

// Temporary to force the creation of a data section
#[used]
#[no_mangle]
pub static mut APP_NAME: [u8; 32] = *b"Sadik\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn my_panic(info: &core::panic::PanicInfo) -> ! {
    let message = if let Some(location) = info.location() {
        alloc::format!(
            "Panic occurred in file '{}' at line {}: {}",
            location.file(),
            location.line(),
            info.message()
        )
    } else {
        alloc::format!("Panic occurred: {}", info.message())
    };
    fatal(&message); // does not return
}

#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub fn _start() {
    main()
}

// parses a 65-byte uncompressed pubkey into an EcfpPublicKey
fn parse_pubkey(pubkey: &[u8]) -> EcfpPublicKey<sdk::curve::Secp256k1, 32> {
    let pubkey_raw: [u8; 65] = pubkey
        .try_into()
        .expect("invalid pubkey: it must be 65 bytes in uncompressed form");
    if pubkey_raw[0] != 0x04 {
        panic!("invalid pubkey: it must start with 0x04");
    }
    EcfpPublicKey::new(
        pubkey_raw[1..33].try_into().unwrap(),
        pubkey_raw[33..65].try_into().unwrap(),
    )
}

pub fn main() {
    sdk::rust_init_heap();

    sdk::ux::ux_idle();
    loop {
        let msg = match sdk::comm::receive_message() {
            Ok(msg) => msg,
            Err(e) => {
                let error_string = e.to_string();
                panic!("Error receiving message: {}", error_string);
            }
        };

        let command: Command = postcard::from_bytes(&msg).expect("Deserialization failed");

        let response: Vec<u8> = match command {
            Command::Hash { hash_id, msg } => {
                let hash_id = HashId::try_from(hash_id).expect("Invalid hash ID");
                match hash_id {
                    HashId::Ripemd160 => {
                        let mut digest: [u8; 20] = [0u8; 20];
                        let mut hasher = sdk::hash::Ripemd160::new();
                        hasher.update(&msg);
                        hasher.digest(&mut digest);
                        digest.to_vec()
                    }
                    HashId::Sha256 => {
                        let mut hasher = sdk::hash::Sha256::new();
                        hasher.update(&msg);
                        let mut digest = [0u8; 32];
                        hasher.digest(&mut digest);
                        digest.to_vec()
                    }
                    HashId::Sha512 => {
                        let mut hasher = sdk::hash::Sha512::new();
                        hasher.update(&msg);
                        let mut digest = [0u8; 64];
                        hasher.digest(&mut digest);
                        digest.to_vec()
                    }
                }
            }
            Command::BigIntOperation {
                operator,
                a,
                b,
                modulus,
            } => {
                if modulus.len() == 0 {
                    macro_rules! impl_bignum_processing {
                        ($len:expr, $a:expr, $b:expr, $operator:expr) => {{
                            let a: BigNum<$len> =
                                BigNum::from_be_bytes($a.as_slice().try_into().unwrap());
                            let b: BigNum<$len> =
                                BigNum::from_be_bytes($b.as_slice().try_into().unwrap());

                            match $operator {
                                common::BigIntOperator::Add => (&a + &b).to_be_bytes().to_vec(),
                                common::BigIntOperator::Sub => (&a - &b).to_be_bytes().to_vec(),
                                common::BigIntOperator::Mul => {
                                    panic!(
                                        "Multiplication is only supported for modular big numbers"
                                    )
                                }
                                common::BigIntOperator::Pow => {
                                    panic!(
                                        "Exponentiation is only supported for modular big numbers"
                                    )
                                }
                            }
                        }};
                    }

                    if a.len() != b.len() {
                        panic!("Big numbers must have the same length");
                    }

                    match a.len() {
                        4 => impl_bignum_processing!(4, a, b, operator),
                        32 => impl_bignum_processing!(32, a, b, operator),
                        64 => impl_bignum_processing!(64, a, b, operator),
                        _ => panic!("Unsupported big number length in sadik"),
                    }
                } else {
                    // modular
                    if modulus.len() != 32 {
                        panic!("Only modulus length of 32 is supported in sadik");
                    }

                    let modulus = Modulus::from_be_bytes(modulus.as_slice().try_into().unwrap());

                    if let common::BigIntOperator::Pow = operator {
                        if a.len() != 32 {
                            panic!("Only modular big numbers of length 32 are supported in sadik");
                        }
                        let a: BigNumMod<32> =
                            BigNumMod::from_be_bytes(a.as_slice().try_into().unwrap(), &modulus);

                        macro_rules! impl_modular_pow {
                            ($len:expr, $b:expr, $a:expr) => {{
                                let b = BigNum::<$len>::from_be_bytes(
                                    $b.as_slice().try_into().unwrap(),
                                );
                                $a.pow(&b).to_be_bytes().to_vec()
                            }};
                        }

                        match b.len() {
                            1 => impl_modular_pow!(1, b, a),
                            4 => impl_modular_pow!(4, b, a),
                            32 => impl_modular_pow!(32, b, a),
                            64 => impl_modular_pow!(64, b, a),
                            _ => {
                                panic!("Unsupported length for the exponent in sadik");
                            }
                        }
                    } else {
                        if a.len() != 32 || b.len() != 32 {
                            panic!("Only modular big numbers of length 32 are supported in sadik");
                        }

                        let a: BigNumMod<32> =
                            BigNumMod::from_be_bytes(a.as_slice().try_into().unwrap(), &modulus);
                        let b: BigNumMod<32> =
                            BigNumMod::from_be_bytes(b.as_slice().try_into().unwrap(), &modulus);

                        match operator {
                            common::BigIntOperator::Add => (&a + &b).to_be_bytes().to_vec(),
                            common::BigIntOperator::Sub => (&a - &b).to_be_bytes().to_vec(),
                            common::BigIntOperator::Mul => (&a * &b).to_be_bytes().to_vec(),
                            common::BigIntOperator::Pow => panic!("Unreachable code"),
                        }
                    }
                }
            }
            Command::GetMasterFingerprint { curve } => match curve {
                Curve::Secp256k1 => sdk::curve::Secp256k1::get_master_fingerprint()
                    .to_be_bytes()
                    .to_vec(),
            },
            Command::DeriveHdNode { curve, path } => match curve {
                // returns the concatenation of the chaincode and private key
                Curve::Secp256k1 => {
                    let node = sdk::curve::Secp256k1::derive_hd_node(&path).unwrap();
                    let mut result = node.chaincode.to_vec();
                    result.extend_from_slice(&node.privkey[..]);
                    result
                }
            },
            Command::ECPointOperation { curve, operation } => match curve {
                Curve::Secp256k1 => match operation {
                    ECPointOperation::Add(p, q) => {
                        let p = Secp256k1Point::from_bytes(p.as_slice().try_into().unwrap());
                        let q = Secp256k1Point::from_bytes(q.as_slice().try_into().unwrap());
                        (p + q).to_bytes().to_vec()
                    }
                    ECPointOperation::ScalarMult(p, k) => {
                        let p = Secp256k1Point::from_bytes(p.as_slice().try_into().unwrap());
                        let k: [u8; 32] = k.as_slice().try_into().unwrap();
                        (p * &k).to_bytes().to_vec()
                    }
                },
            },
            Command::EcdsaSign {
                curve,
                privkey,
                msg_hash,
            } => match curve {
                Curve::Secp256k1 => {
                    let msg_hash: [u8; 32] = msg_hash
                        .as_slice()
                        .try_into()
                        .expect("hash must be 32 bytes");
                    let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> = EcfpPrivateKey::new(
                        privkey.as_slice().try_into().expect("invalid privkey"),
                    );

                    privkey.ecdsa_sign_hash(&msg_hash).unwrap()
                }
            },
            Command::EcdsaVerify {
                curve,
                msg_hash,
                pubkey,
                signature,
            } => match curve {
                Curve::Secp256k1 => {
                    let pubkey = parse_pubkey(&pubkey);
                    let msg_hash: [u8; 32] = msg_hash
                        .as_slice()
                        .try_into()
                        .expect("hash must be 32 bytes");

                    if pubkey.ecdsa_verify_hash(&msg_hash, &signature).is_ok() {
                        vec![1]
                    } else {
                        vec![0]
                    }
                }
            },
            Command::SchnorrSign {
                curve,
                privkey,
                msg,
            } => match curve {
                Curve::Secp256k1 => {
                    let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> = EcfpPrivateKey::new(
                        privkey.as_slice().try_into().expect("invalid privkey"),
                    );
                    privkey.schnorr_sign(&msg).unwrap()
                }
            },
            Command::SchnorrVerify {
                curve,
                pubkey,
                msg,
                signature,
            } => match curve {
                Curve::Secp256k1 => {
                    let pubkey: EcfpPublicKey<sdk::curve::Secp256k1, 32> = parse_pubkey(&pubkey);
                    if pubkey.schnorr_verify(&msg, &signature).is_ok() {
                        vec![1]
                    } else {
                        vec![0]
                    }
                }
            },
            Command::Sleep { n_ticks } => {
                let mut count = 0;
                loop {
                    match sdk::ux::get_event() {
                        sdk::ux::Event::Ticker => {
                            count += 1;
                            if count == n_ticks {
                                break;
                            }
                        }
                        _ => (), // ignore any other type of event
                    }
                }

                vec![]
            }
        };

        sdk::comm::send_message(&response);
    }
}
