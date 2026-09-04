#![cfg_attr(feature = "target_vanadium_ledger", no_std, no_main)]

use sdk::{
    bignum::{BigNum, BigNumMod, ModulusProvider, PrimeModulusProvider},
    curve::{Curve, EcfpPrivateKey, EcfpPublicKey, HdCurve as _, Point},
    hash::Hasher,
    App, AppBuilder,
};

extern crate alloc;

use alloc::{vec, vec::Vec};
use common::{Command, Curve as WireCurve, ECPointOperation, HashId};

sdk::bootstrap!();

/// The curve order of the Secp256k1 curve, represented as a ModulusProvider from Vanadium's app-sdk
#[derive(Debug, Clone, Copy)]
pub struct N;
impl ModulusProvider<32> for N {
    const M: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
}
impl PrimeModulusProvider<32> for N {}

/// Parses an uncompressed SEC1 pubkey (`0x04 || X || Y`) into an `EcfpPublicKey`.
///
/// Generic over the scalar length so the same code serves all three curves; the encoded length
/// is checked against `1 + 2 * SCALAR_LENGTH` rather than a literal.
fn parse_pubkey<C: Curve<SCALAR_LENGTH>, const SCALAR_LENGTH: usize>(
    pubkey: &[u8],
) -> EcfpPublicKey<C, SCALAR_LENGTH> {
    assert_eq!(
        pubkey.len(),
        1 + 2 * SCALAR_LENGTH,
        "invalid pubkey: wrong length for this curve"
    );
    if pubkey[0] != 0x04 {
        panic!("invalid pubkey: it must start with 0x04");
    }
    EcfpPublicKey::new(
        pubkey[1..1 + SCALAR_LENGTH].try_into().unwrap(),
        pubkey[1 + SCALAR_LENGTH..].try_into().unwrap(),
    )
}

/// Verifies a DER-encoded ECDSA signature, returning sadik's boolean encoding.
fn ecdsa_verify<C: Curve<SCALAR_LENGTH>, const SCALAR_LENGTH: usize>(
    pubkey: &[u8],
    msg_hash: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let pubkey = parse_pubkey::<C, SCALAR_LENGTH>(pubkey);
    if pubkey.ecdsa_verify_hash(msg_hash, signature).is_ok() {
        vec![1]
    } else {
        vec![0]
    }
}

/// Point addition and scalar multiplication for one curve width.
///
/// A macro rather than a generic function because `Point::from_bytes` takes
/// `&[u8; 1 + 2 * SCALAR_LENGTH]`, which cannot be named generically without
/// `generic_const_exprs`.
macro_rules! point_operation {
    ($curve:ty, $scalar_len:expr, $point_len:expr, $operation:expr) => {
        match $operation {
            ECPointOperation::Add(p, q) => {
                let p_bytes: [u8; $point_len] = p.as_slice().try_into().unwrap();
                let p = Point::<$curve, $scalar_len>::from_bytes(&p_bytes).unwrap();
                let q_bytes: [u8; $point_len] = q.as_slice().try_into().unwrap();
                let q = Point::<$curve, $scalar_len>::from_bytes(&q_bytes).unwrap();
                (&p + &q).to_bytes().to_vec()
            }
            ECPointOperation::ScalarMult(p, k) => {
                let p_bytes: [u8; $point_len] = p.as_slice().try_into().unwrap();
                let p = Point::<$curve, $scalar_len>::from_bytes(&p_bytes).unwrap();
                let k: [u8; $scalar_len] = k.as_slice().try_into().unwrap();
                (&p * &k).to_bytes().to_vec()
            }
        }
    };
}

#[sdk::handler]
async fn process_message(_app: &mut App, msg: &[u8]) -> Vec<u8> {
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
            modular,
        } => {
            if !modular {
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
                                panic!("Multiplication is only supported for modular big numbers")
                            }
                            common::BigIntOperator::Pow => {
                                panic!("Exponentiation is only supported for modular big numbers")
                            }
                            common::BigIntOperator::Inv => {
                                panic!("Modular inverse is only supported for modular big numbers")
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

                if let common::BigIntOperator::Pow = operator {
                    if a.len() != 32 {
                        panic!("Only modular big numbers of length 32 are supported in sadik");
                    }
                    let a: BigNumMod<32, N> =
                        BigNumMod::from_be_bytes(a.as_slice().try_into().unwrap());

                    macro_rules! impl_modular_pow {
                        ($len:expr, $b:expr, $a:expr) => {{
                            let b =
                                BigNum::<$len>::from_be_bytes($b.as_slice().try_into().unwrap());
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
                } else if let common::BigIntOperator::Inv = operator {
                    if a.len() != 32 {
                        panic!("Only modular big numbers of length 32 are supported in sadik");
                    }
                    let a: BigNumMod<32, N> =
                        BigNumMod::from_be_bytes(a.as_slice().try_into().unwrap());
                    a.inv().to_be_bytes().to_vec()
                } else {
                    if a.len() != 32 || b.len() != 32 {
                        panic!("Only modular big numbers of length 32 are supported in sadik");
                    }

                    let a: BigNumMod<32, N> =
                        BigNumMod::from_be_bytes(a.as_slice().try_into().unwrap());
                    let b: BigNumMod<32, N> =
                        BigNumMod::from_be_bytes(b.as_slice().try_into().unwrap());

                    match operator {
                        common::BigIntOperator::Add => (&a + &b).to_be_bytes().to_vec(),
                        common::BigIntOperator::Sub => (&a - &b).to_be_bytes().to_vec(),
                        common::BigIntOperator::Mul => (&a * &b).to_be_bytes().to_vec(),
                        common::BigIntOperator::Pow | common::BigIntOperator::Inv => {
                            panic!("Unreachable code")
                        }
                    }
                }
            }
        }
        Command::GetMasterFingerprint { curve } => match curve {
            WireCurve::Secp256k1 => sdk::curve::Secp256k1::get_master_fingerprint()
                .to_be_bytes()
                .to_vec(),
            // The other curves are verification-only: the device derives no keys on them.
            WireCurve::Secp256r1 | WireCurve::Secp384r1 => {
                panic!("the master fingerprint is only supported on secp256k1")
            }
        },
        Command::DeriveHdNode { curve, path } => match curve {
            // returns the concatenation of the chaincode and private key
            WireCurve::Secp256k1 => {
                let node = sdk::curve::Secp256k1::derive_hd_node(&path).unwrap();
                let mut result = node.chaincode.to_vec();
                result.extend_from_slice(&node.privkey[..]);
                result
            }
            // The other curves are verification-only: the device derives no keys on them.
            WireCurve::Secp256r1 | WireCurve::Secp384r1 => {
                panic!("HD derivation is only supported on secp256k1")
            }
        },
        Command::DeriveSlip21Key { labels } => {
            let labels_slices: Vec<&[u8]> = labels.iter().map(|v| v.as_slice()).collect();
            sdk::slip21::derive_slip21_key(&labels_slices)
                .dangerous_as_raw_bytes()
                .to_vec()
        }
        Command::ECPointOperation { curve, operation } => match curve {
            WireCurve::Secp256k1 => {
                point_operation!(sdk::curve::Secp256k1, 32, 65, operation)
            }
            WireCurve::Secp256r1 => {
                point_operation!(sdk::curve::Secp256r1, 32, 65, operation)
            }
            WireCurve::Secp384r1 => {
                point_operation!(sdk::curve::Secp384r1, 48, 97, operation)
            }
        },
        Command::EcdsaSign {
            curve,
            privkey,
            msg_hash,
        } => match curve {
            WireCurve::Secp256k1 => {
                let msg_hash: [u8; 32] = msg_hash
                    .as_slice()
                    .try_into()
                    .expect("hash must be 32 bytes");
                let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> =
                    EcfpPrivateKey::new(privkey.as_slice().try_into().expect("invalid privkey"));

                privkey.ecdsa_sign_hash(&msg_hash).unwrap()
            }
            // The other curves are verification-only: the device derives no keys on them.
            WireCurve::Secp256r1 | WireCurve::Secp384r1 => {
                panic!("ECDSA signing is only supported on secp256k1")
            }
        },
        Command::EcdsaVerify {
            curve,
            msg_hash,
            pubkey,
            signature,
        } => match curve {
            WireCurve::Secp256k1 => {
                ecdsa_verify::<sdk::curve::Secp256k1, 32>(&pubkey, &msg_hash, &signature)
            }
            WireCurve::Secp256r1 => {
                ecdsa_verify::<sdk::curve::Secp256r1, 32>(&pubkey, &msg_hash, &signature)
            }
            WireCurve::Secp384r1 => {
                ecdsa_verify::<sdk::curve::Secp384r1, 48>(&pubkey, &msg_hash, &signature)
            }
        },
        Command::SchnorrSign {
            curve,
            privkey,
            msg,
        } => match curve {
            WireCurve::Secp256k1 => {
                let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> =
                    EcfpPrivateKey::new(privkey.as_slice().try_into().expect("invalid privkey"));
                privkey.schnorr_sign(&msg, None).unwrap()
            }
            // BIP-340 is defined for secp256k1 alone.
            WireCurve::Secp256r1 | WireCurve::Secp384r1 => {
                panic!("Schnorr signing is only supported on secp256k1")
            }
        },
        Command::SchnorrVerify {
            curve,
            pubkey,
            msg,
            signature,
        } => match curve {
            WireCurve::Secp256k1 => {
                let pubkey: EcfpPublicKey<sdk::curve::Secp256k1, 32> =
                    parse_pubkey::<sdk::curve::Secp256k1, 32>(&pubkey);
                if pubkey.schnorr_verify(&msg, &signature).is_ok() {
                    vec![1]
                } else {
                    vec![0]
                }
            }
            // BIP-340 is defined for secp256k1 alone.
            WireCurve::Secp256r1 | WireCurve::Secp384r1 => {
                panic!("Schnorr verification is only supported on secp256k1")
            }
        },
        Command::Sleep { n_ticks } => {
            let mut count = 0;
            loop {
                match sdk::executor::block_on(sdk::ux::get_event()) {
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
        Command::WriteStorage { slot, data } => {
            let mut storage_data = [0u8; 32];
            let len = core::cmp::min(data.len(), 32);
            storage_data[..len].copy_from_slice(&data[..len]);
            sdk::storage::write_slot(slot, &storage_data).expect("Failed to write storage");
            vec![]
        }
        Command::ReadStorage { slot } => sdk::storage::read_slot(slot)
            .expect("Failed to read storage")
            .to_vec(),
    };

    response
}

pub fn main() {
    AppBuilder::new("Sadik", env!("CARGO_PKG_VERSION"), process_message).run();
}
