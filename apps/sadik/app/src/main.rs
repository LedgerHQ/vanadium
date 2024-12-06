#![feature(start)]
#![cfg_attr(target_arch = "riscv32", no_std, no_main)]

#[cfg(target_arch = "riscv32")]
use sdk::fatal;

use sdk::{
    bignum::{BigNum, BigNumMod, Modulus},
    curve::Curve as _,
    hash::Hasher,
};

extern crate alloc;

use alloc::string::ToString;
use alloc::vec::Vec;
use common::{Command, Curve, HashId};

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
pub fn _start(_argc: isize, _argv: *const *const u8) -> isize {
    main(_argc, _argv)
}

#[start]
pub fn main(_: isize, _: *const *const u8) -> isize {
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
                    result.extend_from_slice(&node.privkey);
                    result
                }
            },
        };

        sdk::comm::send_message(&response);
    }
}
