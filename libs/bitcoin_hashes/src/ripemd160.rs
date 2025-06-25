// SPDX-License-Identifier: CC0-1.0

//! RIPEMD160 implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use sdk::hash::Hasher as _;

use crate::FromSliceError;

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the RIPEMD160 hash function."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut res = [0u8; 20];
    e.hasher.digest(&mut res);
    Hash(res)
}

/// Engine to compute RIPEMD160 hash function.
#[derive(Clone)]
pub struct HashEngine {
    length: usize,
    hasher: sdk::hash::Ripemd160,
}

impl Default for HashEngine {
    fn default() -> Self { HashEngine { length: 0, hasher: sdk::hash::Ripemd160::new() } }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> usize { self.length }

    fn input(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.length += data.len();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use std::convert::TryFrom;

        use crate::{ripemd160, Hash, HashEngine};

        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Test messages from FIPS 180-1
            Test {
                input: "abc",
                output: vec![
                    0x8e, 0xb2, 0x08, 0xf7,
                    0xe0, 0x5d, 0x98, 0x7a,
                    0x9b, 0x04, 0x4a, 0x8e,
                    0x98, 0xc6, 0xb0, 0x87,
                    0xf1, 0x5a, 0x0b, 0xfc,
                ],
                output_str: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
            },
            Test {
                input:
                     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                output: vec![
                    0x12, 0xa0, 0x53, 0x38,
                    0x4a, 0x9c, 0x0c, 0x88,
                    0xe4, 0x05, 0xa0, 0x6c,
                    0x27, 0xdc, 0xf4, 0x9a,
                    0xda, 0x62, 0xeb, 0x2b,
                ],
                output_str: "12a053384a9c0c88e405a06c27dcf49ada62eb2b"
            },
            // Examples from wikipedia
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output: vec![
                    0x37, 0xf3, 0x32, 0xf6,
                    0x8d, 0xb7, 0x7b, 0xd9,
                    0xd7, 0xed, 0xd4, 0x96,
                    0x95, 0x71, 0xad, 0x67,
                    0x1c, 0xf9, 0xdd, 0x3b,
                ],
                output_str: "37f332f68db77bd9d7edd4969571ad671cf9dd3b",
            },
            Test {
                input: "The quick brown fox jumps over the lazy cog",
                output: vec![
                    0x13, 0x20, 0x72, 0xdf,
                    0x69, 0x09, 0x33, 0x83,
                    0x5e, 0xb8, 0xb6, 0xad,
                    0x0b, 0x77, 0xe7, 0xb6,
                    0xf1, 0x4a, 0xca, 0xd7,
                ],
                output_str: "132072df690933835eb8b6ad0b77e7b6f14acad7",
            },
        ];

        for mut test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = ripemd160::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<ripemd160::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);
            assert_eq!(
                ripemd160::Hash::from_bytes_ref(
                    <&[u8; 20]>::try_from(&*test.output).expect("known length")
                ),
                &hash
            );
            assert_eq!(
                ripemd160::Hash::from_bytes_mut(
                    <&mut [u8; 20]>::try_from(&mut *test.output).expect("known length")
                ),
                &hash
            );

            // Hash through engine, checking that we can input byte by byte
            let mut engine = ripemd160::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = ripemd160::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.as_byte_array(), test.output.as_slice());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ripemd_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        use crate::{ripemd160, Hash};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 20] = [
            0x13, 0x20, 0x72, 0xdf,
            0x69, 0x09, 0x33, 0x83,
            0x5e, 0xb8, 0xb6, 0xad,
            0x0b, 0x77, 0xe7, 0xb6,
            0xf1, 0x4a, 0xca, 0xd7,
        ];

        let hash = ripemd160::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(&hash.readable(), &[Token::Str("132072df690933835eb8b6ad0b77e7b6f14acad7")]);
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{ripemd160, Hash, HashEngine};

    #[bench]
    pub fn ripemd160_10(bh: &mut Bencher) {
        let mut engine = ripemd160::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn ripemd160_1k(bh: &mut Bencher) {
        let mut engine = ripemd160::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn ripemd160_64k(bh: &mut Bencher) {
        let mut engine = ripemd160::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
