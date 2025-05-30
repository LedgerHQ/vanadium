// SPDX-License-Identifier: CC0-1.0

//! SHA512 implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use sdk::hash::Hasher as _;

use crate::FromSliceError;

crate::internal_macros::hash_type! {
    512,
    false,
    "Output of the SHA512 hash function."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut res = [0u8; 64];
    e.hasher.digest(&mut res);
    Hash(res)
}

/// Engine to compute SHA512 hash function.
#[derive(Clone)]
pub struct HashEngine {
    length: usize,
    hasher: sdk::hash::Sha512,
}

impl Default for HashEngine {
    #[rustfmt::skip]
    fn default() -> Self {
        HashEngine {
            length: 0,
            hasher: sdk::hash::Sha512::new(),
        }
    }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 128;

    fn n_bytes_hashed(&self) -> usize { self.length }

    fn input(&mut self, inp: &[u8]) { self.hasher.update(inp); }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use crate::{sha512, Hash, HashEngine};

        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Test vectors computed with `sha512sum`
            Test {
                input: "",
                output: vec![
                    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
                    0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
                    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
                    0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
                    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
                    0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
                    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
                    0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
                ],
                output_str: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output: vec![
                    0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73,
                    0xf7, 0x3f, 0xba, 0xc0, 0x43, 0x5e, 0xd7, 0x69,
                    0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88,
                    0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64,
                    0x2e, 0x93, 0xa2, 0x52, 0xa9, 0x54, 0xf2, 0x39,
                    0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6,
                    0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f,
                    0xa0, 0x53, 0x8f, 0x3d, 0xb8, 0x54, 0xfe, 0xe6,
                ],
                output_str: "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output: vec![
                    0x91, 0xea, 0x12, 0x45, 0xf2, 0x0d, 0x46, 0xae,
                    0x9a, 0x03, 0x7a, 0x98, 0x9f, 0x54, 0xf1, 0xf7,
                    0x90, 0xf0, 0xa4, 0x76, 0x07, 0xee, 0xb8, 0xa1,
                    0x4d, 0x12, 0x89, 0x0c, 0xea, 0x77, 0xa1, 0xbb,
                    0xc6, 0xc7, 0xed, 0x9c, 0xf2, 0x05, 0xe6, 0x7b,
                    0x7f, 0x2b, 0x8f, 0xd4, 0xc7, 0xdf, 0xd3, 0xa7,
                    0xa8, 0x61, 0x7e, 0x45, 0xf3, 0xc4, 0x63, 0xd4,
                    0x81, 0xc7, 0xe5, 0x86, 0xc3, 0x9a, 0xc1, 0xed,
                ],
                output_str: "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha512::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha512::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha512::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha512::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn sha512_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        use crate::{sha512, Hash};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 64] = [
            0x8b, 0x41, 0xe1, 0xb7, 0x8a, 0xd1, 0x15, 0x21,
            0x11, 0x3c, 0x52, 0xff, 0x18, 0x2a, 0x1b, 0x8e,
            0x0a, 0x19, 0x57, 0x54, 0xaa, 0x52, 0x7f, 0xcd,
            0x00, 0xa4, 0x11, 0x62, 0x0b, 0x46, 0xf2, 0x0f,
            0xff, 0xfb, 0x80, 0x88, 0xcc, 0xf8, 0x54, 0x97,
            0x12, 0x1a, 0xd4, 0x49, 0x9e, 0x08, 0x45, 0xb8,
            0x76, 0xf6, 0xdd, 0x66, 0x40, 0x08, 0x8a, 0x2f,
            0x0b, 0x2d, 0x8a, 0x60, 0x0b, 0xdf, 0x4c, 0x0c,
        ];

        let hash = sha512::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(
            &hash.readable(),
            &[Token::Str(
                "8b41e1b78ad11521113c52ff182a1b8e0a195754aa527fcd00a411620b46f20f\
                 fffb8088ccf85497121ad4499e0845b876f6dd6640088a2f0b2d8a600bdf4c0c",
            )],
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha512, Hash, HashEngine};

    #[bench]
    pub fn sha512_10(bh: &mut Bencher) {
        let mut engine = sha512::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_1k(bh: &mut Bencher) {
        let mut engine = sha512::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha512_64k(bh: &mut Bencher) {
        let mut engine = sha512::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
