// SPDX-License-Identifier: CC0-1.0

//! SHA384 implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use sdk::hash::Hasher as _;

use crate::FromSliceError;

crate::internal_macros::hash_type! {
    384,
    false,
    "Output of the SHA384 hash function."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut res = [0u8; 48];
    e.hasher.digest(&mut res);
    Hash(res)
}

/// Engine to compute SHA384 hash function.
#[derive(Clone)]
pub struct HashEngine {
    length: usize,
    hasher: sdk::hash::Sha384,
}

impl Default for HashEngine {
    #[rustfmt::skip]
    fn default() -> Self {
        HashEngine {
            length: 0,
            hasher: sdk::hash::Sha384::new(),
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
        use crate::{sha384, Hash, HashEngine};

        struct Test {
            input: &'static str,
            output_str: &'static str,
        }

        // Examples from the go sha384 tests, as used by the upstream bitcoin_hashes crate.
        let tests = vec![
            Test {
                input: "",
                output_str: "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
            },
            Test {
                input: "abcdef",
                output_str: "c6a4c65b227e7387b9c3e839d44869c4cfca3ef583dea64117859b808c1e3d8ae689e1e314eeef52a6ffe22681aa11f5",
            },
            Test {
                input: "Discard medicine more than two years old.",
                output_str: "86f58ec2d74d1b7f8eb0c2ff0967316699639e8d4eb129de54bdf34c96cdbabe200d052149f2dd787f43571ba74670d4",
            },
            Test {
                input: "There is no reason for any individual to have a computer in their home. -Ken Olsen, 1977",
                output_str: "722d10c5de371ec0c8c4b5247ac8a5f1d240d68c73f8da13d8b25f0166d6f309bf9561979a111a0049405771d201941a",
            },
            Test {
                input: "The major problem is with sendmail.  -Mark Horton",
                output_str: "5ff8e075e465646e7b73ef36d812c6e9f7d60fa6ea0e533e5569b4f73cde53cdd2cc787f33540af57cca3fe467d32fe0",
            },
        ];

        for test in tests {
            // Hash through the high-level API, checking hex encoding/decoding.
            let hash = sha384::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha384::Hash>().expect("parse hex"));
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through the engine, checking that we can input byte by byte.
            let mut engine = sha384::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            assert_eq!(hash, sha384::Hash::from_engine(engine));
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_multiple_blocks() {
        use crate::{sha384, Hash};

        // 1_000_000 repetitions of "a", from the FIPS 180-4 sample vectors.
        let mut engine = sha384::Hash::engine();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            crate::HashEngine::input(&mut engine, &chunk);
        }
        assert_eq!(
            sha384::Hash::from_engine(engine).to_string(),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b\
             07b8b3dc38ecc4ebae97ddd87f3d8985"
        );
    }
}
