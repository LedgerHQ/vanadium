// SPDX-License-Identifier: CC0-1.0

//! SHA256 implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use sdk::hash::Hasher as _;

use crate::{sha256d, FromSliceError};

crate::internal_macros::hash_type! {
    256,
    false,
    "Output of the SHA256 hash function."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut res = [0u8; 32];
    e.hasher.digest(&mut res);
    Hash(res)
}

/// Engine to compute SHA256 hash function.
#[derive(Clone)]
pub struct HashEngine {
    length: usize,
    hasher: sdk::hash::Sha256,
}

impl Default for HashEngine {
    fn default() -> Self { HashEngine { length: 0, hasher: sdk::hash::Sha256::new() } }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> usize { self.length }

    fn input(&mut self, inp: &[u8]) { self.hasher.update(inp); }
}

impl Hash {
    /// Iterate the sha256 algorithm to turn a sha256 hash into a sha256d hash
    pub fn hash_again(&self) -> sha256d::Hash {
        crate::Hash::from_byte_array(<Self as crate::Hash>::hash(&self.0).0)
    }
}

/// Output of the SHA256 hash function.
#[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Midstate(pub [u8; 32]);

crate::internal_macros::arr_newtype_fmt_impl!(Midstate, 32);
serde_impl!(Midstate, 32);
borrow_slice_impl!(Midstate);

impl<I: SliceIndex<[u8]>> Index<I> for Midstate {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl str::FromStr for Midstate {
    type Err = hex::HexToArrayError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { hex::FromHex::from_hex(s) }
}

impl Midstate {
    /// Length of the midstate, in bytes.
    const LEN: usize = 32;

    /// Flag indicating whether user-visible serializations of this hash
    /// should be backward. For some reason Satoshi decided this should be
    /// true for `Sha256dHash`, so here we are.
    const DISPLAY_BACKWARD: bool = true;

    /// Construct a new [`Midstate`] from the inner value.
    pub const fn from_byte_array(inner: [u8; 32]) -> Self { Midstate(inner) }

    /// Copies a byte slice into the [`Midstate`] object.
    pub fn from_slice(sl: &[u8]) -> Result<Midstate, FromSliceError> {
        if sl.len() != Self::LEN {
            Err(FromSliceError { expected: Self::LEN, got: sl.len() })
        } else {
            let mut ret = [0; 32];
            ret.copy_from_slice(sl);
            Ok(Midstate(ret))
        }
    }

    /// Unwraps the [`Midstate`] and returns the underlying byte array.
    pub fn to_byte_array(self) -> [u8; 32] { self.0 }
}

impl hex::FromHex for Midstate {
    type Error = hex::HexToArrayError;

    fn from_hex(s: &str) -> Result<Self, Self::Error> {
        // DISPLAY_BACKWARD is true
        let mut bytes = <[u8; 32]>::from_hex(s)?;
        bytes.reverse();
        Ok(Midstate(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sha256, Hash as _, HashEngine};

    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        #[derive(Clone)]
        struct Test {
            input: &'static str,
            output: Vec<u8>,
            output_str: &'static str,
        }

        #[rustfmt::skip]
        let tests = vec![
            // Examples from wikipedia
            Test {
                input: "",
                output: vec![
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
                ],
                output_str: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output: vec![
                    0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94,
                    0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
                    0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
                    0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92,
                ],
                output_str: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog.",
                output: vec![
                    0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
                    0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
                    0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2,
                    0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
                ],
                output_str: "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
            },
        ];

        for test in tests {
            // Hash through high-level API, check hex encoding/decoding
            let hash = sha256::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha256::Hash>().expect("parse hex"));
            assert_eq!(&hash[..], &test.output[..]);
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through engine, checking that we can input byte by byte
            let mut engine = sha256::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            let manual_hash = sha256::Hash::from_engine(engine);
            assert_eq!(hash, manual_hash);
            assert_eq!(hash.to_byte_array()[..].as_ref(), test.output.as_slice());
        }
    }

    #[test]
    fn fmt_roundtrips() {
        let hash = sha256::Hash::hash(b"some arbitrary bytes");
        let hex = format!("{}", hash);
        let rinsed = hex.parse::<sha256::Hash>().expect("failed to parse hex");
        assert_eq!(rinsed, hash)
    }

    #[cfg(feature = "serde")]
    #[test]
    fn sha256_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        #[rustfmt::skip]
        static HASH_BYTES: [u8; 32] = [
            0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
            0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97,
            0xaa, 0x63, 0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2,
            0xb7, 0x65, 0x44, 0x8c, 0x86, 0x35, 0xfb, 0x6c,
        ];

        let hash = sha256::Hash::from_slice(&HASH_BYTES).expect("right number of bytes");
        assert_tokens(&hash.compact(), &[Token::BorrowedBytes(&HASH_BYTES[..])]);
        assert_tokens(
            &hash.readable(),
            &[Token::Str("ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c")],
        );
    }
}

#[cfg(bench)]
mod benches {
    use test::Bencher;

    use crate::{sha256, Hash, HashEngine};

    #[bench]
    pub fn sha256_10(bh: &mut Bencher) {
        let mut engine = sha256::Hash::engine();
        let bytes = [1u8; 10];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_1k(bh: &mut Bencher) {
        let mut engine = sha256::Hash::engine();
        let bytes = [1u8; 1024];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }

    #[bench]
    pub fn sha256_64k(bh: &mut Bencher) {
        let mut engine = sha256::Hash::engine();
        let bytes = [1u8; 65536];
        bh.iter(|| {
            engine.input(&bytes);
        });
        bh.bytes = bytes.len() as u64;
    }
}
