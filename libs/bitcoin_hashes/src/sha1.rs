// SPDX-License-Identifier: CC0-1.0

//! SHA1 implementation.
//!
//! Unlike the other hash functions in this crate, SHA-1 is implemented in software rather than
//! through an ECALL: no Vanadium target exposes it, and the only consumers are legacy DNSSEC
//! constructions (NSEC3 owner-name hashing and SHA-1 DS digests), which are neither
//! performance-sensitive nor used for anything security-critical on their own.

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use crate::{FromSliceError, HashEngine as _};

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the SHA1 hash function."
}

const BLOCK_SIZE: usize = 64;

fn from_engine(mut e: HashEngine) -> Hash {
    let data_len = e.length as u64;

    // Pad with a single 1 bit, then zeroes, until 8 bytes remain in the final block, then append
    // the message length in bits as a big-endian u64.
    e.input(&[0x80]);
    while e.length % BLOCK_SIZE != BLOCK_SIZE - 8 {
        e.input(&[0]);
    }
    e.input(&(8 * data_len).to_be_bytes());
    debug_assert_eq!(e.length % BLOCK_SIZE, 0);

    let mut ret = [0; 20];
    for (val, ret_bytes) in e.h.iter().zip(ret.chunks_exact_mut(4)) {
        ret_bytes.copy_from_slice(&val.to_be_bytes());
    }
    Hash(ret)
}

/// Engine to compute SHA1 hash function.
#[derive(Clone)]
pub struct HashEngine {
    h: [u32; 5],
    length: usize,
    buffer: [u8; BLOCK_SIZE],
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            length: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> usize { self.length }

    fn input(&mut self, mut inp: &[u8]) {
        while !inp.is_empty() {
            let buf_idx = self.length % BLOCK_SIZE;
            let rem_len = BLOCK_SIZE - buf_idx;
            let write_len = core::cmp::min(rem_len, inp.len());

            self.buffer[buf_idx..buf_idx + write_len].copy_from_slice(&inp[..write_len]);
            self.length += write_len;
            if self.length % BLOCK_SIZE == 0 {
                self.process_block();
            }
            inp = &inp[write_len..];
        }
    }
}

impl HashEngine {
    fn process_block(&mut self) {
        let mut w = [0u32; 80];
        for (w_val, buff_bytes) in w.iter_mut().zip(self.buffer.chunks_exact(4)) {
            *w_val = u32::from_be_bytes(buff_bytes.try_into().expect("4 byte slice"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for (i, w_val) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*w_val);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(feature = "alloc")]
    fn test() {
        use crate::{sha1, Hash, HashEngine};

        struct Test {
            input: &'static str,
            output_str: &'static str,
        }

        let tests = vec![
            // Examples from FIPS 180-2 and the SHA-1 test vectors.
            Test { input: "", output_str: "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
            Test { input: "abc", output_str: "a9993e364706816aba3e25717850c26c9cd0d89d" },
            Test {
                input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                output_str: "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            },
            Test {
                input: "The quick brown fox jumps over the lazy dog",
                output_str: "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            },
        ];

        for test in tests {
            // Hash through the high-level API, checking hex encoding/decoding.
            let hash = sha1::Hash::hash(test.input.as_bytes());
            assert_eq!(hash, test.output_str.parse::<sha1::Hash>().expect("parse hex"));
            assert_eq!(&hash.to_string(), &test.output_str);

            // Hash through the engine, checking that we can input byte by byte.
            let mut engine = sha1::Hash::engine();
            for ch in test.input.as_bytes() {
                engine.input(&[*ch]);
            }
            assert_eq!(hash, sha1::Hash::from_engine(engine));
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_multiple_blocks() {
        use crate::{sha1, Hash};

        // 1_000_000 repetitions of "a", the fourth FIPS 180-2 sample.
        let mut engine = sha1::Hash::engine();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            crate::HashEngine::input(&mut engine, &chunk);
        }
        assert_eq!(
            sha1::Hash::from_engine(engine).to_string(),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }
}
