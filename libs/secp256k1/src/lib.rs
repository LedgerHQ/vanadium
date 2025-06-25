// SPDX-License-Identifier: CC0-1.0

//! Rust bindings for Pieter Wuille's secp256k1 library, which is used for
//! fast and accurate manipulation of ECDSA signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!
//! To minimize dependencies, some functions are feature-gated. To generate
//! random keys or to re-randomize a context object, compile with the
//! `rand-std` feature. If you are willing to use the `rand-std` feature, we
//! have enabled an additional defense-in-depth sidechannel protection for
//! our context objects, which re-blinds certain operations on secret key
//! data. To de/serialize objects with serde, compile with "serde".
//! **Important**: `serde` encoding is **not** the same as consensus
//! encoding!
//!
//! Where possible, the bindings use the Rust type system to ensure that
//! API usage errors are impossible. For example, the library uses context
//! objects that contain precomputation tables which are created on object
//! construction. Since this is a slow operation (10+ milliseconds, vs ~50
//! microseconds for typical crypto operations, on a 2.70 Ghz i7-6820HQ)
//! the tables are optional, giving a performance boost for users who only
//! care about signing, only care about verification, or only care about
//! parsing. In the upstream library, if you attempt to sign a message using
//! a context that does not support this, it will trigger an assertion
//! failure and terminate the program. In `rust-secp256k1`, this is caught
//! at compile-time; in fact, it is impossible to compile code that will
//! trigger any assertion failures in the upstream library.
//!
//! ```rust
//! # #[cfg(all(feature = "rand-std", feature = "hashes-std"))] {
//! use secp256k1::rand::rngs::OsRng;
//! use secp256k1::{Secp256k1, Message};
//! use secp256k1::hashes::{sha256, Hash};
//!
//! let secp = Secp256k1::new();
//! let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
//! let digest = sha256::Hash::hash("Hello World!".as_bytes());
//! let message = Message::from_digest(digest.to_byte_array());
//!
//! let sig = secp.sign_ecdsa(&message, &secret_key);
//! assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! If the "global-context" feature is enabled you have access to an alternate API.
//!
//! ```rust
//! # #[cfg(all(feature = "global-context", feature = "hashes-std", feature = "rand-std"))] {
//! use secp256k1::{generate_keypair, Message};
//! use secp256k1::hashes::{sha256, Hash};
//!
//! let (secret_key, public_key) = generate_keypair(&mut rand::thread_rng());
//! let digest = sha256::Hash::hash("Hello World!".as_bytes());
//! let message = Message::from_digest(digest.to_byte_array());
//!
//! let sig = secret_key.sign_ecdsa(message);
//! assert!(sig.verify(&message, &public_key).is_ok());
//! # }
//! ```
//!
//! The above code requires `rust-secp256k1` to be compiled with the `rand-std` and `hashes-std`
//! feature enabled, to get access to [`generate_keypair`](struct.Secp256k1.html#method.generate_keypair)
//! Alternately, keys and messages can be parsed from slices, like
//!
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! use vlib_secp256k1::{Secp256k1, Message, SecretKey, PublicKey};
//!
//! let secp = Secp256k1::new();
//! let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
//! let public_key = PublicKey::from_secret_key(&secp, &secret_key);
//! // This is unsafe unless the supplied byte slice is the output of a cryptographic hash function.
//! // See the above example for how to use this library together with `hashes-std`.
//! let message = Message::from_digest_slice(&[0xab; 32]).expect("32 bytes");
//!
//! let sig = secp.sign_ecdsa(&message, &secret_key);
//! assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Users who only want to verify signatures can use a cheaper context, like so:
//!
//! ```rust
//! # #[cfg(feature = "alloc")] {
//! use vlib_secp256k1::{Secp256k1, Message, ecdsa, PublicKey};
//!
//! let secp = Secp256k1::verification_only();
//!
//! let public_key = PublicKey::from_slice(&[
//!     0x02,
//!     0xc6, 0x6e, 0x7d, 0x89, 0x66, 0xb5, 0xc5, 0x55,
//!     0xaf, 0x58, 0x05, 0x98, 0x9d, 0xa9, 0xfb, 0xf8,
//!     0xdb, 0x95, 0xe1, 0x56, 0x31, 0xce, 0x35, 0x8c,
//!     0x3a, 0x17, 0x10, 0xc9, 0x62, 0x67, 0x90, 0x63,
//! ]).expect("public keys must be 33 or 65 bytes, serialized according to SEC 2");
//!
//! let message = Message::from_digest_slice(&[
//!     0xaa, 0xdf, 0x7d, 0xe7, 0x82, 0x03, 0x4f, 0xbe,
//!     0x3d, 0x3d, 0xb2, 0xcb, 0x13, 0xc0, 0xcd, 0x91,
//!     0xbf, 0x41, 0xcb, 0x08, 0xfa, 0xc7, 0xbd, 0x61,
//!     0xd5, 0x44, 0x53, 0xcf, 0x6e, 0x82, 0xb4, 0x50,
//! ]).expect("messages must be 32 bytes and are expected to be hashes");
//!
//! let sig = ecdsa::Signature::from_compact(&[
//!     0xdc, 0x4d, 0xc2, 0x64, 0xa9, 0xfe, 0xf1, 0x7a,
//!     0x3f, 0x25, 0x34, 0x49, 0xcf, 0x8c, 0x39, 0x7a,
//!     0xb6, 0xf1, 0x6f, 0xb3, 0xd6, 0x3d, 0x86, 0x94,
//!     0x0b, 0x55, 0x86, 0x82, 0x3d, 0xfd, 0x02, 0xae,
//!     0x3b, 0x46, 0x1b, 0xb4, 0x33, 0x6b, 0x5e, 0xcb,
//!     0xae, 0xfd, 0x66, 0x27, 0xaa, 0x92, 0x2e, 0xfc,
//!     0x04, 0x8f, 0xec, 0x0c, 0x88, 0x1c, 0x10, 0xc4,
//!     0xc9, 0x42, 0x8f, 0xca, 0x69, 0xc1, 0x32, 0xa2,
//! ]).expect("compact signatures are 64 bytes; DER signatures are 68-72 bytes");
//!
//! # #[cfg(not(secp256k1_fuzz))]
//! assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
//! # }
//! ```
//!
//! Observe that the same code using, say [`signing_only`](struct.Secp256k1.html#method.signing_only)
//! to generate a context would simply not compile.
//!
//! ## Crate features/optional dependencies
//!
//! This crate provides the following opt-in Cargo features:
//!
//! * `std` - use standard Rust library, enabled by default.
//! * `alloc` - use the `alloc` standard Rust library to provide heap allocations.
//! * `rand` - use `rand` library to provide random generator (e.g. to generate keys).
//! * `rand-std` - use `rand` library with its `std` feature enabled. (Implies `rand`.)
//! * `hashes` - use the `hashes` library.
//! * `hashes-std` - use the `hashes` library with its `std` feature enabled (implies `hashes`).
//! * `recovery` - enable functions that can compute the public key from signature.
//! * `lowmemory` - optimize the library for low-memory environments.
//! * `global-context` - enable use of global secp256k1 context (implies `std`).
//! * `serde` - implements serialization and deserialization for types in this crate using `serde`.
//!           **Important**: `serde` encoding is **not** the same as consensus encoding!
//!

// suppress dead code warnings in vlib-secp256k1, as we prefer to keep the code as close to the original as possible
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_variables)]
// Coding conventions
#![deny(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![warn(missing_docs, missing_copy_implementations, missing_debug_implementations)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate core;
#[cfg(bench)]
extern crate test;

#[cfg(feature = "hashes")]
pub extern crate hashes;
#[cfg(feature = "rand")]
pub extern crate rand;

#[macro_use]
mod macros;
#[macro_use]
mod secret;
mod context;
mod key;

mod sdk_helpers;

pub mod constants;
pub mod ecdsa;
pub mod scalar;
pub mod schnorr;
#[cfg(feature = "serde")]
mod serde_util;

use core::marker::PhantomData;
use core::{fmt, str};

#[cfg(feature = "serde")]
pub use serde;

#[cfg(feature = "alloc")]
pub use crate::context::{All, SignOnly, VerifyOnly};
pub use crate::context::{AllPreallocated, Context, Signing, Verification};
pub use crate::key::{InvalidParityValue, Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey};
pub use crate::scalar::Scalar;

/// The global context.
///
/// This context is usable everywhere. Note that unlike upstream, this doesn't require `std` but it
/// still does require enabling the feature for consistency.
#[cfg(feature = "global-context")]
pub static SECP256K1: &Secp256k1<All> = &Secp256k1 { phantom: PhantomData };

/// Trait describing something that promises to be a 32-byte random number; in particular,
/// it has negligible probability of being zero or overflowing the group order. Such objects
/// may be converted to `Message`s without any error paths.
#[deprecated(
    since = "0.29.0",
    note = "Please see v0.29.0 rust-secp256k1/CHANGELOG.md for suggestion"
)]
pub trait ThirtyTwoByteHash {
    /// Converts the object into a 32-byte array
    fn into_32(self) -> [u8; 32];
}

/// A (hashed) message input to an ECDSA signature.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);
impl_pretty_debug!(Message);

impl Message {
    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object. **WARNING:** the slice has to be a
    /// cryptographically secure hash of the actual message that's going to be signed. Otherwise
    /// the result of signing isn't a
    /// [secure signature](https://twitter.com/pwuille/status/1063582706288586752).
    #[inline]
    #[deprecated(since = "0.28.0", note = "use from_digest_slice instead")]
    pub fn from_slice(digest: &[u8]) -> Result<Message, Error> {
        Message::from_digest_slice(digest)
    }

    /// Creates a [`Message`] from a `digest`.
    ///
    /// The `digest` array has to be a cryptographically secure hash of the actual message that's
    /// going to be signed. Otherwise the result of signing isn't a [secure signature].
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    pub fn from_digest(digest: [u8; 32]) -> Message { Message(digest) }

    /// Creates a [`Message`] from a 32 byte slice `digest`.
    ///
    /// The slice has to be 32 bytes long and be a cryptographically secure hash of the actual
    /// message that's going to be signed. Otherwise the result of signing isn't a [secure
    /// signature].
    ///
    /// # Errors
    ///
    /// If `digest` is not exactly 32 bytes long.
    ///
    /// [secure signature]: https://twitter.com/pwuille/status/1063582706288586752
    #[inline]
    pub fn from_digest_slice(digest: &[u8]) -> Result<Message, Error> {
        match digest.len() {
            constants::MESSAGE_SIZE => {
                let mut ret = [0u8; constants::MESSAGE_SIZE];
                ret[..].copy_from_slice(digest);
                Ok(Message(ret))
            }
            _ => Err(Error::InvalidMessage),
        }
    }
}

#[allow(deprecated)]
impl<T: ThirtyTwoByteHash> From<T> for Message {
    /// Converts a 32-byte hash directly to a message without error paths.
    fn from(t: T) -> Message { Message(t.into_32()) }
}

impl fmt::LowerHex for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

/// The main error type for this library.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub enum Error {
    /// Signature failed verification.
    IncorrectSignature,
    /// Bad sized message ("messages" are actually fixed-sized digests [`constants::MESSAGE_SIZE`]).
    InvalidMessage,
    /// Bad public key.
    InvalidPublicKey,
    /// Bad signature.
    InvalidSignature,
    /// Bad secret key.
    InvalidSecretKey,
    /// Bad shared secret.
    InvalidSharedSecret,
    /// Bad recovery id.
    InvalidRecoveryId,
    /// Tried to add/multiply by an invalid tweak.
    InvalidTweak,
    /// Didn't pass enough memory to context creation with preallocated memory.
    NotEnoughMemory,
    /// Bad set of public keys.
    InvalidPublicKeySum,
    /// The only valid parity values are 0 or 1.
    InvalidParityValue(key::InvalidParityValue),
    /// Bad EllSwift value
    InvalidEllSwift,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use Error::*;

        match *self {
            IncorrectSignature => f.write_str("signature failed verification"),
            InvalidMessage => f.write_str("message was not 32 bytes (do you need to hash?)"),
            InvalidPublicKey => f.write_str("malformed public key"),
            InvalidSignature => f.write_str("malformed signature"),
            InvalidSecretKey => f.write_str("malformed or out-of-range secret key"),
            InvalidSharedSecret => f.write_str("malformed or out-of-range shared secret"),
            InvalidRecoveryId => f.write_str("bad recovery id"),
            InvalidTweak => f.write_str("bad tweak"),
            NotEnoughMemory => f.write_str("not enough memory allocated"),
            InvalidPublicKeySum => f.write_str(
                "the sum of public keys was invalid or the input vector lengths was less than 1",
            ),
            InvalidParityValue(e) => write_err!(f, "couldn't create parity"; e),
            InvalidEllSwift => f.write_str("malformed EllSwift value"),
        }
    }
}

/// The secp256k1 engine, used to execute all signature operations.
pub struct Secp256k1<C: Context> {
    phantom: PhantomData<C>,
}

// The underlying secp context does not contain any references to memory it does not own.
unsafe impl<C: Context> Send for Secp256k1<C> {}
// The API does not permit any mutation of `Secp256k1` objects except through `&mut` references.
unsafe impl<C: Context> Sync for Secp256k1<C> {}

impl<C: Context> PartialEq for Secp256k1<C> {
    fn eq(&self, _other: &Secp256k1<C>) -> bool { true }
}

impl<C: Context> Eq for Secp256k1<C> {}

impl<C: Context> fmt::Debug for Secp256k1<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<secp256k1 context, {}>", C::DESCRIPTION)
    }
}

/// Utility function used to parse hex into a target u8 buffer. Returns
/// the number of bytes converted or an error if it encounters an invalid
/// character or unexpected end of string.
fn from_hex(hex: &str, target: &mut [u8]) -> Result<usize, ()> {
    if hex.len() % 2 == 1 || hex.len() > target.len() * 2 {
        return Err(());
    }

    let mut b = 0;
    let mut idx = 0;
    for c in hex.bytes() {
        b <<= 4;
        match c {
            b'A'..=b'F' => b |= c - b'A' + 10,
            b'a'..=b'f' => b |= c - b'a' + 10,
            b'0'..=b'9' => b |= c - b'0',
            _ => return Err(()),
        }
        if (idx & 1) == 1 {
            target[idx / 2] = b;
            b = 0;
        }
        idx += 1;
    }
    Ok(idx / 2)
}

/// Utility function used to encode hex into a target u8 buffer. Returns
/// a reference to the target buffer as an str. Returns an error if the target
/// buffer isn't big enough.
#[inline]
fn to_hex<'a>(src: &[u8], target: &'a mut [u8]) -> Result<&'a str, ()> {
    let hex_len = src.len() * 2;
    if target.len() < hex_len {
        return Err(());
    }
    const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

    let mut i = 0;
    for &b in src {
        target[i] = HEX_TABLE[usize::from(b >> 4)];
        target[i + 1] = HEX_TABLE[usize::from(b & 0b00001111)];
        i += 2;
    }
    let result = &target[..hex_len];
    debug_assert!(str::from_utf8(result).is_ok());
    return unsafe { Ok(str::from_utf8_unchecked(result)) };
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    macro_rules! hex {
        ($hex:expr) => {{
            let mut result = vec![0; $hex.len() / 2];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    #[ignore] // Panicking from C may trap (SIGILL) intentionally, so we test this manually.
    #[cfg(feature = "alloc")]
    fn test_panic_raw_ctx_should_terminate_abnormally() {
        // Trying to use an all-zeros public key should cause an ARG_CHECK to trigger.
        let pk = PublicKey::from(sdk::curve::Secp256k1Point::new([0u8; 32], [0u8; 32]));
        pk.serialize();
    }

    #[test]
    fn signature_display() {
        let hex_str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
        let byte_str = hex!(hex_str);

        assert_eq!(
            ecdsa::Signature::from_der(&byte_str).expect("byte str decode"),
            ecdsa::Signature::from_str(hex_str).expect("byte str decode")
        );

        let sig = ecdsa::Signature::from_str(hex_str).expect("byte str decode");
        assert_eq!(&sig.to_string(), hex_str);
        assert_eq!(&format!("{:?}", sig), hex_str);

        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab4"
        )
        .is_err());
        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab"
        )
        .is_err());
        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eabxx"
        )
        .is_err());
        assert!(ecdsa::Signature::from_str(
            "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45\
             72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45"
        )
        .is_err());

        // 71 byte signature
        let hex_str = "30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce774b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776";
        let sig = ecdsa::Signature::from_str(hex_str).expect("byte str decode");
        assert_eq!(&format!("{}", sig), hex_str);
    }

    #[test]
    fn signature_lax_der() {
        macro_rules! check_lax_sig(
            ($hex:expr) => ({
                let sig = hex!($hex);
                assert!(ecdsa::Signature::from_der_lax(&sig[..]).is_ok());
            })
        );

        check_lax_sig!("304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c");
        check_lax_sig!("304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f");
        check_lax_sig!("3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a");
        check_lax_sig!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        check_lax_sig!("3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1");
        check_lax_sig!("3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60");
        check_lax_sig!("3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf");
    }

    #[test]
    fn test_bad_slice() {
        assert_eq!(
            ecdsa::Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE + 1]),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            ecdsa::Signature::from_der(&[0; constants::MAX_SIGNATURE_SIZE]),
            Err(Error::InvalidSignature)
        );

        assert_eq!(
            Message::from_digest_slice(&[0; constants::MESSAGE_SIZE - 1]),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            Message::from_digest_slice(&[0; constants::MESSAGE_SIZE + 1]),
            Err(Error::InvalidMessage)
        );
        assert!(Message::from_digest_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
        assert!(Message::from_digest_slice(&[1; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))] // fuzz-sigs have fixed size/format
    #[cfg(feature = "alloc")]
    fn test_noncedata() {
        let secp = Secp256k1::new();
        let msg = hex!("887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac");
        let msg = Message::from_digest_slice(&msg).unwrap();
        let noncedata = [42u8; 32];
        let sk =
            SecretKey::from_str("57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead")
                .unwrap();
        let expected_sig = hex!("24861b3edd4e7da43319c635091405feced6efa4ec99c3c3c35f6c3ba0ed8816116772e84994084db85a6c20589f6a85af569d42275c2a5dd900da5776b99d5d");
        let expected_sig = ecdsa::Signature::from_compact(&expected_sig).unwrap();

        let sig = secp.sign_ecdsa_with_noncedata(&msg, &sk, &noncedata);

        assert_eq!(expected_sig, sig);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))] // fixed sig vectors can't work with fuzz-sigs
    #[cfg(feature = "alloc")]
    fn test_low_s() {
        // nb this is a transaction on testnet
        // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
        //      input number 3
        let sig = hex!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        let pk = hex!("031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43");
        let msg = hex!("a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d");

        let secp = Secp256k1::new();
        let mut sig = ecdsa::Signature::from_der(&sig[..]).unwrap();
        let pk = PublicKey::from_slice(&pk[..]).unwrap();
        let msg = Message::from_digest_slice(&msg[..]).unwrap();

        // without normalization we expect this will fail
        assert_eq!(secp.verify_ecdsa(&msg, &sig, &pk), Err(Error::IncorrectSignature));
        // after normalization it should pass
        sig.normalize_s();
        assert_eq!(secp.verify_ecdsa(&msg, &sig, &pk), Ok(()));
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))] // fuzz-sigs have fixed size/format
    #[cfg(feature = "alloc")]
    fn test_low_r() {
        let secp = Secp256k1::new();
        let msg = hex!("887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac");
        let msg = Message::from_digest_slice(&msg).unwrap();
        let sk =
            SecretKey::from_str("57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead")
                .unwrap();
        let expected_sig = hex!("047dd4d049db02b430d24c41c7925b2725bcd5a85393513bdec04b4dc363632b1054d0180094122b380f4cfa391e6296244da773173e78fc745c1b9c79f7b713");
        let expected_sig = ecdsa::Signature::from_compact(&expected_sig).unwrap();

        let sig = secp.sign_ecdsa_low_r(&msg, &sk);

        assert_eq!(expected_sig, sig);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))] // fuzz-sigs have fixed size/format
    #[cfg(feature = "alloc")]
    fn test_grind_r() {
        let secp = Secp256k1::new();
        let msg = hex!("ef2d5b9a7c61865a95941d0f04285420560df7e9d76890ac1b8867b12ce43167");
        let msg = Message::from_digest_slice(&msg).unwrap();
        let sk =
            SecretKey::from_str("848355d75fe1c354cf05539bb29b2015f1863065bcb6766b44d399ab95c3fa0b")
                .unwrap();
        let expected_sig = ecdsa::Signature::from_str("304302202ffc447100d518c8ba643d11f3e6a83a8640488e7d2537b1954b942408be6ea3021f26e1248dd1e52160c3a38af9769d91a1a806cab5f9d508c103464d3c02d6e1").unwrap();

        let sig = secp.sign_ecdsa_grind_r(&msg, &sk, 2);

        assert_eq!(expected_sig, sig);
    }

    #[cfg(feature = "serde")]
    #[cfg(not(secp256k1_fuzz))] // fixed sig vectors can't work with fuzz-sigs
    #[cfg(feature = "alloc")]
    #[test]
    fn test_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let s = Secp256k1::new();

        let msg = Message::from_digest_slice(&[1; 32]).unwrap();
        let sk = SecretKey::from_slice(&[2; 32]).unwrap();
        let sig = s.sign_ecdsa(&msg, &sk);
        static SIG_BYTES: [u8; 71] = [
            48, 69, 2, 33, 0, 157, 11, 173, 87, 103, 25, 211, 42, 231, 107, 237, 179, 76, 119, 72,
            102, 103, 60, 189, 227, 244, 225, 41, 81, 85, 92, 148, 8, 230, 206, 119, 75, 2, 32, 40,
            118, 231, 16, 47, 32, 79, 107, 254, 226, 108, 150, 124, 57, 38, 206, 112, 44, 249, 125,
            75, 1, 0, 98, 225, 147, 247, 99, 25, 15, 103, 118,
        ];
        static SIG_STR: &str = "\
            30450221009d0bad576719d32ae76bedb34c774866673cbde3f4e12951555c9408e6ce77\
            4b02202876e7102f204f6bfee26c967c3926ce702cf97d4b010062e193f763190f6776\
        ";

        assert_tokens(&sig.compact(), &[Token::BorrowedBytes(&SIG_BYTES[..])]);
        assert_tokens(&sig.compact(), &[Token::Bytes(&SIG_BYTES)]);
        assert_tokens(&sig.compact(), &[Token::ByteBuf(&SIG_BYTES)]);

        assert_tokens(&sig.readable(), &[Token::BorrowedStr(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::Str(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::String(SIG_STR)]);
    }
}
