#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
// Experimental features we need.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(bench, feature(test))]
// Coding conventions.
// #![warn(missing_docs)]
// Instead of littering the codebase for non-fuzzing code just globally allow.
#![cfg_attr(fuzzing, allow(dead_code, unused_imports))]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::needless_borrows_for_generic_args)] // https://github.com/rust-lang/rust-clippy/issues/12454
// For 0.32.x releases only.
#![allow(deprecated)]

// // Disable 16-bit support at least for now as we can't guarantee it yet.
// #[cfg(target_pointer_width = "16")]
// compile_error!(
//     "rust-bitcoin currently only supports architectures with pointers wider than 16 bits, let us
//     know if you want 16-bit support. Note that we do NOT guarantee that we will implement it!"
// );

// #[cfg(bench)]
// extern crate test;

#[cfg(feature = "std")]
compile_error!("The `std` feature is not supported.");

#[cfg(feature = "rand-std")]
compile_error!("The `rand-std` feature is not supported.");

#[macro_use]
extern crate alloc;

#[cfg(feature = "base64")]
/// Encodes and decodes base64 as bytes or utf8.
pub extern crate base64;

/// Bitcoin base58 encoding and decoding.
pub extern crate base58;

/// Re-export the `bech32` crate.
pub extern crate bech32;

/// Rust implementation of cryptographic hash function algorithms.
pub extern crate hashes;

/// Re-export the `hex-conservative` crate.
pub extern crate hex;

/// Re-export the `bitcoin-io` crate.
pub extern crate io;

/// Re-export the `ordered` crate.
#[cfg(feature = "ordered")]
pub extern crate ordered;

/// Rust wrapper library for Pieter Wuille's libsecp256k1.  Implements ECDSA and BIP 340 signatures
/// for the SECG elliptic curve group secp256k1 and related utilities.
// pub extern crate secp256k1 as secp256k1;

// We do not re-export vlib-secp256k1, as it is only a partial implementation of the rust-secp256k1
// and it should only be used in vlib-bitcoin at this time.
// However, we need to at least export a few types that are part of the public API of vlib-bitcoin.
pub mod secp256k1 {
    pub use secp256k1::{ecdsa, schnorr, Message, PublicKey, Secp256k1, XOnlyPublicKey};
}

#[cfg(feature = "serde")]
#[macro_use]
extern crate actual_serde as serde;

#[cfg(test)]
#[macro_use]
mod test_macros;
mod internal_macros;
#[cfg(feature = "serde")]
mod serde_utils;

// #[macro_use]
pub mod address;
pub mod bip152;
pub mod bip158;
pub mod bip32;
pub mod blockdata;
pub mod consensus;
pub mod p2p;
// Private until we either make this a crate or flatten it - still to be decided.
pub(crate) mod crypto;
pub mod error;
pub mod hash_types;
pub mod merkle_tree;
pub mod network;
pub mod policy;
pub mod pow;
pub mod psbt;
// pub mod sign_message;
pub mod taproot;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::{
    address::{Address, AddressType, KnownHrp},
    amount::{Amount, Denomination, SignedAmount},
    bip158::{FilterHash, FilterHeader},
    bip32::XKeyIdentifier,
    blockdata::block::{self, Block, BlockHash, TxMerkleNode, WitnessMerkleNode, WitnessCommitment},
    blockdata::constants,
    blockdata::fee_rate::FeeRate,
    blockdata::locktime::{self, absolute, relative},
    blockdata::opcodes::{self, Opcode},
    blockdata::script::witness_program::{self, WitnessProgram},
    blockdata::script::witness_version::{self, WitnessVersion},
    blockdata::script::{self, Script, ScriptBuf, ScriptHash, WScriptHash},
    blockdata::transaction::{self, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Wtxid},
    blockdata::weight::Weight,
    blockdata::witness::{self, Witness},
    consensus::encode::VarInt,
    consensus::params,
    crypto::ecdsa,
    crypto::key::{self, PrivateKey, PubkeyHash, PublicKey, CompressedPublicKey, WPubkeyHash, XOnlyPublicKey},
    crypto::sighash::{self, LegacySighash, SegwitV0Sighash, TapSighash, TapSighashTag},
    merkle_tree::MerkleBlock,
    network::{Network, NetworkKind},
    pow::{CompactTarget, Target, Work},
    psbt::Psbt,
    sighash::{EcdsaSighashType, TapSighashType},
    taproot::{TapBranchTag, TapLeafHash, TapLeafTag, TapNodeHash, TapTweakHash, TapTweakTag},
};

#[rustfmt::skip]
#[allow(unused_imports)]
mod prelude {
    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, slice, rc};

    // #[cfg(all(not(feature = "std"), not(test), any(not(rust_v_1_60), target_has_atomic = "ptr")))]
    // pub use alloc::sync;

    #[cfg(any(feature = "std", test))]
    pub use std::{string::{String, ToString}, vec::Vec, boxed::Box, borrow::{Borrow, BorrowMut, Cow, ToOwned}, rc, sync};

    #[cfg(all(not(feature = "std"), not(test)))]
    pub use alloc::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    #[cfg(any(feature = "std", test))]
    pub use std::collections::{BTreeMap, BTreeSet, btree_map, BinaryHeap};

    pub use crate::io::sink;

    pub use hex::DisplayHex;
}

pub mod amount {
    //! Bitcoin amounts.
    //!
    //! This module mainly introduces the [Amount] and [SignedAmount] types.
    //! We refer to the documentation on the types for more information.

    use crate::consensus::{encode, Decodable, Encodable};
    use crate::io::{Read, Write};

    #[rustfmt::skip]            // Keep public re-exports separate.
    #[doc(inline)]
    pub use units::amount::{
        Amount, CheckedSum, Denomination, Display, ParseAmountError, SignedAmount,
    };
    #[cfg(feature = "serde")]
    pub use units::amount::serde;

    impl Decodable for Amount {
        #[inline]
        fn consensus_decode<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
            Ok(Amount::from_sat(Decodable::consensus_decode(r)?))
        }
    }

    impl Encodable for Amount {
        #[inline]
        fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
            self.to_sat().consensus_encode(w)
        }
    }
}

/// Unit parsing utilities.
pub mod parse {
    /// Re-export everything from the [`units::parse`] module.
    pub use units::parse::ParseIntError;
}
