//! Wire protocol between the Bitcoin V-App and its client.
//!
//! The encoding is CBOR via [`minicbor`]. Two properties matter for
//! cross-version compatibility:
//!
//! * Every struct and every field-bearing enum variant is encoded as a
//!   CBOR map keyed by stable integer indices. Unknown keys are skipped
//!   on decode, so adding a new optional field to an existing message is
//!   forward-compatible: an older peer simply ignores it.
//!
//! * Every enum variant carries a stable integer index. Adding a new
//!   variant is *not* a silent compatibility change — an older peer
//!   that receives an unknown variant fails to decode. That is the
//!   intended behaviour: a request the peer cannot handle should be
//!   rejected cleanly, not silently coerced to something else.
//!
//! Rules for evolving this module:
//!
//! 1. Never reuse a field or variant index.
//! 2. Never change the *type* of an existing field; introduce a new
//!    field at a fresh index instead.
//! 3. New fields added to existing variants must be `Option<_>` (or
//!    otherwise carry a sensible default) so that older encoders can
//!    omit them.

use alloc::{string::String, vec::Vec};
use minicbor::{Decode, Encode};

mod bip388_codec;

/// BIP32 derivation path. Encoded transparently as a CBOR array of `u32`s.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(transparent)]
pub struct Bip32Path(#[n(0)] pub Vec<u32>);

/// Selects which BIP-32 derivation tree a key request refers to.
///
/// `Standard` is the tree rooted at the device seed; `Resident` is the
/// per-app tree rooted at the resident master key generated from the
/// resident seed stored on-device.
#[derive(Encode, Decode, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cbor(index_only)]
pub enum KeyTree {
    #[default]
    #[n(0)]
    Standard,
    #[n(1)]
    Resident,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct WalletPolicyCoordinates {
    #[n(0)]
    pub is_change: bool,
    #[n(1)]
    pub address_index: u32,
}

impl WalletPolicyCoordinates {
    pub fn new(is_change: bool, address_index: u32) -> Self {
        Self {
            is_change,
            address_index,
        }
    }
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum Account {
    #[n(0)]
    WalletPolicy(#[cbor(n(0), with = "bip388_codec")] crate::bip388::WalletPolicy),
    // more will be added here
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum AccountCoordinates {
    #[n(0)]
    WalletPolicy(#[n(0)] WalletPolicyCoordinates),
    // more will be added here
}

/// A Schnorr signature for object authentication, containing the compressed public key of the
/// identity key that produced the signature, and the 64-byte BIP-340 signature.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct IdentitySignature {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub identity_pubkey: Vec<u8>,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub signature: Vec<u8>,
}

/// An identity key registration entry used to authenticate cosigner xpubs during
/// account registration.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct RegisteredIdentityEntry {
    /// 33-byte compressed secp256k1 public key of the identity key.
    #[cbor(n(0), with = "minicbor::bytes")]
    pub pubkey: Vec<u8>,
    #[n(1)]
    pub name: String,
    /// 32-byte proof-of-registration HMAC for this identity key.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub por: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum Request {
    #[n(0)]
    GetVersion,

    #[n(1)]
    Exit,

    #[n(2)]
    #[cbor(map)]
    GetMasterFingerprint {
        #[n(0)]
        tree: KeyTree,
    },

    #[n(3)]
    #[cbor(map)]
    GetExtendedPubkey {
        #[n(0)]
        tree: KeyTree,
        #[n(1)]
        display: bool,
        #[n(2)]
        path: Bip32Path,
        /// If set, the response will include a Schnorr signature over the xpub
        /// using the identity key at this index. Only valid with `KeyTree::Standard`.
        #[n(3)]
        identity_index: Option<u32>,
    },

    #[n(4)]
    #[cbor(map)]
    RegisterAccount {
        #[n(0)]
        name: String,
        #[n(1)]
        account: Account,
        /// Optional list of registered identity keys (with their proofs of registration)
        /// used to authenticate cosigner xpubs.
        #[n(2)]
        registered_identities: Option<Vec<RegisteredIdentityEntry>>,
        /// Optional per-key Schnorr signatures over the cosigner xpubs.
        /// `key_signatures[i]` covers `keys_info[i]`; `None` means unsigned.
        #[n(3)]
        key_signatures: Option<Vec<Option<IdentitySignature>>>,
        /// If true and the descriptor template's confusion score is at most
        /// `MAX_CONFUSION_SCORE`, show a human-readable cleartext description
        /// of the descriptor template on screen.
        #[n(4)]
        show_cleartext: bool,
    },

    #[n(5)]
    #[cbor(map)]
    GetAddress {
        #[n(0)]
        display: bool,
        #[n(1)]
        name: Option<String>,
        #[n(2)]
        account: Account,
        #[cbor(n(3), with = "minicbor::bytes")]
        por: Vec<u8>,
        #[n(4)]
        coordinates: AccountCoordinates,
        /// If set, the response will include a Schnorr signature over the output
        /// script using the identity key at this index.
        #[n(5)]
        identity_index: Option<u32>,
    },

    #[n(6)]
    #[cbor(map)]
    SignPsbt {
        #[cbor(n(0), with = "minicbor::bytes")]
        psbt: Vec<u8>,
    },

    #[n(7)]
    #[cbor(map)]
    RegisterIdentityKey {
        #[n(0)]
        name: String,
        #[cbor(n(1), with = "minicbor::bytes")]
        pubkey: Vec<u8>,
    },
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct PartialSignature {
    #[n(0)]
    pub input_index: u32,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub signature: Vec<u8>,
    #[cbor(n(2), with = "minicbor::bytes")]
    pub pubkey: Vec<u8>,
    #[cbor(n(3), with = "minicbor::bytes")]
    pub leaf_hash: Option<Vec<u8>>,
}

/// Round-1 MuSig2 pubnonce output for a single `(input, key expression)` pair
/// of a `musig(...)` placeholder. Mirrors the on-device representation in
/// [`crate::musig::PubNonce`] but adds the contextual fields the host needs to
/// populate BIP-373 PSBT entries.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct MuSig2Pubnonce {
    #[n(0)]
    pub input_index: u32,
    /// 66-byte BIP-327 public nonce (`R_s1 || R_s2`).
    #[cbor(n(1), with = "minicbor::bytes")]
    pub pubnonce: [u8; 66],
    /// 33-byte SEC1 compressed pubkey of *this* participant (the device).
    #[cbor(n(2), with = "minicbor::bytes")]
    pub participant_pk: [u8; 33],
    /// 33-byte SEC1 compressed aggregate pubkey *after* all tweaks
    /// (BIP-32 derivations + optional BIP-341 taptweak for keypath spend).
    #[cbor(n(3), with = "minicbor::bytes")]
    pub aggregate_pubkey: [u8; 33],
    /// `Some(hash)` for script-path spends, `None` for key-path spends.
    #[cbor(n(4), with = "minicbor::bytes")]
    pub leaf_hash: Option<[u8; 32]>,
}

/// Round-2 MuSig2 partial signature output for a single `(input, key expression)`
/// pair. The host aggregates all participants' partial signatures into the
/// final 64-byte Schnorr signature.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct MuSig2PartialSignature {
    #[n(0)]
    pub input_index: u32,
    /// 32-byte BIP-327 partial signature.
    #[cbor(n(1), with = "minicbor::bytes")]
    pub signature: [u8; 32],
    #[cbor(n(2), with = "minicbor::bytes")]
    pub participant_pk: [u8; 33],
    #[cbor(n(3), with = "minicbor::bytes")]
    pub aggregate_pubkey: [u8; 33],
    #[cbor(n(4), with = "minicbor::bytes")]
    pub leaf_hash: Option<[u8; 32]>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum Response {
    #[n(0)]
    #[cbor(map)]
    Version {
        #[n(0)]
        version: String,
    },

    #[n(1)]
    #[cbor(map)]
    MasterFingerprint {
        #[n(0)]
        fingerprint: u32,
    },

    #[n(2)]
    #[cbor(map)]
    ExtendedPubkey {
        #[cbor(n(0), with = "minicbor::bytes")]
        xpub: Vec<u8>,
        #[n(1)]
        identity_sig: Option<IdentitySignature>,
    },

    #[n(3)]
    #[cbor(map)]
    AccountRegistered {
        #[cbor(n(0), with = "minicbor::bytes")]
        account_id: [u8; 32],
        #[cbor(n(1), with = "minicbor::bytes")]
        hmac: [u8; 32],
    },

    #[n(4)]
    #[cbor(map)]
    Address {
        #[n(0)]
        address: String,
        #[n(1)]
        identity_sig: Option<IdentitySignature>,
    },

    #[n(5)]
    #[cbor(map)]
    PsbtSigned {
        /// ECDSA / Schnorr partial signatures for plain key placeholders.
        #[n(0)]
        signatures: Vec<PartialSignature>,
        /// Round-1 MuSig2 pubnonces produced for `musig(...)` placeholders
        /// whose corresponding PSBT input *did not* already carry pubnonces.
        /// Empty when the PSBT involves no musig participants for which the
        /// device is round-1 capable, or when this is a round-2 call.
        #[n(1)]
        musig_pubnonces: Vec<MuSig2Pubnonce>,
        /// Round-2 MuSig2 partial signatures produced for `musig(...)`
        /// placeholders whose PSBT input carries this device's pubnonce
        /// (i.e. the cosigners have completed round 1 and merged the
        /// pubnonces back into the PSBT).
        #[n(2)]
        musig_partial_sigs: Vec<MuSig2PartialSignature>,
    },

    #[n(6)]
    #[cbor(map)]
    IdentityKeyRegistered {
        #[cbor(n(0), with = "minicbor::bytes")]
        key_id: [u8; 32],
        #[cbor(n(1), with = "minicbor::bytes")]
        hmac: [u8; 32],
    },

    #[n(7)]
    #[cbor(map)]
    Error {
        #[n(0)]
        error: crate::errors::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CBOR round-trip for `MuSig2Pubnonce`.
    #[test]
    fn musig2_pubnonce_roundtrip() {
        let pn = MuSig2Pubnonce {
            input_index: 7,
            pubnonce: [0x11; 66],
            participant_pk: [0x22; 33],
            aggregate_pubkey: [0x33; 33],
            leaf_hash: Some([0x44; 32]),
        };
        let bytes = minicbor::to_vec(&pn).unwrap();
        let decoded: MuSig2Pubnonce = minicbor::decode(&bytes).unwrap();
        assert_eq!(pn, decoded);

        let pn_no_leaf = MuSig2Pubnonce {
            input_index: 0,
            pubnonce: [0u8; 66],
            participant_pk: [0u8; 33],
            aggregate_pubkey: [0u8; 33],
            leaf_hash: None,
        };
        let bytes = minicbor::to_vec(&pn_no_leaf).unwrap();
        let decoded: MuSig2Pubnonce = minicbor::decode(&bytes).unwrap();
        assert_eq!(pn_no_leaf, decoded);
    }

    /// CBOR round-trip for `MuSig2PartialSignature`.
    #[test]
    fn musig2_partial_sig_roundtrip() {
        let ps = MuSig2PartialSignature {
            input_index: 3,
            signature: [0x55; 32],
            participant_pk: [0x22; 33],
            aggregate_pubkey: [0x33; 33],
            leaf_hash: None,
        };
        let bytes = minicbor::to_vec(&ps).unwrap();
        let decoded: MuSig2PartialSignature = minicbor::decode(&bytes).unwrap();
        assert_eq!(ps, decoded);
    }

    /// CBOR round-trip for the extended `Response::PsbtSigned`, including the
    /// two new fields.
    #[test]
    fn response_psbt_signed_roundtrip_with_musig() {
        let resp = Response::PsbtSigned {
            signatures: vec![PartialSignature {
                input_index: 0,
                signature: vec![1, 2, 3, 4],
                pubkey: vec![5, 6, 7],
                leaf_hash: None,
            }],
            musig_pubnonces: vec![MuSig2Pubnonce {
                input_index: 0,
                pubnonce: [0xAB; 66],
                participant_pk: [0xCD; 33],
                aggregate_pubkey: [0xEF; 33],
                leaf_hash: Some([0x12; 32]),
            }],
            musig_partial_sigs: vec![MuSig2PartialSignature {
                input_index: 0,
                signature: [0x99; 32],
                participant_pk: [0xCD; 33],
                aggregate_pubkey: [0xEF; 33],
                leaf_hash: Some([0x12; 32]),
            }],
        };
        let bytes = minicbor::to_vec(&resp).unwrap();
        let decoded: Response = minicbor::decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    /// `Response::PsbtSigned` with empty musig fields (the common case for
    /// PSBTs that don't involve any `musig(...)` placeholder) round-trips
    /// identically.
    #[test]
    fn response_psbt_signed_roundtrip_empty_musig() {
        let resp = Response::PsbtSigned {
            signatures: vec![],
            musig_pubnonces: vec![],
            musig_partial_sigs: vec![],
        };
        let bytes = minicbor::to_vec(&resp).unwrap();
        let decoded: Response = minicbor::decode(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }
}
