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
pub struct KeyOrigin {
    #[n(0)]
    pub fingerprint: u32,
    #[n(1)]
    pub path: Bip32Path,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct PubkeyInfo {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub pubkey: Vec<u8>,
    #[n(1)]
    pub origin: Option<KeyOrigin>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct WalletPolicy {
    #[n(0)]
    pub template: String,
    #[n(1)]
    pub keys_info: Vec<PubkeyInfo>,
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
    WalletPolicy(#[n(0)] WalletPolicy),
    // more will be added here
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum AccountCoordinates {
    #[n(0)]
    WalletPolicy(#[n(0)] WalletPolicyCoordinates),
    // more will be added here
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct NamedAccount {
    #[n(0)]
    name: String,
    #[n(1)]
    descriptor: WalletPolicy,
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
        #[n(0)]
        signatures: Vec<PartialSignature>,
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

// Conversions between messages and other internal types

impl TryFrom<&Account> for crate::bip388::WalletPolicy {
    type Error = crate::errors::Error;
    fn try_from(acc: &Account) -> Result<Self, Self::Error> {
        match acc {
            Account::WalletPolicy(wallet_policy) => {
                let keys = wallet_policy
                    .keys_info
                    .iter()
                    .map(|info| {
                        let pubkey = bitcoin::bip32::Xpub::decode(&info.pubkey)
                            .map_err(|_| crate::errors::Error::InvalidKey)?;
                        let origin_info =
                            info.origin.as_ref().map(|origin| crate::bip388::KeyOrigin {
                                fingerprint: origin.fingerprint,
                                derivation_path: origin
                                    .path
                                    .0
                                    .iter()
                                    .copied()
                                    .map(Into::into)
                                    .collect(),
                            });
                        Ok(crate::bip388::KeyInformation {
                            pubkey,
                            origin_info,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                crate::bip388::WalletPolicy::new(&wallet_policy.template, keys)
                    .map_err(|_| crate::errors::Error::InvalidKey)
            }
            #[allow(unreachable_patterns)] // more patterns will be allowed in the future
            _ => Err(crate::errors::Error::InvalidKey),
        }
    }
}
