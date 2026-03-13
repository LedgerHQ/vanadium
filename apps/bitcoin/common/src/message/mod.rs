use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

// BIP32 path as a reusable type
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Bip32Path(pub Vec<u32>);

// Key origin information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub path: Bip32Path,
}

// Public key information for wallet policies
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PubkeyInfo {
    pub pubkey: Vec<u8>,
    pub origin: Option<KeyOrigin>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    pub template: String,
    pub keys_info: Vec<PubkeyInfo>,
}

// Coordinates for an address within a wallet
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicyCoordinates {
    pub is_change: bool,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Account {
    WalletPolicy(WalletPolicy),
    // more will be added here
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum AccountCoordinates {
    WalletPolicy(WalletPolicyCoordinates),
    // more will be added here
}

// Core account definition
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NamedAccount {
    name: String,
    descriptor: WalletPolicy,
}

/// A Schnorr signature for object authentication, containing the compressed public key of the
/// identity key that produced the signature, and the 64-byte BIP-340 signature.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct IdentitySignature {
    pub identity_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// An identity key registration entry used to authenticate cosigner xpubs during
/// account registration.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RegisteredIdentityEntry {
    /// 33-byte compressed secp256k1 public key of the identity key.
    pub pubkey: Vec<u8>,
    pub name: String,
    /// 32-byte proof-of-registration HMAC for this identity key.
    pub por: Vec<u8>,
}

// Request types
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetVersion,
    Exit,
    GetMasterFingerprint,
    GetExtendedPubkey {
        display: bool,
        path: Bip32Path,
        /// If set, the response will include a Schnorr signature over the xpub
        /// using the identity key at this index.
        identity_index: Option<u32>,
    },
    RegisterAccount {
        name: String,
        account: Account,
        /// Optional list of registered identity keys (with their proofs of registration)
        /// used to authenticate cosigner xpubs.
        registered_identities: Option<Vec<RegisteredIdentityEntry>>,
        /// Optional per-key Schnorr signatures over the cosigner xpubs.
        /// `key_signatures[i]` covers `keys_info[i]`; `None` means unsigned.
        key_signatures: Option<Vec<Option<IdentitySignature>>>,
        /// If true and the descriptor template's complexity score is at most
        /// `MAX_CONFUSION_SCORE`, show a human-readable cleartext description
        /// of the descriptor template on screen.
        show_cleartext: bool,
    },
    GetAddress {
        display: bool,
        name: Option<String>,
        account: Account,
        por: Vec<u8>,
        coordinates: AccountCoordinates,
        /// If set, the response will include a Schnorr signature over the output
        /// script using the identity key at this index.
        identity_index: Option<u32>,
    },
    SignPsbt {
        psbt: Vec<u8>,
    },
    GetResidentPubkey {
        display: bool,
        index: u16,
    },
    RegisterIdentityKey {
        name: String,
        pubkey: Vec<u8>,
    },
}

// Partial signature for PSBT signing
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PartialSignature {
    pub input_index: u32,
    pub signature: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub leaf_hash: Option<Vec<u8>>, // Explicitly optional
}

// Response types
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Version(String),
    MasterFingerprint(u32),
    ExtendedPubkey {
        xpub: Vec<u8>,
        identity_sig: Option<IdentitySignature>,
    },
    AccountRegistered {
        account_id: [u8; 32],
        hmac: [u8; 32],
    },
    Address {
        address: String,
        identity_sig: Option<IdentitySignature>,
    },
    PsbtSigned(Vec<PartialSignature>),
    ResidentPubkey(Vec<u8>),
    IdentityKeyRegistered {
        key_id: [u8; 32],
        hmac: [u8; 32],
    },
    Error(crate::errors::Error),
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
