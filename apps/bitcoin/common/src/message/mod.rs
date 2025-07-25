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

// Request types
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetVersion,
    Exit,
    GetMasterFingerprint,
    GetExtendedPubkey {
        display: bool,
        path: Bip32Path,
    },
    RegisterAccount {
        name: String,
        account: Account,
    },
    GetAddress {
        display: bool,
        name: Option<String>,
        account: Account,
        hmac: Vec<u8>,
        coordinates: AccountCoordinates,
    },
    SignPsbt {
        psbt: Vec<u8>,
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
    ExtendedPubkey(Vec<u8>),
    AccountRegistered {
        account_id: [u8; 32],
        hmac: [u8; 32],
    },
    Address(String),
    PsbtSigned(Vec<PartialSignature>),
    Error(String),
}

// Conversions between messages and other internal types

impl TryFrom<&Account> for crate::bip388::WalletPolicy {
    type Error = &'static str;
    fn try_from(acc: &Account) -> Result<Self, Self::Error> {
        match acc {
            Account::WalletPolicy(wallet_policy) => {
                let keys = wallet_policy
                    .keys_info
                    .iter()
                    .map(|info| {
                        let pubkey = bitcoin::bip32::Xpub::decode(&info.pubkey)
                            .map_err(|_| "Failed to decode pubkey")?;
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
            }
            #[allow(unreachable_patterns)] // more patterns will be allowed in the future
            _ => Err("Unsupported account variant"),
        }
    }
}
