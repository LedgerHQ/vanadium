use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::io::Read;
use bitcoin::VarInt;

use sdk::hash::{Hasher, Sha256};

use crate::bip388::KeyOrigin;
// re-export, as we use this both as a message and as an internal data type
pub use crate::message::WalletPolicyCoordinates;

pub use crate::bip388::{
    DescriptorTemplate, KeyInformation, KeyPlaceholder, TapTree, WalletPolicy,
};
use bitcoin::{params::Params, Address};

use crate::script::ToScript;

// TODO: maybe we can modify the serialize() methods to use bitcoin::io::Write instead

pub trait AccountCoordinates: Sized {
    fn serialize(&self) -> Vec<u8>;

    fn deserialize<R: Read + ?Sized>(bytes: &mut R) -> Result<Self, encode::Error>;
}

impl AccountCoordinates for WalletPolicyCoordinates {
    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(5);
        result.push(if self.is_change { 1 } else { 0 });
        result.extend_from_slice(&self.address_index.to_le_bytes());
        result
    }

    fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(WalletPolicyCoordinates {
            is_change: bool::consensus_decode(r)?,
            address_index: u32::consensus_decode(r)?,
        })
    }
}

const ACCOUNT_MAGIC: [u8; 14] = [
    13, b'N', b'A', b'M', b'E', b'D', b'_', b'A', b'C', b'C', b'O', b'U', b'N', b'T',
];

/// A generic trait for "accounts", parameterized by the type of coordinates.
///
/// Each implementer will define how to turn its coordinates into an address.
///
pub trait Account: Sized {
    type Coordinates: AccountCoordinates;

    /// Each implementation of Account should define a different version number
    const VERSION: u32;

    fn serialize(&self) -> Vec<u8>; // TODO: avoid Vec
    fn deserialize<R: Read + ?Sized>(bytes: &mut R) -> Result<Self, encode::Error>;

    fn get_address(&self, coords: &Self::Coordinates) -> Result<String, &'static str>;

    /// Returns a unique identifier for the named account.
    ///
    /// The identifier is the hash of:
    /// - the magic constant `ACCOUNT_MAGIC`
    /// - the version of the account
    /// - the length of the name, encoded as a bitcoin-style VarInt (if longer than 252 bytes)
    /// - the name itself
    /// - the serialization of the account.
    fn get_id(&self, name: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&ACCOUNT_MAGIC);
        hasher.update(&Self::VERSION.to_be_bytes());

        let mut name_len_bytes = Vec::with_capacity(1);
        VarInt(name.len() as u64)
            .consensus_encode(&mut name_len_bytes)
            .expect("Cannot fail");
        hasher.update(&name_len_bytes);

        hasher.update(name.as_bytes());

        hasher.update(&self.serialize());
        hasher.finalize().into()
    }
}

// Implement the generic trait for `WalletPolicy` with its corresponding coordinates.
impl Account for WalletPolicy {
    type Coordinates = WalletPolicyCoordinates;

    const VERSION: u32 = 1;

    fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        let len = VarInt(self.descriptor_template_raw().len() as u64);
        len.consensus_encode(&mut result).unwrap();
        result.extend_from_slice(self.descriptor_template_raw().as_bytes());

        // number of keys
        VarInt(self.key_information.len() as u64)
            .consensus_encode(&mut result)
            .unwrap();
        for key_info in &self.key_information {
            // serialize key information
            match &key_info.origin_info {
                None => {
                    result.push(0);
                }
                Some(k) => {
                    result.push(1);
                    result.extend_from_slice(&k.fingerprint.to_be_bytes());
                    result.push(k.derivation_path.len() as u8);
                    for step in k.derivation_path.iter() {
                        result.extend_from_slice(&u32::from(*step).to_le_bytes());
                    }
                }
            }
            // serialize pubkey
            result.extend_from_slice(&key_info.pubkey.encode());
        }

        result
    }

    fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        // Deserialize descriptor template.
        let VarInt(desc_len) = VarInt::consensus_decode(r)?;
        let mut desc_bytes = vec![0u8; desc_len as usize];
        r.read_exact(&mut desc_bytes)?;
        let descriptor_template_str = String::from_utf8(desc_bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid UTF-8 in descriptor"))?;

        // Deserialize key_information vector.
        let VarInt(key_count) = VarInt::consensus_decode(r)?;
        let mut key_information = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let mut flag = [0u8; 1];
            r.read_exact(&mut flag)?;
            let origin_info = match flag[0] {
                0 => None,
                1 => {
                    let mut fp_buf = [0; 4];
                    r.read_exact(&mut fp_buf)?;
                    let fingerprint = u32::from_be_bytes(fp_buf);
                    let mut len_buf = [0u8; 1];
                    r.read_exact(&mut len_buf)?;
                    let dp_len = len_buf[0] as usize;
                    let mut derivation_path = Vec::with_capacity(dp_len);
                    for _ in 0..dp_len {
                        let mut step_bytes = [0u8; 4];
                        r.read_exact(&mut step_bytes)?;
                        derivation_path.push(ChildNumber::from(u32::from_le_bytes(step_bytes)));
                    }
                    Some(KeyOrigin {
                        fingerprint,
                        derivation_path,
                    })
                }
                _ => {
                    return Err(encode::Error::ParseFailed("Invalid key information flag"));
                }
            };
            // Deserialize pubkey.
            let mut xpub_bytes = vec![0u8; 78];
            r.read_exact(&mut xpub_bytes)?;

            key_information.push(KeyInformation {
                origin_info,
                pubkey: Xpub::decode(&xpub_bytes)
                    .map_err(|_| encode::Error::ParseFailed("Invalid xpub"))?,
            });
        }
        Ok(
            WalletPolicy::new(&descriptor_template_str, key_information).map_err(|_| {
                encode::Error::ParseFailed("Invalid descriptor template or key information")
            })?,
        )
    }

    fn get_address(&self, coords: &WalletPolicyCoordinates) -> Result<String, &'static str> {
        let script = self
            .to_script(coords.is_change, coords.address_index)
            .map_err(|_| "Failed to derive script")?;
        Address::from_script(&script, Params::TESTNET4)
            .map(|address| address.to_string())
            .map_err(|_| "Failed to derive address")
    }
}

// TODO: add some tests
