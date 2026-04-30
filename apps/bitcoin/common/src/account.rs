use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::io::Read;
use bitcoin::VarInt;
use sdk::hash::{Hasher, Sha256};

// re-export, as we use this both as a message and as an internal data type
pub use crate::message::WalletPolicyCoordinates;

pub use crate::bip388::{
    DescriptorTemplate, KeyExpression, KeyExpressionType, KeyInformation, KeyPlaceholder, TapTree,
    WalletPolicy,
};
use crate::por::{Registerable, RegistrationId};
use bitcoin::{params::Params, Address};

use crate::errors::Error;
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
pub(crate) const ACCOUNT_MAGIC: [u8; 14] = *b"\x0DNAMED_ACCOUNT";

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

    fn get_address(&self, coords: &Self::Coordinates) -> Result<String, Error>;

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
        let mut res = Vec::new();
        res.extend_from_slice(&Self::VERSION.to_le_bytes());
        res.extend(WalletPolicy::serialize(self));
        res
    }

    fn deserialize<R: Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let version = u32::consensus_decode(r)?;
        if version != Self::VERSION {
            return Err(encode::Error::ParseFailed("Unsupported version"));
        }
        WalletPolicy::deserialize(r)
    }

    fn get_address(&self, coords: &WalletPolicyCoordinates) -> Result<String, Error> {
        let script = self.to_script(coords.is_change, coords.address_index)?;
        Address::from_script(&script, Params::TESTNET4)
            .map(|address| address.to_string())
            .map_err(|_| Error::AddressFromScriptFailed)
    }
}

impl<T: Account> Registerable for T {
    type Context = str;

    fn registration_id(&self, name: &str) -> RegistrationId<Self> {
        RegistrationId::<T>::from_bytes(self.get_id(name))
    }
}
