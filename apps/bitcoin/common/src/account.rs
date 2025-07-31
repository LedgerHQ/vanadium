use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::io::Read;
use bitcoin::VarInt;

use sdk::hash::{Hasher, Sha256};

// re-export, as we use this both as a message and as an internal data type
pub use crate::message::WalletPolicyCoordinates;

pub use crate::bip388::{
    DescriptorTemplate, KeyInformation, KeyPlaceholder, TapTree, WalletPolicy,
};
use bitcoin::{params::Params, Address};

use crate::script::ToScript;
use subtle::ConstantTimeEq;

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

    fn get_address(&self, coords: &WalletPolicyCoordinates) -> Result<String, &'static str> {
        let script = self
            .to_script(coords.is_change, coords.address_index)
            .map_err(|_| "Failed to derive script")?;
        Address::from_script(&script, Params::TESTNET4)
            .map(|address| address.to_string())
            .map_err(|_| "Failed to derive address")
    }
}

// m/POR_MAGIC computed with SLIP21 is the hmac key for Proofs of Registration.
const POR_MAGIC: &[u8] = b"Proof of Registration";

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct ProofOfRegistration([u8; 32]);

impl PartialEq for ProofOfRegistration {
    /// Uses constant-time comparison to prevent timing attacks.
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}
impl Eq for ProofOfRegistration {}

impl ProofOfRegistration {
    // TODO: This function should really only be available if compiling inside a Vanadium V-App,
    //       regardless if natively or for the riscv targets.
    //       How to gate this properly?
    pub fn new(id: &[u8; 32]) -> Self {
        let por_key = sdk::slip21::derive_slip21_key(&[&POR_MAGIC]);

        let mut mac = HmacEngine::<bitcoin::hashes::sha256::Hash>::new(&por_key);
        mac.input(id);
        Self(Hmac::<bitcoin::hashes::sha256::Hash>::from_engine(mac).to_byte_array())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes of the proof of registration.
    ///
    /// This is necessary for example to serialize and return the proof externally. However,
    /// it is generally dangerous to use the serialized form of proofs of registrations, as
    /// incorrect use might lead to side-channel attacks.
    ///
    /// In order to verify the proof, build a new instance using the `from_bytes` method
    /// before comparing it with the expected proof.
    pub fn dangerous_as_bytes(&self) -> [u8; 32] {
        self.0
    }
}
