use alloc::vec::Vec;
use bitcoin::consensus::{encode as enc, Decodable, Encodable};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::io::Cursor;
use minicbor::{Decode, Encode};

use super::GlobalHasProprietaryFields;

/// Proprietary key prefix for signing-policy entries in PSBT global maps.
///
/// The identifier is intentionally not Vanadium-specific so other implementations
/// can adopt the same format.
pub const PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER: [u8; 14] = *b"SIGNING_POLICY";

/// Subtype for a policy script entry (engine_id + version + length-prefixed script).
pub const PSBT_SIGNING_POLICY_GLOBAL_SCRIPT: u8 = 0x00;

/// Engine identifier for the built-in "signing program" language.
///
/// `0x00` is reserved (it was used by an abandoned Rhai-based prototype).
pub const ENGINE_ID_PROGRAM: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningPolicyError {
    InvalidValue,
    DuplicateHash,
    HashMismatch,
}

/// An owned signing program supplied during account registration.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(map)]
pub struct SigningPolicy {
    #[n(0)]
    pub engine_id: u8,
    #[n(1)]
    pub engine_version: u8,
    #[cbor(n(2), with = "minicbor::bytes")]
    pub script: Vec<u8>,
}

impl SigningPolicy {
    pub fn new(engine_id: u8, engine_version: u8, script: Vec<u8>) -> Self {
        Self {
            engine_id,
            engine_version,
            script,
        }
    }

    pub fn value_and_hash(&self) -> (Vec<u8>, [u8; 32]) {
        build_signing_policy_value(self.engine_id, self.engine_version, &self.script)
    }

    pub fn hash(&self) -> [u8; 32] {
        self.value_and_hash().1
    }

    pub fn as_entry(&self) -> SigningPolicyEntry<'_> {
        SigningPolicyEntry {
            hash: self.hash(),
            engine_id: self.engine_id,
            engine_version: self.engine_version,
            script: &self.script,
        }
    }
}

/// A parsed signing-policy entry from a PSBT global proprietary field.
///
/// The `hash` is the SHA-256 of the value bytes (`engine_id || engine_version ||
/// compact_size_len || script`) and must equal the chaincode of any xpub bound to
/// this policy.
#[derive(Debug, Clone, Copy)]
pub struct SigningPolicyEntry<'a> {
    pub hash: [u8; 32],
    pub engine_id: u8,
    pub engine_version: u8,
    pub script: &'a [u8],
}

impl<'a> SigningPolicyEntry<'a> {
    /// Parse the raw value bytes of a `PSBT_SIGNING_POLICY_GLOBAL_SCRIPT` entry.
    ///
    /// Returns the parsed entry; the caller is responsible for verifying that
    /// the entry's `hash` matches its proprietary subkey data.
    fn parse(value: &'a [u8]) -> Result<Self, SigningPolicyError> {
        if value.len() < 2 {
            return Err(SigningPolicyError::InvalidValue);
        }
        let engine_id = value[0];
        let engine_version = value[1];

        let mut cur = Cursor::new(&value[2..]);
        let len = enc::VarInt::consensus_decode(&mut cur)
            .map_err(|_| SigningPolicyError::InvalidValue)?
            .0;
        let pos = cur.position() as usize;
        let rest = &value[2 + pos..];
        let len = usize::try_from(len).map_err(|_| SigningPolicyError::InvalidValue)?;
        if rest.len() != len {
            return Err(SigningPolicyError::InvalidValue);
        }
        let hash: [u8; 32] = sha256::Hash::hash(value).to_byte_array();
        Ok(Self {
            hash,
            engine_id,
            engine_version,
            script: rest,
        })
    }
}

/// Serialize an `(engine_id, engine_version, script)` triple into the value bytes
/// of a `PSBT_SIGNING_POLICY_GLOBAL_SCRIPT` entry. Also returns the SHA-256 hash
/// that must be used both as the subkey data and as the chaincode of any bound xpub.
pub fn build_signing_policy_value(
    engine_id: u8,
    engine_version: u8,
    script: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut value = Vec::with_capacity(2 + 9 + script.len());
    value.push(engine_id);
    value.push(engine_version);
    enc::VarInt(script.len() as u64)
        .consensus_encode(&mut value)
        .expect("encoding to Vec cannot fail");
    value.extend_from_slice(script);
    let hash = sha256::Hash::hash(&value).to_byte_array();
    (value, hash)
}

/// Trait implemented by PSBT views that expose global proprietary fields, providing
/// read access to `SIGNING_POLICY` entries.
pub trait PsbtSigningPolicyGlobalRead: GlobalHasProprietaryFields {
    /// Collect all signing-policy entries from the PSBT global map.
    ///
    /// Returns an error if any entry is malformed, if its subkey data does not
    /// match the SHA-256 of its value bytes, or if multiple entries share the
    /// same hash.
    fn get_signing_policies(&self) -> Result<Vec<SigningPolicyEntry<'_>>, SigningPolicyError> {
        let mut entries: Vec<SigningPolicyEntry<'_>> = Vec::new();
        for entry in self.iter_proprietary() {
            if entry.prefix != PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER {
                continue;
            }
            if entry.subtype != PSBT_SIGNING_POLICY_GLOBAL_SCRIPT {
                continue;
            }
            if entry.key.len() != 32 {
                return Err(SigningPolicyError::InvalidValue);
            }
            let parsed = SigningPolicyEntry::parse(entry.value)?;
            let key_hash: [u8; 32] = entry.key.try_into().unwrap();
            if key_hash != parsed.hash {
                return Err(SigningPolicyError::HashMismatch);
            }
            if entries.iter().any(|e| e.hash == parsed.hash) {
                return Err(SigningPolicyError::DuplicateHash);
            }
            entries.push(parsed);
        }
        Ok(entries)
    }

    /// Look up a signing-policy entry by its 32-byte hash.
    fn get_signing_policy(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<SigningPolicyEntry<'_>>, SigningPolicyError> {
        for entry in self.iter_proprietary() {
            if entry.prefix != PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER {
                continue;
            }
            if entry.subtype != PSBT_SIGNING_POLICY_GLOBAL_SCRIPT {
                continue;
            }
            if entry.key.len() != 32 {
                return Err(SigningPolicyError::InvalidValue);
            }
            if entry.key != hash {
                continue;
            }
            let parsed = SigningPolicyEntry::parse(entry.value)?;
            if parsed.hash != *hash {
                return Err(SigningPolicyError::HashMismatch);
            }
            return Ok(Some(parsed));
        }
        Ok(None)
    }
}

impl<T: GlobalHasProprietaryFields> PsbtSigningPolicyGlobalRead for T {}

/// Helper to insert a signing-policy entry into a writable `bitcoin::psbt::Psbt`.
///
/// Intended for callers (clients, tests) constructing PSBTs with policy-bound
/// keys.
pub fn set_signing_policy(
    psbt: &mut bitcoin::psbt::Psbt,
    engine_id: u8,
    engine_version: u8,
    script: &[u8],
) -> [u8; 32] {
    let (value, hash) = build_signing_policy_value(engine_id, engine_version, script);
    let key = bitcoin::psbt::raw::ProprietaryKey {
        prefix: PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER.to_vec(),
        subtype: PSBT_SIGNING_POLICY_GLOBAL_SCRIPT,
        key: hash.to_vec(),
    };
    psbt.proprietary.insert(key, value);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let script = b"approve();";
        let (value, hash) = build_signing_policy_value(ENGINE_ID_PROGRAM, 0x00, script);
        let parsed = SigningPolicyEntry::parse(&value).unwrap();
        assert_eq!(parsed.hash, hash);
        assert_eq!(parsed.engine_id, ENGINE_ID_PROGRAM);
        assert_eq!(parsed.engine_version, 0x00);
        assert_eq!(parsed.script, script);
    }

    #[test]
    fn owned_policy_cbor_roundtrip_uses_canonical_hash() {
        let policy = SigningPolicy::new(ENGINE_ID_PROGRAM, 0x00, b"approve();".to_vec());
        let encoded = minicbor::to_vec(&policy).unwrap();
        let decoded: SigningPolicy = minicbor::decode(&encoded).unwrap();
        let (value, hash) =
            build_signing_policy_value(decoded.engine_id, decoded.engine_version, &decoded.script);

        assert_eq!(decoded, policy);
        assert_eq!(decoded.value_and_hash(), (value, hash));
        assert_eq!(decoded.as_entry().hash, hash);
    }

    #[test]
    fn parse_rejects_short_value() {
        assert!(SigningPolicyEntry::parse(&[]).is_err());
        assert!(SigningPolicyEntry::parse(&[0x00]).is_err());
    }

    #[test]
    fn parse_rejects_length_mismatch() {
        // engine_id=1, version=0, len=10, but only 2 script bytes follow
        let bad = [0x01, 0x00, 0x0a, b'A', b'B'];
        assert!(SigningPolicyEntry::parse(&bad).is_err());
    }

    #[test]
    fn parse_handles_empty_script() {
        let (value, _) = build_signing_policy_value(ENGINE_ID_PROGRAM, 0x00, &[]);
        let parsed = SigningPolicyEntry::parse(&value).unwrap();
        assert_eq!(parsed.script, b"");
    }
}
