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
/// compact_size_len || script`). A key is bound to this policy by deriving it along
/// the signing-policy path built from `hash` (see [`signing_policy_key_path`]).
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
/// that is used as the subkey data and to derive the signing-policy binding path.
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

/// BIP-32 hardened bit.
const HARDENED_BIT: u32 = 0x8000_0000;

/// First (hardened) derivation index for a signing-policy-bound key: the ASCII
/// bytes `"PLCY"` read as a big-endian `u32` (`0x504C4359 = 1347175257`).
pub const SIGNING_POLICY_PURPOSE: u32 = 0x504C_4359;

/// Derive the four non-hardened 31-bit path chunks that bind a key to the policy
/// with the given SHA-256 `hash`.
///
/// Each chunk is the big-endian `u32` of four consecutive hash bytes with the top
/// bit cleared, so `chunk[i]` is a valid non-hardened BIP-32 child number. This is
/// a 124-bit binding taken from the first 16 bytes of the hash. It must be computed
/// identically on the device and the client.
pub fn signing_policy_chunks(hash: &[u8; 32]) -> [u32; 4] {
    let mut chunks = [0u32; 4];
    for (i, chunk) in chunks.iter_mut().enumerate() {
        let word = u32::from_be_bytes([
            hash[4 * i],
            hash[4 * i + 1],
            hash[4 * i + 2],
            hash[4 * i + 3],
        ]);
        *chunk = word & !HARDENED_BIT;
    }
    chunks
}

/// Build the full BIP-32 key-origin path for a signing-policy-bound key:
/// `m / PLCY' / coin_type' / account' / chunk0 / chunk1 / chunk2 / chunk3`,
/// where the chunks come from [`signing_policy_chunks`].
///
/// `coin_type` and `account` are the (non-hardened) BIP-44-style coin-type and
/// account indices; both are hardened here.
pub fn signing_policy_key_path(coin_type: u32, account: u32, hash: &[u8; 32]) -> [u32; 7] {
    let chunks = signing_policy_chunks(hash);
    [
        SIGNING_POLICY_PURPOSE | HARDENED_BIT,
        coin_type | HARDENED_BIT,
        account | HARDENED_BIT,
        chunks[0],
        chunks[1],
        chunks[2],
        chunks[3],
    ]
}

/// Recognize a signing-policy key-origin path.
///
/// Returns `Some((coin_type, account, chunks))` iff `path` has the exact shape
/// produced by [`signing_policy_key_path`]: length 7, `PLCY'` / hardened
/// coin-type / hardened account, followed by four non-hardened chunks.
/// `coin_type` and `account` are returned unhardened.
pub fn parse_signing_policy_path(path: &[u32]) -> Option<(u32, u32, [u32; 4])> {
    if path.len() != 7 {
        return None;
    }
    if path[0] != (SIGNING_POLICY_PURPOSE | HARDENED_BIT) {
        return None;
    }
    if path[1] & HARDENED_BIT == 0 {
        return None;
    }
    if path[2] & HARDENED_BIT == 0 {
        return None;
    }
    let chunks = [path[3], path[4], path[5], path[6]];
    if chunks.iter().any(|&c| c & HARDENED_BIT != 0) {
        return None;
    }
    Some((
        path[1] & !HARDENED_BIT,
        path[2] & !HARDENED_BIT,
        chunks,
    ))
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

    /// Collect `(signing_policy_chunks(hash), hash)` for every policy present in
    /// the PSBT, for matching against key-origin paths (see
    /// [`parse_signing_policy_path`]).
    fn signing_policy_chunk_bindings(
        &self,
    ) -> Result<Vec<([u32; 4], [u8; 32])>, SigningPolicyError> {
        Ok(self
            .get_signing_policies()?
            .iter()
            .map(|entry| (signing_policy_chunks(&entry.hash), entry.hash))
            .collect())
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

    #[test]
    fn purpose_constant_is_plcy_ascii() {
        assert_eq!(SIGNING_POLICY_PURPOSE, u32::from_be_bytes(*b"PLCY"));
        assert_eq!(SIGNING_POLICY_PURPOSE, 1347175257);
    }

    #[test]
    fn chunks_are_non_hardened_and_use_first_16_bytes() {
        let mut hash = [0u8; 32];
        for (i, b) in hash.iter_mut().enumerate() {
            *b = i as u8;
        }
        let chunks = signing_policy_chunks(&hash);
        // top bit cleared -> all valid non-hardened child numbers
        for c in chunks {
            assert_eq!(c & 0x8000_0000, 0);
        }
        // first word: bytes 00 01 02 03 -> 0x00010203 (top bit already 0)
        assert_eq!(chunks[0], 0x0001_0203);
        // fourth word: bytes 0c 0d 0e 0f -> 0x0c0d0e0f
        assert_eq!(chunks[3], 0x0C0D_0E0F);
    }

    #[test]
    fn chunk_top_bit_is_masked() {
        let mut hash = [0u8; 32];
        hash[0] = 0xFF; // sets bit 31 of word 0, must be cleared
        let chunks = signing_policy_chunks(&hash);
        assert_eq!(chunks[0], 0x7F00_0000);
    }

    #[test]
    fn key_path_roundtrips_through_parse() {
        let hash = [0x5au8; 32];
        // Use a non-default coin_type to prove it is not hardcoded.
        let path = signing_policy_key_path(0, 3, &hash);
        assert_eq!(path[0], 0x504C_4359 | 0x8000_0000);
        assert_eq!(path[1], 0 | 0x8000_0000);
        assert_eq!(path[2], 3 | 0x8000_0000);
        let (coin_type, account, chunks) = parse_signing_policy_path(&path).unwrap();
        assert_eq!(coin_type, 0);
        assert_eq!(account, 3);
        assert_eq!(chunks, signing_policy_chunks(&hash));
    }

    #[test]
    fn parse_accepts_any_hardened_coin_type() {
        let hash = [0x11u8; 32];
        for coin_type in [0u32, 1, 42, 0x7fff_ffff] {
            let path = signing_policy_key_path(coin_type, 0, &hash);
            let (parsed_coin, _, _) = parse_signing_policy_path(&path).unwrap();
            assert_eq!(parsed_coin, coin_type);
        }
    }

    #[test]
    fn parse_rejects_non_policy_paths() {
        const H: u32 = 0x8000_0000;
        // wrong length
        assert!(parse_signing_policy_path(&[SIGNING_POLICY_PURPOSE | H]).is_none());
        // ordinary BIP-84 path (wrong purpose)
        assert!(parse_signing_policy_path(&[84 | H, 1 | H, 0 | H, 0, 0, 0, 0]).is_none());
        // coin_type not hardened
        assert!(
            parse_signing_policy_path(&[SIGNING_POLICY_PURPOSE | H, 1, 0 | H, 0, 0, 0, 0])
                .is_none()
        );
        // account not hardened
        assert!(
            parse_signing_policy_path(&[SIGNING_POLICY_PURPOSE | H, 1 | H, 0, 0, 0, 0, 0])
                .is_none()
        );
        // a chunk hardened
        assert!(parse_signing_policy_path(&[
            SIGNING_POLICY_PURPOSE | H,
            1 | H,
            0 | H,
            0,
            0 | H,
            0,
            0
        ])
        .is_none());
    }
}
