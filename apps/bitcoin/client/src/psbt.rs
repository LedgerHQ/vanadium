use std::collections::HashSet;
use std::fmt;

use bitcoin::consensus::{encode, Decodable, Encodable};
use bitcoin::io::Cursor;
use common::psbt::signing_policy::{
    SigningPolicy, PSBT_SIGNING_POLICY_GLOBAL_SCRIPT, PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER,
};

const PSBT_MAGIC: &[u8; 5] = b"psbt\xff";
const PSBT_PROPRIETARY_KEY_TYPE: u8 = 0xfc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertSigningPoliciesError {
    InvalidMagic,
    InvalidCompactSize,
    TruncatedGlobalMap,
    DuplicateGlobalKey,
    ConflictingPolicy,
}

impl fmt::Display for InsertSigningPoliciesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => f.write_str("invalid PSBT magic"),
            Self::InvalidCompactSize => f.write_str("invalid PSBT CompactSize value"),
            Self::TruncatedGlobalMap => f.write_str("truncated PSBT global map"),
            Self::DuplicateGlobalKey => f.write_str("duplicate PSBT global key"),
            Self::ConflictingPolicy => f.write_str("conflicting signing policy for the same hash"),
        }
    }
}

impl std::error::Error for InsertSigningPoliciesError {}

struct PolicyEntry {
    key: Vec<u8>,
    value: Vec<u8>,
    exists: bool,
}

fn read_compact_size(raw: &[u8], position: &mut usize) -> Result<u64, InsertSigningPoliciesError> {
    let mut cursor = Cursor::new(
        raw.get(*position..)
            .ok_or(InsertSigningPoliciesError::TruncatedGlobalMap)?,
    );
    let value = encode::VarInt::consensus_decode(&mut cursor)
        .map_err(|_| InsertSigningPoliciesError::InvalidCompactSize)?
        .0;
    let consumed = usize::try_from(cursor.position())
        .map_err(|_| InsertSigningPoliciesError::InvalidCompactSize)?;
    *position = position
        .checked_add(consumed)
        .ok_or(InsertSigningPoliciesError::InvalidCompactSize)?;
    Ok(value)
}

fn read_bytes<'a>(
    raw: &'a [u8],
    position: &mut usize,
    len: u64,
) -> Result<&'a [u8], InsertSigningPoliciesError> {
    let len = usize::try_from(len).map_err(|_| InsertSigningPoliciesError::InvalidCompactSize)?;
    let end = position
        .checked_add(len)
        .ok_or(InsertSigningPoliciesError::InvalidCompactSize)?;
    let bytes = raw
        .get(*position..end)
        .ok_or(InsertSigningPoliciesError::TruncatedGlobalMap)?;
    *position = end;
    Ok(bytes)
}

fn signing_policy_key(hash: &[u8; 32]) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(3 + PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER.len() + hash.len());
    key.push(PSBT_PROPRIETARY_KEY_TYPE);
    key.push(PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER.len() as u8);
    key.extend_from_slice(&PSBT_SIGNING_POLICY_PROPRIETARY_IDENTIFIER);
    key.push(PSBT_SIGNING_POLICY_GLOBAL_SCRIPT);
    key.extend_from_slice(hash);
    key
}

fn write_pair(out: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    encode::VarInt(key.len() as u64)
        .consensus_encode(out)
        .expect("encoding to Vec cannot fail");
    out.extend_from_slice(key);
    encode::VarInt(value.len() as u64)
        .consensus_encode(out)
        .expect("encoding to Vec cannot fail");
    out.extend_from_slice(value);
}

/// Inserts content-addressed signing policies into a raw PSBT global map.
///
/// The helper accepts both PSBTv0 and PSBTv2. It preserves every existing byte
/// except for appending missing policy entries immediately before the global-map
/// separator.
pub fn insert_signing_policies(
    raw_psbt: &[u8],
    signing_policies: &[SigningPolicy],
) -> Result<Vec<u8>, InsertSigningPoliciesError> {
    if !raw_psbt.starts_with(PSBT_MAGIC) {
        return Err(InsertSigningPoliciesError::InvalidMagic);
    }

    let mut policies: Vec<PolicyEntry> = Vec::new();
    for policy in signing_policies {
        let (value, hash) = policy.value_and_hash();
        if let Some(existing) = policies
            .iter()
            .find(|entry| entry.key == signing_policy_key(&hash))
        {
            if existing.value != value {
                return Err(InsertSigningPoliciesError::ConflictingPolicy);
            }
            continue;
        }
        policies.push(PolicyEntry {
            key: signing_policy_key(&hash),
            value,
            exists: false,
        });
    }

    let mut position = PSBT_MAGIC.len();
    let mut seen_keys: HashSet<Vec<u8>> = HashSet::new();
    let separator_position = loop {
        let pair_position = position;
        let key_len = read_compact_size(raw_psbt, &mut position)?;
        if key_len == 0 {
            break pair_position;
        }
        let key = read_bytes(raw_psbt, &mut position, key_len)?;
        if !seen_keys.insert(key.to_vec()) {
            return Err(InsertSigningPoliciesError::DuplicateGlobalKey);
        }
        let value_len = read_compact_size(raw_psbt, &mut position)?;
        let value = read_bytes(raw_psbt, &mut position, value_len)?;

        if let Some(policy) = policies.iter_mut().find(|entry| entry.key == key) {
            if policy.value != value {
                return Err(InsertSigningPoliciesError::ConflictingPolicy);
            }
            policy.exists = true;
        }
    };

    let mut out = Vec::with_capacity(raw_psbt.len());
    out.extend_from_slice(&raw_psbt[..separator_position]);
    for policy in policies.iter().filter(|entry| !entry.exists) {
        write_pair(&mut out, &policy.key, &policy.value);
    }
    out.extend_from_slice(&raw_psbt[separator_position..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use common::psbt::signing_policy::{PsbtSigningPolicyGlobalRead, ENGINE_ID_PROGRAM};

    use super::*;

    fn policy(script: &[u8]) -> SigningPolicy {
        SigningPolicy::new(ENGINE_ID_PROGRAM, 0, script.to_vec())
    }

    fn empty_psbt_v0() -> Vec<u8> {
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };
        bitcoin::psbt::Psbt::from_unsigned_tx(transaction)
            .unwrap()
            .serialize()
    }

    fn global_separator(raw: &[u8]) -> usize {
        let mut position = PSBT_MAGIC.len();
        loop {
            let key_len = read_compact_size(raw, &mut position).unwrap();
            if key_len == 0 {
                return position - 1;
            }
            read_bytes(raw, &mut position, key_len).unwrap();
            let value_len = read_compact_size(raw, &mut position).unwrap();
            read_bytes(raw, &mut position, value_len).unwrap();
        }
    }

    fn assert_preserves_maps(raw: &[u8]) {
        let signing_policy = policy(b"approve();");
        let separator = global_separator(raw);
        let updated = insert_signing_policies(raw, &[signing_policy.clone()]).unwrap();

        assert_eq!(&updated[..separator], &raw[..separator]);
        let updated_separator = global_separator(&updated);
        assert_eq!(&updated[updated_separator..], &raw[separator..]);
        assert_eq!(
            insert_signing_policies(&updated, &[signing_policy]).unwrap(),
            updated
        );
    }

    #[test]
    fn inserts_policy_and_preserves_psbt_v0_maps() {
        let raw = empty_psbt_v0();
        assert_preserves_maps(&raw);

        let updated = insert_signing_policies(&raw, &[policy(b"approve();")]).unwrap();
        let parsed = bitcoin::psbt::Psbt::deserialize(&updated).unwrap();
        let policies = parsed.get_signing_policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].script, b"approve();");
    }

    #[test]
    fn inserts_policy_and_preserves_psbt_v2_maps() {
        let raw = common::psbt::psbt_v0_to_v2(&empty_psbt_v0()).unwrap();
        assert_preserves_maps(&raw);

        let updated = insert_signing_policies(&raw, &[policy(b"approve();")]).unwrap();
        let parsed = common::fastpsbt::Psbt::parse(&updated).unwrap();
        let policies = parsed.get_signing_policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].script, b"approve();");
    }

    #[test]
    fn repeated_policies_are_deduplicated() {
        let raw = empty_psbt_v0();
        let signing_policy = policy(b"approve();");
        let updated =
            insert_signing_policies(&raw, &[signing_policy.clone(), signing_policy.clone()])
                .unwrap();
        let parsed = bitcoin::psbt::Psbt::deserialize(&updated).unwrap();
        assert_eq!(parsed.get_signing_policies().unwrap().len(), 1);
    }

    #[test]
    fn rejects_conflicting_existing_policy() {
        let raw = empty_psbt_v0();
        let signing_policy = policy(b"approve();");
        let mut updated = insert_signing_policies(&raw, &[signing_policy.clone()]).unwrap();
        let value_position =
            global_separator(&raw) + 1 + signing_policy_key(&signing_policy.hash()).len() + 1;
        updated[value_position] ^= 1;

        assert_eq!(
            insert_signing_policies(&updated, &[signing_policy]),
            Err(InsertSigningPoliciesError::ConflictingPolicy)
        );
    }

    #[test]
    fn rejects_duplicate_global_keys() {
        let raw = b"psbt\xff\x01\x01\x00\x01\x01\x00\x00";
        assert_eq!(
            insert_signing_policies(raw, &[]),
            Err(InsertSigningPoliciesError::DuplicateGlobalKey)
        );
    }

    #[test]
    fn rejects_malformed_global_map() {
        assert_eq!(
            insert_signing_policies(b"not a psbt", &[]),
            Err(InsertSigningPoliciesError::InvalidMagic)
        );
        assert_eq!(
            insert_signing_policies(b"psbt\xff\xfd", &[]),
            Err(InsertSigningPoliciesError::InvalidCompactSize)
        );
        assert_eq!(
            insert_signing_policies(b"psbt\xff\x02\x01", &[]),
            Err(InsertSigningPoliciesError::TruncatedGlobalMap)
        );
    }
}
