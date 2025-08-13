use crate::{
    account::{AccountCoordinates, WalletPolicy, WalletPolicyCoordinates},
    bip388::{KeyOrigin, KeyPlaceholder},
};

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    consensus::Encodable,
    psbt::{self, raw::ProprietaryKey, Psbt},
    TapLeafHash,
};

/// Proprietary key prefix for account-related data in PSBT fields
pub const PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER: [u8; 7] = *b"ACCOUNT";

pub const PSBT_ACCOUNT_GLOBAL_ACCOUNT_DESCRIPTOR: u8 = 0x00;
pub const PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME: u8 = 0x01;
pub const PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR: u8 = 0x02;

pub const PSBT_ACCOUNT_IN_COORDINATES: u8 = 0x00;
pub const PSBT_ACCOUNT_OUT_COORDINATES: u8 = 0x00;

// the largest value that is represented as a single byte in compact size
const MAX_SINGLE_BYTE_COMPACTSIZE: u8 = 252;

fn is_valid_account_name(value: &[u8]) -> bool {
    value.len() >= 1 // not too short
        && value.len() <= 64 // not too long
        && value[0] != b' ' // doesn't start with space
        && value[value.len() - 1] != b' ' // doesn't end with space
        && value.iter().all(|&c| c >= 0x20 && c <= 0x7E) // no disallowed characters
}

#[derive(Debug, Clone)]
pub enum PsbtAccount {
    WalletPolicy(WalletPolicy),
    // other account types will be added here
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtAccountCoordinates {
    WalletPolicy(WalletPolicyCoordinates),
    // coordinates for other account types will be added here
}

pub trait PsbtAccountGlobalRead {
    fn get_accounts(&self) -> Result<Vec<PsbtAccount>, &'static str>;
    fn get_account(&self, id: u32) -> Result<Option<PsbtAccount>, &'static str>;
    fn get_account_name(&self, id: u32) -> Result<Option<String>, &'static str>;
    fn get_account_proof_of_registration(&self, id: u32) -> Result<Option<Vec<u8>>, &'static str>;
}

pub trait PsbtAccountGlobalWrite {
    fn set_account(&mut self, id: u32, account: PsbtAccount) -> Result<(), &'static str>;
    fn set_accounts(&mut self, accounts: Vec<PsbtAccount>) -> Result<(), &'static str> {
        for (i, account) in accounts.into_iter().enumerate() {
            self.set_account(i as u32, account)?;
        }
        Ok(())
    }
    fn set_account_name(&mut self, id: u32, name: &str) -> Result<(), &'static str>;
    fn set_account_proof_of_registration(
        &mut self,
        id: u32,
        por: &[u8],
    ) -> Result<(), &'static str>;
}

pub trait PsbtAccountInputRead {
    fn get_account_coordinates(
        &self,
    ) -> Result<Option<(u32, PsbtAccountCoordinates)>, &'static str>;
}

pub trait PsbtAccountInputWrite {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), &'static str>;
}

pub trait PsbtAccountOutputRead {
    fn get_account_coordinates(
        &self,
    ) -> Result<Option<(u32, PsbtAccountCoordinates)>, &'static str>;
}

pub trait PsbtAccountOutputWrite {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), &'static str>;
}

impl PsbtAccountGlobalRead for Psbt {
    // Get all accounts from the global section of the PSBT.
    // Unknown account types are ignored.
    fn get_accounts(&self) -> Result<Vec<PsbtAccount>, &'static str> {
        let mut id = 0u32;
        let mut res = Vec::new();

        // Keep trying to get accounts with increasing IDs until we find none
        loop {
            match self.get_account(id)? {
                Some(account) => {
                    res.push(account);
                    id += 1;
                }
                None => break, // No more accounts at this ID
            }
        }

        Ok(res)
    }

    // Get the account with the specific id. Returns None if not found
    // Unknown account types are ignored.
    fn get_account(&self, id: u32) -> Result<Option<PsbtAccount>, &'static str> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_DESCRIPTOR,
            key: id_raw,
        };

        if let Some(value) = self.proprietary.get(&key) {
            if value.len() < 1 {
                return Err("Empty account value");
            }
            match value[0] {
                0 => {
                    let wp = WalletPolicy::deserialize(&mut &value[1..])
                        .map_err(|_| "Failed to deserialize WalletPolicy")?;
                    Ok(Some(PsbtAccount::WalletPolicy(wp)))
                }
                _ => Err("Unknown account type"),
            }
        } else {
            Ok(None)
        }
    }

    fn get_account_name(&self, id: u32) -> Result<Option<String>, &'static str> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME,
            key: id_raw,
        };

        if let Some(value) = self.proprietary.get(&key) {
            if !is_valid_account_name(&value) {
                return Err("Invalid account name");
            }

            Ok(Some(String::from_utf8(value.to_vec()).unwrap()))
        } else {
            Ok(None)
        }
    }

    fn get_account_proof_of_registration(&self, id: u32) -> Result<Option<Vec<u8>>, &'static str> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR,
            key: id_raw,
        };

        if let Some(value) = self.proprietary.get(&key) {
            if value.len() < 1 {
                return Err("Empty account value");
            }
            Ok(Some(value.to_vec()))
        } else {
            Ok(None)
        }
    }
}

impl PsbtAccountGlobalWrite for Psbt {
    fn set_account(&mut self, id: u32, account: PsbtAccount) -> Result<(), &'static str> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_DESCRIPTOR,
            key: id_raw,
        };

        match account {
            PsbtAccount::WalletPolicy(wp) => {
                let ser_wp = wp.serialize();
                let mut res = Vec::with_capacity(1 + ser_wp.len());
                res.push(0x00);
                res.extend_from_slice(&ser_wp);
                self.proprietary.insert(key, res);
            }
        }

        Ok(())
    }

    fn set_account_name(&mut self, id: u32, name: &str) -> Result<(), &'static str> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME,
            key: id_raw,
        };

        if !is_valid_account_name(name.as_bytes()) {
            return Err("Invalid account name");
        }
        self.proprietary.insert(key, name.as_bytes().to_vec());

        Ok(())
    }

    fn set_account_proof_of_registration(
        &mut self,
        id: u32,
        por: &[u8],
    ) -> Result<(), &'static str> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR,
            key: id_raw,
        };

        if por.len() < 1 {
            return Err("Empty account value");
        }

        self.proprietary.insert(key, por.to_vec());

        Ok(())
    }
}

impl PsbtAccountInputRead for psbt::Input {
    fn get_account_coordinates(
        &self,
    ) -> Result<Option<(u32, PsbtAccountCoordinates)>, &'static str> {
        for (key, value) in &self.proprietary {
            if key.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && key.subtype == PSBT_ACCOUNT_IN_COORDINATES
            {
                if value.len() < 3 {
                    return Err("Invalid account value");
                }
                let account_id = value[0] as u32;
                if account_id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
                    return Err("Account ID exceeds valid range");
                }
                match value[1] {
                    0 => {
                        let coords = AccountCoordinates::deserialize(&mut &value[2..])
                            .map_err(|_| "Failed to deserialize AccountCoordinates")?;
                        return Ok(Some((
                            account_id,
                            PsbtAccountCoordinates::WalletPolicy(coords),
                        )));
                    }
                    _ => return Err("Unknown account type"),
                }
            }
        }
        Ok(None)
    }
}

impl PsbtAccountInputWrite for psbt::Input {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), &'static str> {
        if id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
            return Err("Account ID exceeds valid range");
        }
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_IN_COORDINATES,
            key: Vec::new(),
        };

        match coordinates {
            PsbtAccountCoordinates::WalletPolicy(coords) => {
                let serialized_coords = coords.serialize();
                let mut serialized_value = Vec::with_capacity(1 + 1 + serialized_coords.len());
                serialized_value.push(id as u8);
                serialized_value.push(0); // tag
                serialized_value.extend_from_slice(&serialized_coords);
                self.proprietary.insert(key, serialized_value);
            }
        }

        Ok(())
    }
}

impl PsbtAccountOutputRead for psbt::Output {
    fn get_account_coordinates(
        &self,
    ) -> Result<Option<(u32, PsbtAccountCoordinates)>, &'static str> {
        for (key, value) in &self.proprietary {
            if key.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && key.subtype == PSBT_ACCOUNT_OUT_COORDINATES
            {
                if value.len() < 3 {
                    return Err("Invalid coordinates value");
                }
                let account_id = value[0] as u32;
                if account_id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
                    // specs would want a compact size, but we use 1 byte for simplicity
                    return Err("No more than 253 accounts are supported");
                }
                match value[1] {
                    0 => {
                        let coords = AccountCoordinates::deserialize(&mut &value[2..])
                            .map_err(|_| "Failed to deserialize AccountCoordinates")?;
                        return Ok(Some((
                            account_id,
                            PsbtAccountCoordinates::WalletPolicy(coords),
                        )));
                    }
                    _ => return Err("Unknown account type"),
                }
            }
        }
        Ok(None)
    }
}

impl PsbtAccountOutputWrite for psbt::Output {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), &'static str> {
        if id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
            // specs would want a compact size, but we use 1 byte for simplicity
            return Err("No more than 253 accounts are supported");
        }
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_OUT_COORDINATES,
            key: Vec::new(),
        };

        match coordinates {
            PsbtAccountCoordinates::WalletPolicy(coords) => {
                let serialized_coords = coords.serialize();
                let mut serialized_value = Vec::with_capacity(1 + 1 + serialized_coords.len());
                serialized_value.push(id as u8);
                serialized_value.push(0); // tag
                serialized_value.extend_from_slice(&serialized_coords);
                self.proprietary.insert(key, serialized_value);
            }
        }

        Ok(())
    }
}

// Helper function to get wallet policy coordinates from a PSBT input or output
fn get_wallet_policy_coordinates(
    bip32_derivation: &BTreeMap<bitcoin::secp256k1::PublicKey, (Fingerprint, DerivationPath)>,
    tap_bip32_derivation: &BTreeMap<
        bitcoin::secp256k1::XOnlyPublicKey,
        (Vec<TapLeafHash>, (Fingerprint, DerivationPath)),
    >,
    key_orig_info: &KeyOrigin,
    key_placeholder: &KeyPlaceholder,
) -> Option<WalletPolicyCoordinates> {
    // iterate over all derivations; if it's a key derived from the internal key,
    // deduce the coordinates and insert them
    for (_, (fpr, der)) in bip32_derivation.iter() {
        if *fpr != key_orig_info.fingerprint.to_be_bytes().into() {
            continue;
        }
        if key_orig_info.derivation_path.len() + 2 != der.len() {
            continue;
        }
        let change_step: u32 = der[der.len() - 2].into();
        let is_change = match change_step {
            n if n == key_placeholder.num1 => false,
            n if n == key_placeholder.num2 => true,
            _ => continue, // this could only happen in case of a fingerprint collision
        };
        let address_index: u32 = der[der.len() - 1].into();
        return Some(WalletPolicyCoordinates {
            is_change,
            address_index,
        });
    }

    // do the same for the tap_bip32_derivations
    // TODO: we might want to avoid the code duplication
    for (_, (_, (fpr, der))) in tap_bip32_derivation.iter() {
        if *fpr != key_orig_info.fingerprint.to_be_bytes().into() {
            continue;
        }
        if key_orig_info.derivation_path.len() + 2 != der.len() {
            continue;
        }
        let change_step: u32 = der[der.len() - 2].into();
        let is_change = match change_step {
            n if n == key_placeholder.num1 => false,
            n if n == key_placeholder.num2 => true,
            _ => continue, // this could only happen in case of a fingerprint collision
        };
        let address_index: u32 = der[der.len() - 1].into();
        return Some(WalletPolicyCoordinates {
            is_change,
            address_index,
        });
    }

    None
}

// Given a PSBT and a wallet policy, and one of the placeholders, fills the psbt with the following fields:
// - Global: account descriptor, account name (if given), proof of registration (if given)
// - Input: account coordinates
// - Output: account coordinates
// Coordinates are deduced from the bip32 derivations in the PSBT, only using keys with
// full key origin information in the wallet policy.
pub fn fill_psbt_with_bip388_coordinates(
    psbt: &mut Psbt,
    wallet_policy: &WalletPolicy,
    name: Option<&str>,
    proof_of_registrations: Option<&[u8]>,
    key_placeholder: &KeyPlaceholder,
    account_id: u32,
) -> Result<(), &'static str> {
    psbt.set_account(account_id, PsbtAccount::WalletPolicy(wallet_policy.clone()))?;
    if let Some(name) = name {
        psbt.set_account_name(account_id, name)?;
    }
    if let Some(por) = proof_of_registrations {
        psbt.set_account_proof_of_registration(account_id, por)?;
    }

    // we will look for keys derived from this
    let key_expr = &wallet_policy.key_information[key_placeholder.key_index as usize];
    let Some(ref key_orig_info) = key_expr.origin_info else {
        return Err("Key expression has no origin info");
    };

    // Fill input coordinates
    for input in psbt.inputs.iter_mut() {
        if let Some(coords) = get_wallet_policy_coordinates(
            &input.bip32_derivation,
            &input.tap_key_origins,
            key_orig_info,
            key_placeholder,
        ) {
            input.set_account_coordinates(
                account_id,
                PsbtAccountCoordinates::WalletPolicy(coords),
            )?;
        }
    }

    // Fill output coordinates
    for output in psbt.outputs.iter_mut() {
        if let Some(coords) = get_wallet_policy_coordinates(
            &output.bip32_derivation,
            &output.tap_key_origins,
            key_orig_info,
            key_placeholder,
        ) {
            output.set_account_coordinates(
                account_id,
                PsbtAccountCoordinates::WalletPolicy(coords),
            )?;
        }
    }

    Ok(())
}

mod convert_v0_to_v2 {
    // This module provides a minimal conversion code from psbtv0 to psbtv2, directly in binary format.
    // It performs very little validation, so it should only be used to convert a serialized PSBTv0 to PSBTv2
    // before passing it to some other code that expects PSBTv2.
    //
    // Not thoroughly tested.

    use alloc::{vec, vec::Vec};
    use bitcoin::{
        consensus::{encode as enc, Decodable, Encodable},
        hashes::Hash,
        io::{Cursor, Read},
        Transaction,
    };

    struct KV {
        key: Vec<u8>,
        val: Vec<u8>,
    }

    fn read_varint<R: Read>(r: &mut R) -> Result<u64, &'static str> {
        Ok(enc::VarInt::consensus_decode(r)
            .map_err(|_| "Failed to read varint")?
            .0)
    }
    fn write_varint(buf: &mut Vec<u8>, n: u64) -> Result<(), &'static str> {
        enc::VarInt(n)
            .consensus_encode(buf)
            .map_err(|_| "Failed to write varint")?;
        Ok(())
    }
    fn read_bytes<R: Read>(r: &mut R, len: usize) -> Result<Vec<u8>, &'static str> {
        let mut v = vec![0u8; len];
        r.read_exact(&mut v).map_err(|_| "Failed to read bytes")?;
        Ok(v)
    }
    fn read_map<R: Read>(r: &mut R) -> Result<Vec<KV>, &'static str> {
        let mut out = Vec::new();
        loop {
            let key_len = read_varint(r)? as usize;
            if key_len == 0 {
                break;
            } // map sep
            let key = read_bytes(r, key_len)?;
            let val_len = read_varint(r)? as usize;
            let val = read_bytes(r, val_len)?;
            out.push(KV { key, val });
        }
        Ok(out)
    }
    fn key_type(raw_key: &[u8]) -> Result<u64, &'static str> {
        let mut c = Cursor::new(raw_key);
        Ok(enc::VarInt::consensus_decode(&mut c)
            .map_err(|_| "Failed to read key type")?
            .0)
    }
    fn mk_key(typ: u64, keydata: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut k = Vec::with_capacity(1 + keydata.len() + 9);
        enc::VarInt(typ)
            .consensus_encode(&mut k)
            .map_err(|_| "Failed to write key")?;
        k.extend_from_slice(keydata);
        Ok(k)
    }
    fn push_kv(
        glob: &mut Vec<KV>,
        typ: u64,
        keydata: &[u8],
        val: Vec<u8>,
    ) -> Result<(), &'static str> {
        glob.push(KV {
            key: mk_key(typ, keydata)?,
            val,
        });
        Ok(())
    }

    fn write_map_sorted(buf: &mut Vec<u8>, mut m: Vec<KV>) -> Result<(), &'static str> {
        m.sort_unstable_by(|a, b| a.key.cmp(&b.key).then_with(|| a.val.cmp(&b.val)));
        for KV { key, val } in m {
            write_varint(buf, key.len() as u64)?;
            buf.extend_from_slice(&key);
            write_varint(buf, val.len() as u64)?;
            buf.extend_from_slice(&val);
        }
        buf.push(0x00); // map separator
        Ok(())
    }

    /// Converts a PSBTv0 to PSBTv2 in binary format, and makes sure that the keys are sorted in each map.
    /// Returns an error if the input is not a valid PSBTv0; however, very little validation is performed on the
    /// input PSBTv0.
    pub fn psbt_v0_to_v2(raw_psbt: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Header
        if raw_psbt.len() < 5 || &raw_psbt[0..5] != b"psbt\xff" {
            return Err("Not a PSBT");
        }
        let mut cur = Cursor::new(&raw_psbt[5..]);

        // Parse v0 global map and capture unsigned tx
        let mut g0 = read_map(&mut cur)?;
        let mut unsigned_tx_bytes: Option<Vec<u8>> = None;
        let mut g_pass = Vec::<KV>::new();

        for kv in g0.drain(..) {
            let t = key_type(&kv.key)?;
            match t {
            0x00 /* PSBT_GLOBAL_UNSIGNED_TX */ => { unsigned_tx_bytes = Some(kv.val); }
            0x02 | 0x03 | 0x04 | 0x05 | 0xFB => { return Err("v2 fields already present"); }
            _ => g_pass.push(kv),
        }
        }
        let utx = unsigned_tx_bytes.ok_or("missing unsigned tx")?;
        let tx: Transaction =
            enc::deserialize(&utx).map_err(|_| "Failed to deserialize unsigned tx")?;

        // Knowing counts, parse inputs and outputs from v0
        let n_inputs = tx.input.len();
        let n_outputs = tx.output.len();

        let mut ins_v0: Vec<Vec<KV>> = Vec::with_capacity(n_inputs);
        for _ in 0..n_inputs {
            ins_v0.push(read_map(&mut cur)?);
        }
        let mut outs_v0: Vec<Vec<KV>> = Vec::with_capacity(n_outputs);
        for _ in 0..n_outputs {
            outs_v0.push(read_map(&mut cur)?);
        }

        // Build v2
        let mut out = Vec::<u8>::new();
        out.extend_from_slice(b"psbt\xff");

        // v2 global map
        let mut g2 = g_pass;
        // PSBT_GLOBAL_VERSION = 0xFB, value: u32 LE 2
        push_kv(&mut g2, 0xFB, &[], 2u32.to_le_bytes().to_vec())?;
        // PSBT_GLOBAL_TX_VERSION = 0x02, value: i32 LE
        push_kv(&mut g2, 0x02, &[], tx.version.0.to_le_bytes().to_vec())?;
        // PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03, value: u32 LE
        push_kv(
            &mut g2,
            0x03,
            &[],
            tx.lock_time.to_consensus_u32().to_le_bytes().to_vec(),
        )?;
        // PSBT_GLOBAL_INPUT_COUNT = 0x04, value: compactsize
        {
            let mut v = Vec::new();
            write_varint(&mut v, n_inputs as u64)?;
            push_kv(&mut g2, 0x04, &[], v)?;
        }
        // PSBT_GLOBAL_OUTPUT_COUNT = 0x05, value: compactsize
        {
            let mut v = Vec::new();
            write_varint(&mut v, n_outputs as u64)?;
            push_kv(&mut g2, 0x05, &[], v)?;
        }
        write_map_sorted(&mut out, g2)?;

        // v2 inputs: copy v0 fields + add {prev_txid, vout, sequence}
        for (i, mut imap) in ins_v0.into_iter().enumerate() {
            let txin = &tx.input[i];

            // PSBT_IN_PREVIOUS_TXID = 0x0e, value: 32-byte txid
            {
                let mut v = Vec::with_capacity(32);
                // Use the hash's underlying bytes
                v.extend_from_slice(txin.previous_output.txid.as_raw_hash().as_byte_array());
                push_kv(&mut imap, 0x0e, &[], v)?;
            }
            // PSBT_IN_OUTPUT_INDEX = 0x0f, value: u32 LE
            push_kv(
                &mut imap,
                0x0f,
                &[],
                txin.previous_output.vout.to_le_bytes().to_vec(),
            )?;
            // PSBT_IN_SEQUENCE = 0x10, value: u32 LE (include unconditionally)
            push_kv(&mut imap, 0x10, &[], txin.sequence.0.to_le_bytes().to_vec())?;

            write_map_sorted(&mut out, imap)?;
        }

        // v2 outputs: copy v0 fields + add {amount, script}
        for (j, mut omap) in outs_v0.into_iter().enumerate() {
            let txout = &tx.output[j];

            // PSBT_OUT_AMOUNT = 0x03, value: i64 LE
            push_kv(
                &mut omap,
                0x03,
                &[],
                (txout.value.to_sat() as i64).to_le_bytes().to_vec(),
            )?;
            // PSBT_OUT_SCRIPT = 0x04, value: scriptPubKey bytes
            push_kv(
                &mut omap,
                0x04,
                &[],
                txout.script_pubkey.as_bytes().to_vec(),
            )?;

            write_map_sorted(&mut out, omap)?;
        }

        Ok(out)
    }
}

pub use convert_v0_to_v2::psbt_v0_to_v2;

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    use super::*;

    const TEST_PSBT: &'static str = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";

    fn psbt_from_str(psbt: &str) -> Result<Psbt, String> {
        let decoded = STANDARD
            .decode(psbt)
            .map_err(|e| format!("Failed to decode PSBT: {}", e))?;
        let psbt = Psbt::deserialize(&decoded)
            .map_err(|e| format!("Failed to deserialize PSBT: {}", e))?;
        Ok(psbt)
    }

    #[test]
    fn test_set_and_get_account_name() {
        let mut psbt = psbt_from_str(TEST_PSBT).unwrap();
        let account_id = 0;
        let valid_name = "TestAccount";
        assert!(psbt.set_account_name(account_id, valid_name).is_ok());
        let ret = psbt.get_account_name(account_id).unwrap();
        assert_eq!(ret, Some(valid_name.to_string()));
    }

    #[test]
    fn test_invalid_account_name() {
        // setting invalid account names should fail
        let mut psbt = psbt_from_str(TEST_PSBT).unwrap();
        let account_id = 0;

        let long_name = "a".repeat(65);

        let invalid_names = [
            "",                 // too short
            long_name.as_str(), // too long
            " Invalid",         // starts with space
            "Invalid ",         // ends with a space
            "Invàlid",          // contains disallowed character
        ];
        for invalid_name in invalid_names.iter() {
            assert!(psbt.set_account_name(account_id, invalid_name).is_err());
        }
    }

    #[test]
    fn test_set_and_get_proof_of_registration() {
        let mut psbt = psbt_from_str(TEST_PSBT).unwrap();
        let account_id = 0;
        let por: Vec<u8> = vec![1, 2, 3, 4];
        assert!(psbt
            .set_account_proof_of_registration(account_id, &por)
            .is_ok());
        let ret = psbt.get_account_proof_of_registration(account_id).unwrap();
        assert_eq!(ret, Some(por));
    }

    #[test]
    fn test_set_and_get_account() {
        let mut psbt = psbt_from_str(TEST_PSBT).unwrap();
        let wallet_policy = WalletPolicy::new(
            "pkh(@0/**)",
            [
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
                    .try_into()
                    .unwrap()
            ]
            .to_vec()
        )
        .unwrap();
        let account_id = 0;
        assert!(psbt
            .set_account(account_id, PsbtAccount::WalletPolicy(wallet_policy.clone()))
            .is_ok());
        let retrieved = psbt.get_account(account_id).unwrap();
        match retrieved {
            Some(PsbtAccount::WalletPolicy(ref wp)) => {
                assert_eq!(wp.serialize(), wallet_policy.serialize());
            }
            _ => panic!("Unexpected or missing account type"),
        }
    }

    #[test]
    fn test_get_nonexistent_account() {
        let psbt = psbt_from_str(TEST_PSBT).unwrap();
        let retrieved = psbt.get_account(99).unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_set_and_get_input_coordinates() {
        use super::*;
        let mut input = psbt::Input::default();
        let account_id = 0;
        let coords = PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates {
            is_change: false,
            address_index: 5,
        });
        input
            .set_account_coordinates(account_id, coords.clone())
            .unwrap();
        let retrieved = input.get_account_coordinates().unwrap();
        assert_eq!(retrieved, Some((account_id, coords)));
    }

    #[test]
    fn test_set_and_get_output_coordinates() {
        use super::*;
        let mut output = psbt::Output::default();
        let account_id = 0;
        let coords = PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates {
            is_change: true,
            address_index: 10,
        });
        output
            .set_account_coordinates(account_id, coords.clone())
            .unwrap();
        let retrieved = output.get_account_coordinates().unwrap();
        assert_eq!(retrieved, Some((account_id, coords)));
    }

    #[test]
    fn test_fill_psbt_with_bip388_coordinates() {
        let wallet_policy = WalletPolicy::new("wpkh(@0/**)", [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()
        ].to_vec()).unwrap();
        let psbt_str = "cHNidP8BAKYCAAAAAp4s/ifwrYe3iiN9XXQF1KMGZso2HVhaRnsN/kImK020AQAAAAD9////r7+uBlkPdB/xr1m2rEYRJjNqTEqC21U99v76tzesM/MAAAAAAP3///8CqDoGAAAAAAAWABTrOPqbgSj4HybpXtsMX/rqg2kP5OCTBAAAAAAAIgAgP6lmyd3Nwv2W5KXhvHZbn69s6LPrTxEEqta993Mk5b4AAAAAAAEAcQIAAAABk2qy4BBy95PP5Ml3VN4bYf4D59tlNsiy8h3QtXQsSEUBAAAAAP7///8C3uHHAAAAAAAWABTreNfEC/EGOw4/zinDVltonIVZqxAnAAAAAAAAFgAUIxjWb4T+9cSHX5M7A43GODH42hP5lx4AAQEfECcAAAAAAAAWABQjGNZvhP71xIdfkzsDjcY4MfjaEyIGA0Ve587cl7C6Q1uABm/JLJY6NMYAMXmB0TUzDE7kOsejGPWswv1UAACAAQAAgAAAAIAAAAAAAQAAAAABAHEBAAAAAQ5HHvTpLBrLUe/IZg+NP2mTbqnJsr/3L/m8gcUe/PRkAQAAAAAAAAAAAmCuCgAAAAAAFgAUNcbg3W08hLFrqIXcpzrIY9C1k+yvBjIAAAAAABYAFNwobgzS5r03zr6ew0n7XwiQVnL8AAAAAAEBH2CuCgAAAAAAFgAUNcbg3W08hLFrqIXcpzrIY9C1k+wiBgJxtbd5rYcIOFh3l7z28MeuxavnanCdck9I0uJs+HTwoBj1rML9VAAAgAEAAIAAAACAAQAAAAAAAAAAIgICKexHcnEx7SWIogxG7amrt9qm9J/VC6/nC5xappYcTswY9azC/VQAAIABAACAAAAAgAEAAAAKAAAAAAA=";
        let mut psbt = psbt_from_str(psbt_str).unwrap();

        let placeholders: Vec<KeyPlaceholder> = wallet_policy
            .descriptor_template
            .placeholders()
            .map(|(k, _)| k.clone())
            .collect();
        assert!(placeholders.len() == 1);
        let key_placeholder = placeholders[0];

        let result = fill_psbt_with_bip388_coordinates(
            &mut psbt,
            &wallet_policy,
            None,
            None,
            &key_placeholder,
            0,
        );

        assert!(result.is_ok());

        let accounts = psbt.get_accounts().unwrap();
        assert_eq!(accounts.len(), 1);

        assert_eq!(
            psbt.inputs[0].get_account_coordinates().unwrap(),
            Some((
                0,
                PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates::new(false, 1))
            ))
        );
        assert_eq!(
            psbt.inputs[1].get_account_coordinates().unwrap(),
            Some((
                0,
                PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates::new(true, 0))
            ))
        );
        assert_eq!(
            psbt.outputs[0].get_account_coordinates().unwrap(),
            Some((
                0,
                PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates::new(true, 10))
            ))
        );
        assert_eq!(psbt.outputs[1].get_account_coordinates().unwrap(), None);
    }

    #[test]
    fn test_psbt_v0_to_v2() {
        let psbt_v0 = "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";
        let psbt_v2 = "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";
        let psbt_v0_bytes = STANDARD.decode(psbt_v0).unwrap();
        let psbt_v2_bytes = STANDARD.decode(psbt_v2).unwrap();

        let psbt_v2_converted = psbt_v0_to_v2(&psbt_v0_bytes).unwrap();
        assert_eq!(psbt_v2_converted, psbt_v2_bytes);
    }
}
