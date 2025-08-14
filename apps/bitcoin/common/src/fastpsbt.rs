// This module is a fast implementation of a read-only version of PSBTv2 (Partially Signed Bitcoin Transaction)
// as specified in BIP-370.
// It is created by parsing a &[u8] once, and creating an indexed view of the PSBT for fast access, with minimal
// overhead and validation.
// Fields that are small are also stored as variables during parsing, while fields that can be large will be stored
// as slices into the original PSBT data.
//
// It is assumed that keys in each map of the PSBT are unique and sorted in ascending order.
//
// This is currently only a partial implementation, only targeting what the vnd-bitcoin V-App uses.
//
// TODO:
// - implement missing fields
// - make all fields of Psbt, Input and Output private and implement accessors (preventing modifications to the
//   internal state)
// - Make the compulsory fields from BIP-370 not be typed as an Option<T>; fail in the constructor instead
// - Add test vectors from BIP-370

#![allow(dead_code)]

use alloc::vec::Vec;
use bitcoin::{
    consensus::deserialize, hashes::Hash, psbt::OutputType, script::ScriptBuf, secp256k1::Message,
    sighash::SighashCache, transaction::Version, Amount, EcdsaSighashType, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};

use core::{borrow::Borrow, cell::OnceCell, cmp::Ordering};

const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_XPUB: u8 = 0x01;
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
const PSBT_IN_POR_COMMITMENT: u8 = 0x09;
const PSBT_IN_RIPEMD160: u8 = 0x0A;
const PSBT_IN_SHA256: u8 = 0x0B;
const PSBT_IN_HASH160: u8 = 0x0C;
const PSBT_IN_HASH256: u8 = 0x0D;
const PSBT_IN_PREVIOUS_TXID: u8 = 0x0E;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0F;
const PSBT_IN_SEQUENCE: u8 = 0x10;
const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;
const PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x1A;
const PSBT_IN_MUSIG2_PUB_NONCE: u8 = 0x1B;
const PSBT_IN_MUSIG2_PARTIAL_SIG: u8 = 0x1C;
const PSBT_IN_SP_ECDH_SHARE: u8 = 0x1D;
const PSBT_IN_SP_DLEQ: u8 = 0x1E;
const PSBT_IN_PROPRIETARY: u8 = 0xFC;

const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
const PSBT_OUT_AMOUNT: u8 = 0x03;
const PSBT_OUT_SCRIPT: u8 = 0x04;
const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
const PSBT_OUT_TAP_TREE: u8 = 0x06;
const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;
const PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS: u8 = 0x08;
const PSBT_OUT_SP_V0_INFO: u8 = 0x09;
const PSBT_OUT_SP_V0_LABEL: u8 = 0x0A;
const PSBT_OUT_DNSSEC_PROOF: u8 = 0x35;
const PSBT_OUT_PROPRIETARY: u8 = 0xFC;

// A key in a PSBT map, consisting of a type and key data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key<'a> {
    pub key_type: u8,
    pub key_data: &'a [u8],
}

impl<'a> PartialOrd for Key<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for Key<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_type
            .cmp(&other.key_type)
            .then_with(|| self.key_data.cmp(other.key_data))
    }
}

// Internal struct to represent a pair of keydata and corresponding value parsed in the map. Note that the keylen and
// keytype must have been already parsed before creating this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtError {
    InvalidMagic,
    UnexpectedEof,
    InvalidCompactSize,
    MapTerminatorMissing,
    DuplicateKey,  // exact duplicate key bytes in same map
    UnsortedKeys,  // only PSBTs with lexicographically sorted maps are supported
    BadValue,      // invalid value
    MissingCounts, // missing PSBT_GLOBAL_INPUT_COUNT or PSBT_GLOBAL_OUTPUT_COUNT
    MissingOutputIndex,
    MissingRedeemScript,
    MissingWitnessScript,
    CountsTooLarge, // counts don't fit in usize
    NotAllowed,     // not allowed in PSBT v2
    OutOfRange,
    UnknownOutputType,
    Unsupported,
}

#[derive(Debug, Clone, Copy)]
struct MapPair<'a> {
    pub key_type: u8,
    pub key_data: &'a [u8],
    pub value: &'a [u8],
}

#[derive(Debug)]
pub struct Psbt<'a> {
    pub raw_psbt: &'a [u8],

    global_map: ParsedMap<'a>,

    pub inputs: Vec<Input<'a>>,
    pub outputs: Vec<Output<'a>>,

    pub version: u32,
    pub tx_version: i32,
    pub fallback_locktime: Option<u32>,
    pub tx_modifiable: Option<u8>,

    cached_unsigned_tx: OnceCell<Transaction>,
}

#[derive(Debug)]
pub struct Input<'a> {
    map: ParsedMap<'a>,

    pub non_witness_utxo: Option<&'a [u8]>,
    pub witness_utxo: Option<&'a [u8]>,
    pub sighash_type: Option<u32>,
    pub redeem_script: Option<&'a [u8]>,
    pub witness_script: Option<&'a [u8]>,
    pub final_scriptsig: Option<&'a [u8]>,
    pub final_scriptwitness: Option<&'a [u8]>,
    pub previous_txid: Option<&'a [u8; 32]>,
    pub output_index: Option<u32>,
    pub sequence: Option<u32>,
    pub required_time_locktime: Option<u32>,
    pub required_height_locktime: Option<u32>,

    cached_witness_utxo: OnceCell<bitcoin::TxOut>,
    cached_non_witness_utxo: OnceCell<bitcoin::Transaction>,
}

#[derive(Debug)]
pub struct Output<'a> {
    map: ParsedMap<'a>,

    pub redeem_script: Option<&'a [u8]>,
    pub witness_script: Option<&'a [u8]>,
    pub amount: Option<u64>,
    pub script: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PsbtError> {
        if self.remaining() < n {
            return Err(PsbtError::UnexpectedEof);
        }
        let start = self.pos;
        self.pos += n;
        Ok(&self.buf[start..start + n])
    }

    fn read_compact_size(&mut self) -> Result<u64, PsbtError> {
        let b = *self.take(1)?.first().unwrap();
        match b {
            n @ 0x00..=0xfc => Ok(n as u64),
            0xfd => {
                let s = self.take(2)?;
                Ok(u16::from_le_bytes([s[0], s[1]]) as u64)
            }
            0xfe => {
                let s = self.take(4)?;
                Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64)
            }
            0xff => {
                let s = self.take(8)?;
                Ok(u64::from_le_bytes([
                    s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
                ]))
            }
        }
    }

    fn read_len_prefixed(&mut self) -> Result<&'a [u8], PsbtError> {
        let len = self.read_compact_size()?;
        usize::try_from(len)
            .ok()
            .and_then(|n| if self.remaining() >= n { Some(n) } else { None })
            .ok_or(PsbtError::UnexpectedEof)
            .and_then(|n| self.take(n))
    }
}

fn u64_from_compact_size(data: &[u8]) -> Result<u64, PsbtError> {
    let mut cur = Cursor::new(data, 0);
    let res = cur.read_compact_size();
    if cur.remaining() > 0 {
        return Err(PsbtError::InvalidCompactSize);
    }
    res
}

#[derive(Debug)]
struct ParsedMap<'a> {
    pub pairs: Vec<MapPair<'a>>,
}

impl<'a> ParsedMap<'a> {
    fn from_cursor<F>(cur: &mut Cursor<'a>, mut f: F) -> Result<ParsedMap<'a>, PsbtError>
    where
        F: for<'b> FnMut(&'b MapPair<'a>) -> Result<(), PsbtError>,
    {
        let mut pairs: Vec<MapPair<'a>> = Vec::new();

        loop {
            // key
            let key_len = cur.read_compact_size()?;
            if key_len == 0 {
                return Ok(ParsedMap { pairs });
            }
            let key_len_usize =
                usize::try_from(key_len).map_err(|_| PsbtError::InvalidCompactSize)?;
            let key_full = cur.take(key_len_usize)?;
            // Extract key_type and key_data
            let key_type = key_full[0];
            let key_data = &key_full[1..];

            if let Some(last) = pairs.last() {
                // Check for lexicographic ordering: first key_type then key_data
                if key_type < last.key_type
                    || (key_type == last.key_type && key_data < last.key_data)
                {
                    return Err(PsbtError::UnsortedKeys);
                }
                if key_type == last.key_type && key_data == last.key_data {
                    return Err(PsbtError::DuplicateKey);
                }
            }

            let value = cur.read_len_prefixed()?;
            let pair = MapPair {
                key_type,
                key_data,
                value,
            };
            f(&pair)?;
            pairs.push(pair);
        }
    }

    fn get(&self, key_type: u8, key_data: &[u8]) -> Option<&'a [u8]> {
        self.pairs
            .binary_search_by(|p| {
                p.key_type
                    .cmp(&key_type)
                    .then_with(|| p.key_data.cmp(key_data))
            })
            .ok()
            .map(|idx| self.pairs[idx].value)
    }

    /// Iterate over all pairs with the given key_type, in-order.
    fn iter_keys(&'a self, key_type: u8) -> core::slice::Iter<'a, MapPair<'a>> {
        let start = self.pairs.partition_point(|p| p.key_type < key_type);
        let end = start + self.pairs[start..].partition_point(|p| p.key_type == key_type);
        self.pairs[start..end].iter()
    }
}

impl<'a> Psbt<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, PsbtError> {
        const MAGIC: &[u8; 5] = b"psbt\xff";
        if raw.len() < MAGIC.len() || &raw[..5] != MAGIC {
            return Err(PsbtError::InvalidMagic);
        }
        let mut cur = Cursor::new(raw, MAGIC.len());

        let mut psbt_version = None::<u32>;
        let mut tx_version = None::<i32>;
        let mut fallback_locktime = None::<u32>;
        let mut n_inputs = None::<u64>;
        let mut n_outputs = None::<u64>;
        let mut tx_modifiable = None::<u8>;

        let global_map = ParsedMap::from_cursor(&mut cur, |pair: &MapPair| {
            if !pair.key_data.is_empty() {
                return Ok(());
            }
            match pair.key_type {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    return Err(PsbtError::NotAllowed);
                }
                PSBT_GLOBAL_TX_VERSION => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    tx_version = Some(i32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                PSBT_GLOBAL_FALLBACK_LOCKTIME => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    fallback_locktime = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                PSBT_GLOBAL_INPUT_COUNT => {
                    n_inputs = Some(u64_from_compact_size(pair.value)?);
                }
                PSBT_GLOBAL_OUTPUT_COUNT => {
                    n_outputs = Some(u64_from_compact_size(pair.value)?);
                }
                PSBT_GLOBAL_TX_MODIFIABLE => {
                    if pair.value.len() != 1 {
                        return Err(PsbtError::BadValue);
                    }
                    tx_modifiable = Some(pair.value[0]);
                }
                PSBT_GLOBAL_VERSION => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    psbt_version = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                _ => {}
            }
            Ok(())
        })?;

        let n_inputs = n_inputs.ok_or(PsbtError::MissingCounts)?;
        let n_outputs = n_outputs.ok_or(PsbtError::MissingCounts)?;

        let psbt_version = psbt_version.ok_or(PsbtError::MissingCounts)?;
        let tx_version = tx_version.ok_or(PsbtError::MissingCounts)?;

        if psbt_version != 2 {
            return Err(PsbtError::NotAllowed);
        }

        let inputs_count_usize =
            usize::try_from(n_inputs).map_err(|_| PsbtError::CountsTooLarge)?;
        let outputs_count_usize =
            usize::try_from(n_outputs).map_err(|_| PsbtError::CountsTooLarge)?;

        let inputs = (0..inputs_count_usize)
            .map(|_| Input::from_cursor(&mut cur))
            .collect::<Result<Vec<_>, _>>()?;

        let outputs = (0..outputs_count_usize)
            .map(|_| Output::from_cursor(&mut cur))
            .collect::<Result<Vec<_>, _>>()?;

        if cur.remaining() > 0 {
            return Err(PsbtError::UnexpectedEof);
        }

        Ok(Self {
            raw_psbt: raw,
            global_map,
            inputs,
            outputs,
            version: psbt_version,
            tx_version,
            fallback_locktime,
            tx_modifiable,
            cached_unsigned_tx: OnceCell::new(),
        })
    }

    fn get_global(&self, key_type: u8, key_data: &[u8]) -> Option<&'a [u8]> {
        self.global_map.get(key_type, key_data)
    }

    /// Iterate global map entries with a given key_type.
    pub fn iter_keys(&'a self, key_type: u8) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.global_map
            .iter_keys(key_type)
            .map(|p| (p.key_data, p.value))
    }

    pub fn unsigned_tx(&self) -> Result<&bitcoin::Transaction, PsbtError> {
        if let Some(tx) = self.cached_unsigned_tx.get() {
            return Ok(tx);
        }

        let tx = self.build_unsigned_tx()?;
        let _ = self.cached_unsigned_tx.set(tx);
        Ok(self.cached_unsigned_tx.get().unwrap())
    }

    fn build_unsigned_tx(&self) -> Result<bitcoin::Transaction, PsbtError> {
        // Determine lock_time
        let mut req_height: Option<u32> = None;
        let mut req_time: Option<u32> = None;

        for inp in &self.inputs {
            if let Some(h) = inp.required_height_locktime {
                req_height = Some(req_height.map_or(h, |m| m.max(h)));
            }
            if let Some(t) = inp.required_time_locktime {
                req_time = Some(req_time.map_or(t, |m| m.max(t)));
            }
        }

        // Both height- and time-based requirements cannot be satisfied together.
        if req_height.is_some() && req_time.is_some() {
            return Err(PsbtError::BadValue);
        }

        let mut lock_time: u32 = self.fallback_locktime.unwrap_or(0);

        if let Some(h) = req_height {
            if h >= 500_000_000 {
                return Err(PsbtError::BadValue);
            }
            lock_time = lock_time.max(h);
        }
        if let Some(t) = req_time {
            if t < 500_000_000 {
                return Err(PsbtError::BadValue);
            }
            lock_time = lock_time.max(t);
        }

        // Build inputs
        let mut ins = Vec::with_capacity(self.inputs.len());
        for inp in &self.inputs {
            let prev_txid_be = inp.previous_txid.ok_or(PsbtError::BadValue)?;
            let vout = inp.output_index.ok_or(PsbtError::BadValue)?;
            let txid = Txid::from_byte_array(*prev_txid_be);

            let seq_val = inp.sequence.unwrap_or(0xFFFF_FFFF);
            ins.push(TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(seq_val),
                witness: Witness::new(),
            });
        }

        // Build outputs
        let mut outs = Vec::with_capacity(self.outputs.len());
        for out in &self.outputs {
            let amt = Amount::from_sat(out.amount.ok_or(PsbtError::BadValue)?);
            let spk_bytes = out.script.ok_or(PsbtError::BadValue)?;
            outs.push(TxOut {
                value: amt,
                script_pubkey: ScriptBuf::from_bytes(spk_bytes.to_vec()),
            });
        }

        Ok(Transaction {
            version: Version(self.tx_version),
            lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
            input: ins,
            output: outs,
        })
    }

    fn spend_utxo(&self, input_index: usize) -> Result<TxOut, PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::OutOfRange);
        }

        let input = &self.inputs[input_index];
        if let Some(witness_utxo) = input.witness_utxo {
            if witness_utxo.len() < 8 + 1 {
                return Err(PsbtError::BadValue);
            }
            let script_len = witness_utxo[8] as usize;
            if script_len > 0xfc {
                return Err(PsbtError::BadValue);
            }
            if witness_utxo.len() != 8 + 1 + script_len {
                return Err(PsbtError::BadValue);
            }
            let script_pubkey = ScriptBuf::from_bytes(witness_utxo[9..9 + script_len].to_vec());
            let amount = Amount::from_sat(u64::from_le_bytes([
                witness_utxo[0],
                witness_utxo[1],
                witness_utxo[2],
                witness_utxo[3],
                witness_utxo[4],
                witness_utxo[5],
                witness_utxo[6],
                witness_utxo[7],
            ]));
            Ok(TxOut {
                value: amount,
                script_pubkey,
            })
        } else if let Some(non_witness_utxo) = input.non_witness_utxo {
            let non_witness_utxo: Transaction =
                deserialize(non_witness_utxo).map_err(|_| PsbtError::BadValue)?;
            let vout = input.output_index.ok_or(PsbtError::MissingOutputIndex)? as usize;
            if vout >= non_witness_utxo.output.len() {
                return Err(PsbtError::OutOfRange);
            }
            Ok(TxOut {
                value: non_witness_utxo.output[vout].value,
                script_pubkey: non_witness_utxo.output[vout].script_pubkey.clone(),
            })
        } else {
            Err(PsbtError::BadValue)
        }
    }

    // ported from rust-bitcoin
    pub fn sighash_ecdsa<T: Borrow<Transaction>>(
        &self,
        input_index: usize,
        cache: &mut SighashCache<T>,
    ) -> Result<(Message, EcdsaSighashType), PsbtError> {
        if input_index >= self.inputs.len() {
            return Err(PsbtError::OutOfRange);
        }

        let input = &self.inputs[input_index];
        let utxo = self.spend_utxo(input_index)?;
        let spk = &utxo.script_pubkey;

        let output_type = if !(spk.is_witness_program() || spk.is_p2sh()) {
            OutputType::Bare
        } else if spk.is_p2wpkh() {
            OutputType::Wpkh
        } else if spk.is_p2wsh() {
            OutputType::Wsh
        } else if spk.is_p2sh() {
            if input
                .redeem_script
                .as_ref()
                .map(|s| {
                    let s = ScriptBuf::from_bytes(s.to_vec());
                    s.is_p2wpkh()
                })
                .unwrap_or(false)
            {
                OutputType::ShWpkh
            } else if input
                .redeem_script
                .as_ref()
                .map(|s| {
                    let s = ScriptBuf::from_bytes(s.to_vec());
                    s.is_p2wsh()
                })
                .unwrap_or(false)
            {
                OutputType::ShWsh
            } else {
                OutputType::Sh
            }
        } else {
            return Err(PsbtError::UnknownOutputType);
        };

        let hash_ty = EcdsaSighashType::All; // TODO: compute correctly from the PSBT

        match output_type {
            OutputType::Bare => {
                let sighash = cache
                    .legacy_signature_hash(input_index, spk, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Sh => {
                let script_code = input
                    .redeem_script
                    .as_ref()
                    .ok_or(PsbtError::MissingRedeemScript)?;
                let script_code = ScriptBuf::from_bytes(script_code.to_vec());
                let sighash = cache
                    .legacy_signature_hash(input_index, &script_code, hash_ty.to_u32())
                    .expect("input checked above");
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Wpkh => {
                let sighash = cache
                    .p2wpkh_signature_hash(input_index, spk, utxo.value, hash_ty)
                    .map_err(|_| PsbtError::BadValue)?;
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::ShWpkh => {
                let redeem_script = input.redeem_script.as_ref().expect("checked above");
                let redeem_script = ScriptBuf::from_bytes(redeem_script.to_vec());
                let sighash = cache
                    .p2wpkh_signature_hash(input_index, &redeem_script, utxo.value, hash_ty)
                    .map_err(|_| PsbtError::BadValue)?;
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Wsh | OutputType::ShWsh => {
                let witness_script = input
                    .witness_script
                    .as_ref()
                    .ok_or(PsbtError::MissingWitnessScript)?;
                let witness_script = ScriptBuf::from_bytes(witness_script.to_vec());
                let sighash = cache
                    .p2wsh_signature_hash(input_index, &witness_script, utxo.value, hash_ty)
                    .map_err(|_| PsbtError::BadValue)?;
                Ok((Message::from(sighash), hash_ty))
            }
            OutputType::Tr => {
                Err(PsbtError::Unsupported) // different function for taproot sighash
            }
            _ => Err(PsbtError::Unsupported),
        }
    }
}

impl<'a> Input<'a> {
    fn from_cursor(cur: &mut Cursor<'a>) -> Result<Self, PsbtError> {
        let mut non_witness_utxo = None;
        let mut witness_utxo = None;
        let mut sighash_type = None;
        let mut redeem_script = None;
        let mut witness_script = None;
        let mut final_scriptsig = None;
        let mut final_scriptwitness = None;
        let mut previous_txid = None;
        let mut output_index = None;
        let mut sequence = None;
        let mut required_time_locktime = None;
        let mut required_height_locktime = None;

        let map = ParsedMap::from_cursor(cur, |pair: &MapPair| {
            if !pair.key_data.is_empty() {
                return Ok(());
            }
            match pair.key_type {
                PSBT_IN_NON_WITNESS_UTXO => {
                    non_witness_utxo = Some(pair.value);
                }
                PSBT_IN_WITNESS_UTXO => {
                    witness_utxo = Some(pair.value);
                }
                PSBT_IN_SIGHASH_TYPE => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    sighash_type = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                PSBT_IN_REDEEM_SCRIPT => {
                    redeem_script = Some(pair.value);
                }
                PSBT_IN_WITNESS_SCRIPT => {
                    witness_script = Some(pair.value);
                }
                PSBT_IN_FINAL_SCRIPTSIG => {
                    final_scriptsig = Some(pair.value);
                }
                PSBT_IN_FINAL_SCRIPTWITNESS => {
                    final_scriptwitness = Some(pair.value);
                }
                PSBT_IN_PREVIOUS_TXID => {
                    previous_txid = Some(pair.value.try_into().map_err(|_| PsbtError::BadValue)?);
                }
                PSBT_IN_OUTPUT_INDEX => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    output_index = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                PSBT_IN_SEQUENCE => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    sequence = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                PSBT_IN_REQUIRED_TIME_LOCKTIME => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    required_time_locktime = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                PSBT_IN_REQUIRED_HEIGHT_LOCKTIME => {
                    if pair.value.len() != 4 {
                        return Err(PsbtError::BadValue);
                    }
                    required_height_locktime = Some(u32::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                    ]));
                }
                _ => {}
            }
            Ok(())
        })?;

        Ok(Self {
            map,
            non_witness_utxo,
            witness_utxo,
            sighash_type,
            redeem_script,
            witness_script,
            final_scriptsig,
            final_scriptwitness,
            previous_txid,
            output_index,
            sequence,
            required_time_locktime,
            required_height_locktime,
            cached_witness_utxo: OnceCell::new(),
            cached_non_witness_utxo: OnceCell::new(),
        })
    }

    fn get(&self, key_type: u8, key_data: &[u8]) -> Option<&'a [u8]> {
        self.map.get(key_type, key_data)
    }

    /// Iterate this input's map entries with a given key_type.
    pub fn iter_keys(&'a self, key_type: u8) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.map.iter_keys(key_type).map(|p| (p.key_data, p.value))
    }

    pub fn bip32_derivations(&'a self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.iter_keys(PSBT_IN_BIP32_DERIVATION)
    }

    pub fn get_witness_utxo(&self) -> Result<Option<&bitcoin::TxOut>, PsbtError> {
        if let Some(txout) = self.cached_witness_utxo.get() {
            return Ok(Some(txout));
        }

        let Some(wutxo) = self.witness_utxo else {
            return Ok(None);
        };

        if wutxo.len() < 8 + 1 || wutxo[8] > 0xfc || wutxo.len() != 8 + 1 + wutxo[8] as usize {
            return Err(PsbtError::BadValue);
        }
        let script_len = wutxo[8] as usize;

        let script_pubkey = ScriptBuf::from_bytes(wutxo[9..9 + script_len].to_vec());
        let amount = Amount::from_sat(u64::from_le_bytes([
            wutxo[0], wutxo[1], wutxo[2], wutxo[3], wutxo[4], wutxo[5], wutxo[6], wutxo[7],
        ]));

        let txout = TxOut {
            value: amount,
            script_pubkey,
        };

        let _ = self.cached_witness_utxo.set(txout);

        Ok(self.cached_witness_utxo.get())
    }

    pub fn get_non_witness_utxo(&self) -> Result<Option<&bitcoin::Transaction>, PsbtError> {
        if let Some(tx) = self.cached_non_witness_utxo.get() {
            return Ok(Some(tx));
        }

        let Some(tx) = self.non_witness_utxo else {
            return Ok(None);
        };

        let tx: bitcoin::Transaction = deserialize(tx).map_err(|_| PsbtError::BadValue)?;

        let _ = self.cached_non_witness_utxo.set(tx);

        Ok(self.cached_non_witness_utxo.get())
    }
}

impl<'a> Output<'a> {
    fn from_cursor(cur: &mut Cursor<'a>) -> Result<Self, PsbtError> {
        let mut redeem_script = None;
        let mut witness_script = None;
        let mut amount = None;
        let mut script = None;

        let map = ParsedMap::from_cursor(cur, |pair: &MapPair| {
            if !pair.key_data.is_empty() {
                return Ok(());
            }
            match pair.key_type {
                PSBT_OUT_REDEEM_SCRIPT => {
                    redeem_script = Some(pair.value);
                }
                PSBT_OUT_WITNESS_SCRIPT => {
                    witness_script = Some(pair.value);
                }
                PSBT_OUT_AMOUNT => {
                    if pair.value.len() != 8 {
                        return Err(PsbtError::BadValue);
                    }
                    amount = Some(u64::from_le_bytes([
                        pair.value[0],
                        pair.value[1],
                        pair.value[2],
                        pair.value[3],
                        pair.value[4],
                        pair.value[5],
                        pair.value[6],
                        pair.value[7],
                    ]));
                }
                PSBT_OUT_SCRIPT => {
                    script = Some(pair.value);
                }
                _ => {}
            }
            Ok(())
        })?;

        Ok(Self {
            map,
            redeem_script,
            witness_script,
            amount,
            script,
        })
    }

    fn get(&self, key_type: u8, key_data: &[u8]) -> Option<&'a [u8]> {
        self.map.get(key_type, key_data)
    }

    /// Iterate this output's map entries with a given key_type.
    pub fn iter_keys(&'a self, key_type: u8) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.map.iter_keys(key_type).map(|p| (p.key_data, p.value))
    }

    pub fn bip32_derivations(&'a self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.iter_keys(PSBT_OUT_BIP32_DERIVATION)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use hex_literal::hex;

    const VALID_PSBT: &'static str = "cHNidP8BAgQBAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAP2qAgIAAAACi2Zf4OfqcC9dP65eJYTdm2lEN3xrnoEYNkv/hkQqOWYTAAAAUH9xQ+dl/v00udlaANFBQ8e8ZWi3c/8Z0+0VpGehUw6m+yXOnVtzCPM7aeSUm5QDs4ouBwzvGEwrHIOfJSApchGgqu0M+c6UDXq2s6RX1mHKAAAAABoOiW2ZTQbNg34JFFvnTHKomMgn83CJhxG7mIJ3naqVCAAAAFDB+Dkn1WRZaoy+4uHRa+OvMG/0njULECR32KQwLveX/e8envK98kFzGeZ7f3QRkTjFrNWwSMTpQdRQdhO/7Og6qIRCmBJklYV5Keo6+aRcnAAAAAAKvZcHBAAAAAAiACBUAxjw2HG6OrfLFbYssfGGedd7uQ+zRhDpUy9lVZgmv1RO9wEAAAAAIgAgROs//J4l9zteFJQLgPfThvlQ/EaW7zamDjUa3Igq+Hb+tocCAAAAACIAIJikAWfDfFJz8dDGRvcZ5wT3y1Rxzho0Od3mllEPlYHlg7sgAwAAAAAiACBKVGjcCkkC2NxgguZGk9rzzqAG8KBY5MzTFfm+vVslpmLu8gEAAAAAIgAgr00MjwnaUMATFIQXZuu42pFvDEw0gMQKjkCRRCCnwi/1HSQAAAAAACIAIGYb/o9UFORFY2ROJKcziKQglXIsJdPWagIspZ3IiT1UOzm1AAAAAAAiACDh0X20Ps51dozZHB3Fs5kY/UwQzayX3D5uW75jT0I0SiF1yAQAAAAAIgAgk2tug44aCowkvN3eHI++I/v09t1lg07puohUJaitMnN16CEDAAAAACIAIKbGDEP0Qq+vkN6BPg7+h5h35z69yxPiTLW6dDx0BGuNECcAAAAAAAAiACAF42YWI29NGW9kDAYPsBXblMbaRLXPydreRe16JcPvfAAAAAABASsQJwAAAAAAACIAIAXjZhYjb00Zb2QMBg+wFduUxtpEtc/J2t5F7Xolw+98AQX9AgFUIQMZ97fwu0jrNC0PAYtW3F2DKuKwotSdPQhAI5aJjIkX3iECgXFEyxMHM5/kW0j5cAhcvppwm0iVNC0Fe3lvaRephgghA7XkdUGcyWun5uDUQByg2S2bqORWXDxuK2KKYQ+PIGdmIQPlrYVplvzvvMn4/1grtQ6JaDh+heyYF/mFMSiAnIkpXFSuc2R2qRSj/+wHoZz/UbEtXd4ziK5a50dPZ4isa3apFP7rXJfetE6jrh2H1/pnvTTS4pioiKxsk2t2qRSBEa8aKbmTOe0oiDjtmteZdh0Hc4isbJNrdqkUZxd8DR1rcAF9hUGikKJCV3yzJ3uIrGyTU4gD//8AsmgiBgMHoiONlif9tR7i5AaLjW2skP3hhmCjInLZCdyGslZGLxz1rML9MAAAgAEAAIAAAACAAgAAgAMAAAAjHAAAIgYDGfe38LtI6zQtDwGLVtxdgyrisKLUnT0IQCOWiYyJF94c9azC/TAAAIABAACAAAAAgAIAAIABAAAAIxwAAAEOIFrwzTKgg6tMc9v7Q/I8V4WAgNcjaR/75ec1yAnDtAtKAQ8ECQAAAAEQBAAAAAAAAQMIiBMAAAAAAAABBCJRILP1RJnT7QOYUMrJAGMR3YGZOsBz2w6jZ/fU/kk6FV5CAAEB/QIBVCEDJ1HzCxSlPAsnEPz/7BEzGQp/cDWxHrGzIyfoq3QCelIhA12y7TUnW8SXC/9QR0lmIM5AOSop26+9vi4po5BfzrDnIQKF9obmSKLfpCvQbZldEYgbR8H581S9ce5gmuK52THdMiECdZrk4zzp+zP22COHZLNyMLzGa2FONuWb8gIenoo7+rNUrnNkdqkUwp8TsRTegg/yHxPtVxwoGIQ6tN6IrGt2qRTXAO9/18OwUIbq4mS4Y9JoTXEcuYisbJNrdqkUrGsPP+UzVcSq/gnU5Pxzggcj4zCIrGyTa3apFHL0P3AQrNVmKXhd6agGrlaPuZVMiKxsk1OIA///ALJoIgIC3Nt/ijs79Z4Sxy/3IXG/Rz7PixSMBIsbsi3ujO0QLSYc9azC/TAAAIABAACAAAAAgAIAAIADAAAANiAAACICAydR8wsUpTwLJxD8/+wRMxkKf3A1sR6xsyMn6Kt0AnpSHPWswv0wAACAAQAAgAAAAIACAACAAQAAADYgAAABAwiHEwAAAAAAAAEEIgAgg5JTVA1kaZh98aAl0gND0Fr+jtnDZcBgvzDG+qZirW0A";

    #[test]
    fn test_parse_psbt() {
        let psbt_bin = STANDARD.decode(&VALID_PSBT).unwrap();
        let psbt = Psbt::parse(&psbt_bin).unwrap();
        assert_eq!(psbt.raw_psbt, psbt_bin);
        assert_eq!(psbt.tx_version, 1);
        assert_eq!(psbt.fallback_locktime, Some(0));
        assert_eq!(psbt.tx_modifiable, None);

        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.inputs[0].non_witness_utxo, Some(&hex!("02000000028b665fe0e7ea702f5d3fae5e2584dd9b6944377c6b9e8118364bff86442a396613000000507f7143e765fefd34b9d95a00d14143c7bc6568b773ff19d3ed15a467a1530ea6fb25ce9d5b7308f33b69e4949b9403b38a2e070cef184c2b1c839f2520297211a0aaed0cf9ce940d7ab6b3a457d661ca000000001a0e896d994d06cd837e09145be74c72a898c827f370898711bb9882779daa950800000050c1f83927d564596a8cbee2e1d16be3af306ff49e350b102477d8a4302ef797fdef1e9ef2bdf2417319e67b7f74119138c5acd5b048c4e941d4507613bfece83aa8844298126495857929ea3af9a45c9c000000000abd97070400000000220020540318f0d871ba3ab7cb15b62cb1f18679d77bb90fb34610e9532f65559826bf544ef7010000000022002044eb3ffc9e25f73b5e14940b80f7d386f950fc4696ef36a60e351adc882af876feb687020000000022002098a40167c37c5273f1d0c646f719e704f7cb5471ce1a3439dde696510f9581e583bb2003000000002200204a5468dc0a4902d8dc6082e64693daf3cea006f0a058e4ccd315f9bebd5b25a662eef20100000000220020af4d0c8f09da50c01314841766ebb8da916f0c4c3480c40a8e40914420a7c22ff51d240000000000220020661bfe8f5414e44563644e24a73388a42095722c25d3d66a022ca59dc8893d543b39b50000000000220020e1d17db43ece75768cd91c1dc5b39918fd4c10cdac97dc3e6e5bbe634f42344a2175c80400000000220020936b6e838e1a0a8c24bcddde1c8fbe23fbf4f6dd65834ee9ba885425a8ad327375e8210300000000220020a6c60c43f442afaf90de813e0efe879877e73ebdcb13e24cb5ba743c74046b8d102700000000000022002005e36616236f4d196f640c060fb015db94c6da44b5cfc9dade45ed7a25c3ef7c00000000")[..]));
        assert_eq!(psbt.inputs[0].witness_utxo, Some(&hex!("102700000000000022002005e36616236f4d196f640c060fb015db94c6da44b5cfc9dade45ed7a25c3ef7c")[..]));
        assert_eq!(psbt.inputs[0].witness_script, Some(&hex!("54210319f7b7f0bb48eb342d0f018b56dc5d832ae2b0a2d49d3d08402396898c8917de2102817144cb1307339fe45b48f970085cbe9a709b4895342d057b796f6917a986082103b5e475419cc96ba7e6e0d4401ca0d92d9ba8e4565c3c6e2b628a610f8f2067662103e5ad856996fcefbcc9f8ff582bb50e8968387e85ec9817f9853128809c89295c54ae736476a914a3ffec07a19cff51b12d5dde3388ae5ae7474f6788ac6b76a914feeb5c97deb44ea3ae1d87d7fa67bd34d2e298a888ac6c936b76a9148111af1a29b99339ed288838ed9ad799761d077388ac6c936b76a91467177c0d1d6b70017d8541a290a242577cb3277b88ac6c93538803ffff00b268")[..]));
        assert_eq!(
            psbt.inputs[0].previous_txid,
            Some(&hex!(
                "5af0cd32a083ab4c73dbfb43f23c57858080d723691ffbe5e735c809c3b40b4a"
            ))
        );
        assert_eq!(psbt.inputs[0].output_index, Some(9));
        assert_eq!(psbt.inputs[0].final_scriptsig, None);
        assert_eq!(psbt.inputs[0].final_scriptwitness, None);
        assert_eq!(psbt.inputs[0].sequence, Some(0));

        assert_eq!(psbt.outputs.len(), 2);
        assert_eq!(psbt.outputs[0].amount, Some(5000));
        assert_eq!(
            psbt.outputs[0].script,
            Some(&hex!("5120b3f54499d3ed039850cac9006311dd81993ac073db0ea367f7d4fe493a155e42")[..])
        );
        assert_eq!(psbt.outputs[0].redeem_script, None);
        assert_eq!(psbt.outputs[1].amount, Some(4999));
        assert_eq!(
            psbt.outputs[1].script,
            Some(&hex!("0020839253540d6469987df1a025d20343d05afe8ed9c365c060bf30c6faa662ad6d")[..])
        );
        assert_eq!(psbt.outputs[1].redeem_script, None);
        assert_eq!(
            psbt.outputs[1].witness_script,
            Some(&hex!("5421032751f30b14a53c0b2710fcffec1133190a7f7035b11eb1b32327e8ab74027a5221035db2ed35275bc4970bff5047496620ce40392a29dbafbdbe2e29a3905fceb0e7210285f686e648a2dfa42bd06d995d11881b47c1f9f354bd71ee609ae2b9d931dd322102759ae4e33ce9fb33f6d8238764b37230bcc66b614e36e59bf2021e9e8a3bfab354ae736476a914c29f13b114de820ff21f13ed571c2818843ab4de88ac6b76a914d700ef7fd7c3b05086eae264b863d2684d711cb988ac6c936b76a914ac6b0f3fe53355c4aafe09d4e4fc73820723e33088ac6c936b76a91472f43f7010acd56629785de9a806ae568fb9954c88ac6c93538803ffff00b268")[..])
        );

        let bip32_derivations = psbt.inputs[0].bip32_derivations().collect::<Vec<_>>();
        assert_eq!(bip32_derivations.len(), 2);
        assert_eq!(
            bip32_derivations[0],
            (
                &hex!("0307a2238d9627fdb51ee2e4068b8d6dac90fde18660a32272d909dc86b256462f")[..],
                &hex!("f5acc2fd3000008001000080000000800200008003000000231c0000")[..]
            )
        );
        assert_eq!(
            bip32_derivations[1],
            (
                &hex!("0319f7b7f0bb48eb342d0f018b56dc5d832ae2b0a2d49d3d08402396898c8917de")[..],
                &hex!("f5acc2fd3000008001000080000000800200008001000000231c0000")[..]
            )
        );
    }

    // TODO: add other missing fields
}
