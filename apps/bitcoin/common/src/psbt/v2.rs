//! A PSBTv2 that the host can read and edit, field by field.
//!
//! rust-bitcoin only supports PSBTv0, whose outputs come from the unsigned transaction: it can't
//! hold an output without a script, like a silent payment output before a signer computes its
//! script. This editor works on the maps of the PSBT instead, and only decodes the few fields that
//! the host reads. Its maps are always serialized sorted by key, as [`fastpsbt`](crate::fastpsbt)
//! requires.

use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::{Deref, DerefMut};

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Fingerprint},
    consensus::{deserialize, encode::VarInt, Decodable, Encodable},
    hashes::Hash,
    ScriptBuf, Transaction, TxOut,
};

use super::{
    parse_proprietary_key_data, GlobalHasProprietaryFields, InputHasProprietaryFields,
    OutputHasProprietaryFields, ProprietaryEntry,
};
use crate::fastpsbt::*;

const MAGIC: &[u8; 5] = b"psbt\xff";

/// The key type of proprietary fields, in every map.
const PROPRIETARY: u8 = 0xFC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtV2Error {
    /// The data doesn't start with the magic bytes of a PSBT.
    InvalidMagic,
    /// The data is truncated, has a non-canonical compact size, or goes on after the last map.
    InvalidEncoding,
    /// A map has the same key twice.
    DuplicateKey,
    /// Not a PSBT of the expected version, or a PSBTv0 that has fields of PSBTv2.
    InvalidVersion,
    /// A field is missing or has an invalid value.
    InvalidField,
}

fn read_compact_size(data: &mut &[u8]) -> Result<u64, PsbtV2Error> {
    Ok(VarInt::consensus_decode(data)
        .map_err(|_| PsbtV2Error::InvalidEncoding)?
        .0)
}

fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    VarInt(n)
        .consensus_encode(out)
        .expect("writing to a Vec doesn't fail");
}

fn compact_size(n: u64) -> Vec<u8> {
    let mut res = Vec::new();
    write_compact_size(&mut res, n);
    res
}

fn read_bytes<'a>(data: &mut &'a [u8]) -> Result<&'a [u8], PsbtV2Error> {
    let len =
        usize::try_from(read_compact_size(data)?).map_err(|_| PsbtV2Error::InvalidEncoding)?;
    if data.len() < len {
        return Err(PsbtV2Error::InvalidEncoding);
    }
    let (res, rest) = data.split_at(len);
    *data = rest;
    Ok(res)
}

/// A map of a PSBT: values by key, where a key is a key type followed by key data.
///
/// Key types are single bytes: compact sizes of 0xFD and above aren't used by any field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Map(BTreeMap<Vec<u8>, Vec<u8>>);

impl Map {
    fn key(key_type: u8, key_data: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + key_data.len());
        key.push(key_type);
        key.extend_from_slice(key_data);
        key
    }

    pub fn get(&self, key_type: u8, key_data: &[u8]) -> Option<&[u8]> {
        self.0
            .get(&Self::key(key_type, key_data))
            .map(|v| v.as_slice())
    }

    /// Sets the value of a key, and returns its previous value.
    pub fn insert(&mut self, key_type: u8, key_data: &[u8], value: Vec<u8>) -> Option<Vec<u8>> {
        self.0.insert(Self::key(key_type, key_data), value)
    }

    /// Removes a key, and returns its value.
    pub fn remove(&mut self, key_type: u8, key_data: &[u8]) -> Option<Vec<u8>> {
        self.0.remove(&Self::key(key_type, key_data))
    }

    /// The key data and the value of each entry of type `key_type`, sorted by key data.
    pub fn iter_type(&self, key_type: u8) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.0
            .range(Self::key(key_type, &[])..)
            .take_while(move |(key, _)| key[0] == key_type)
            .map(|(key, value)| (&key[1..], value.as_slice()))
    }

    /// Sets the value of the proprietary key with identifier `prefix`, subtype `subtype` and key
    /// data `key`.
    pub fn insert_proprietary(&mut self, prefix: &[u8], subtype: u8, key: &[u8], value: Vec<u8>) {
        let mut key_data = compact_size(prefix.len() as u64);
        key_data.extend_from_slice(prefix);
        key_data.push(subtype);
        key_data.extend_from_slice(key);
        self.insert(PROPRIETARY, &key_data, value);
    }

    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.iter_type(PROPRIETARY)
            .filter_map(|(key_data, value)| parse_proprietary_key_data(key_data, value))
    }

    fn read(data: &mut &[u8]) -> Result<Self, PsbtV2Error> {
        let mut map = BTreeMap::new();
        loop {
            let key = read_bytes(data)?;
            if key.is_empty() {
                return Ok(Self(map));
            }
            let value = read_bytes(data)?;
            if map.insert(key.to_vec(), value.to_vec()).is_some() {
                return Err(PsbtV2Error::DuplicateKey);
            }
        }
    }

    fn write(&self, out: &mut Vec<u8>) {
        for (key, value) in &self.0 {
            write_compact_size(out, key.len() as u64);
            out.extend_from_slice(key);
            write_compact_size(out, value.len() as u64);
            out.extend_from_slice(value);
        }
        out.push(0x00);
    }
}

/// Decodes a key origin: a fingerprint, then the steps of the path, little-endian.
fn decode_key_origin(value: &[u8]) -> Result<(Fingerprint, DerivationPath), PsbtV2Error> {
    if value.len() < 4 || value.len() % 4 != 0 {
        return Err(PsbtV2Error::InvalidField);
    }
    let fingerprint = Fingerprint::from(<[u8; 4]>::try_from(&value[..4]).unwrap());
    let path: Vec<ChildNumber> = value[4..]
        .chunks_exact(4)
        .map(|step| ChildNumber::from(u32::from_le_bytes(step.try_into().unwrap())))
        .collect();
    Ok((fingerprint, path.into()))
}

/// The key origins of the BIP-32 derivations of a map, then of its taproot BIP-32 derivations,
/// whose values start with leaf hashes.
fn key_origins(
    map: &Map,
    bip32_key_type: u8,
    tap_bip32_key_type: u8,
) -> Result<Vec<(Fingerprint, DerivationPath)>, PsbtV2Error> {
    let mut res = Vec::new();
    for (_, value) in map.iter_type(bip32_key_type) {
        res.push(decode_key_origin(value)?);
    }
    for (_, mut value) in map.iter_type(tap_bip32_key_type) {
        let n_leaf_hashes = read_compact_size(&mut value)?;
        let origin = usize::try_from(n_leaf_hashes)
            .ok()
            .and_then(|n| n.checked_mul(32))
            .and_then(|len| value.get(len..))
            .ok_or(PsbtV2Error::InvalidField)?;
        res.push(decode_key_origin(origin)?);
    }
    Ok(res)
}

/// Decodes the unsigned transaction of a PSBTv0, which is serialized without witnesses: decoded
/// as usual, a transaction without inputs would look like the start of a segwit serialization.
/// Its scriptSigs must be empty.
fn decode_unsigned_tx(raw: &[u8]) -> Result<Transaction, PsbtV2Error> {
    let mut data = raw;
    let decode = |data: &mut &[u8]| -> Result<Transaction, bitcoin::consensus::encode::Error> {
        Ok(Transaction {
            version: Decodable::consensus_decode(data)?,
            input: Decodable::consensus_decode(data)?,
            output: Decodable::consensus_decode(data)?,
            lock_time: Decodable::consensus_decode(data)?,
        })
    };
    let tx = decode(&mut data).map_err(|_| PsbtV2Error::InvalidField)?;
    if !data.is_empty() || tx.input.iter().any(|txin| !txin.script_sig.is_empty()) {
        return Err(PsbtV2Error::InvalidField);
    }
    Ok(tx)
}

/// The map of an input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input(pub Map);

impl Deref for Input {
    type Target = Map;
    fn deref(&self) -> &Map {
        &self.0
    }
}

impl DerefMut for Input {
    fn deref_mut(&mut self) -> &mut Map {
        &mut self.0
    }
}

impl Input {
    /// The script of the output that this input spends: from its witness UTXO if it has one, or
    /// else from its non-witness UTXO.
    pub fn spent_script(&self) -> Result<Option<ScriptBuf>, PsbtV2Error> {
        if let Some(value) = self.get(PSBT_IN_WITNESS_UTXO, &[]) {
            let utxo: TxOut = deserialize(value).map_err(|_| PsbtV2Error::InvalidField)?;
            return Ok(Some(utxo.script_pubkey));
        }
        let Some(value) = self.get(PSBT_IN_NON_WITNESS_UTXO, &[]) else {
            return Ok(None);
        };
        let tx: Transaction = deserialize(value).map_err(|_| PsbtV2Error::InvalidField)?;
        let index = self
            .get(PSBT_IN_OUTPUT_INDEX, &[])
            .and_then(|value| <[u8; 4]>::try_from(value).ok())
            .ok_or(PsbtV2Error::InvalidField)?;
        let utxo = tx
            .output
            .into_iter()
            .nth(u32::from_le_bytes(index) as usize)
            .ok_or(PsbtV2Error::InvalidField)?;
        Ok(Some(utxo.script_pubkey))
    }

    /// The key origins of the keys of this input, from `PSBT_IN_BIP32_DERIVATION` and
    /// `PSBT_IN_TAP_BIP32_DERIVATION`.
    pub fn key_origins(&self) -> Result<Vec<(Fingerprint, DerivationPath)>, PsbtV2Error> {
        key_origins(self, PSBT_IN_BIP32_DERIVATION, PSBT_IN_TAP_BIP32_DERIVATION)
    }
}

/// The map of an output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output(pub Map);

impl Deref for Output {
    type Target = Map;
    fn deref(&self) -> &Map {
        &self.0
    }
}

impl DerefMut for Output {
    fn deref_mut(&mut self) -> &mut Map {
        &mut self.0
    }
}

impl Output {
    /// The script of this output, if it has one.
    pub fn script(&self) -> Option<ScriptBuf> {
        self.get(PSBT_OUT_SCRIPT, &[])
            .map(|script| ScriptBuf::from_bytes(script.to_vec()))
    }

    /// The key origins of the keys of this output, from `PSBT_OUT_BIP32_DERIVATION` and
    /// `PSBT_OUT_TAP_BIP32_DERIVATION`.
    pub fn key_origins(&self) -> Result<Vec<(Fingerprint, DerivationPath)>, PsbtV2Error> {
        key_origins(
            self,
            PSBT_OUT_BIP32_DERIVATION,
            PSBT_OUT_TAP_BIP32_DERIVATION,
        )
    }
}

/// A PSBTv2 (BIP-370).
///
/// The global map has no `PSBT_GLOBAL_INPUT_COUNT` and `PSBT_GLOBAL_OUTPUT_COUNT`: they are the
/// numbers of `inputs` and `outputs`, and are only added when serializing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsbtV2 {
    pub global: Map,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl PsbtV2 {
    /// Parses a PSBTv2. Its maps don't need to be sorted.
    pub fn parse(raw: &[u8]) -> Result<Self, PsbtV2Error> {
        let mut data = raw.strip_prefix(MAGIC).ok_or(PsbtV2Error::InvalidMagic)?;
        let mut global = Map::read(&mut data)?;
        if global.get(PSBT_GLOBAL_VERSION, &[]) != Some(&2u32.to_le_bytes())
            || global.get(PSBT_GLOBAL_UNSIGNED_TX, &[]).is_some()
        {
            return Err(PsbtV2Error::InvalidVersion);
        }
        let mut take_count = |key_type| -> Result<u64, PsbtV2Error> {
            let value = global
                .remove(key_type, &[])
                .ok_or(PsbtV2Error::InvalidField)?;
            let mut value = value.as_slice();
            let count = read_compact_size(&mut value).map_err(|_| PsbtV2Error::InvalidField)?;
            if !value.is_empty() {
                return Err(PsbtV2Error::InvalidField);
            }
            Ok(count)
        };
        let n_inputs = take_count(PSBT_GLOBAL_INPUT_COUNT)?;
        let n_outputs = take_count(PSBT_GLOBAL_OUTPUT_COUNT)?;

        let inputs = (0..n_inputs)
            .map(|_| Map::read(&mut data).map(Input))
            .collect::<Result<_, _>>()?;
        let outputs = (0..n_outputs)
            .map(|_| Map::read(&mut data).map(Output))
            .collect::<Result<_, _>>()?;
        if !data.is_empty() {
            return Err(PsbtV2Error::InvalidEncoding);
        }
        Ok(Self {
            global,
            inputs,
            outputs,
        })
    }

    /// Converts a PSBTv0 (BIP-174): the fields of its unsigned transaction move to the fields of
    /// PSBTv2, and all the other fields are kept as they are.
    pub fn from_v0(raw: &[u8]) -> Result<Self, PsbtV2Error> {
        let mut data = raw.strip_prefix(MAGIC).ok_or(PsbtV2Error::InvalidMagic)?;
        let mut global = Map::read(&mut data)?;
        let tx = global
            .remove(PSBT_GLOBAL_UNSIGNED_TX, &[])
            .ok_or(PsbtV2Error::InvalidField)
            .and_then(|tx| decode_unsigned_tx(&tx))?;
        let v2_only = [
            PSBT_GLOBAL_TX_VERSION,
            PSBT_GLOBAL_FALLBACK_LOCKTIME,
            PSBT_GLOBAL_INPUT_COUNT,
            PSBT_GLOBAL_OUTPUT_COUNT,
            PSBT_GLOBAL_TX_MODIFIABLE,
        ];
        if v2_only
            .iter()
            .any(|&key_type| global.iter_type(key_type).next().is_some())
        {
            return Err(PsbtV2Error::InvalidVersion);
        }
        if global
            .get(PSBT_GLOBAL_VERSION, &[])
            .is_some_and(|version| version != 0u32.to_le_bytes())
        {
            return Err(PsbtV2Error::InvalidVersion);
        }
        global.insert(PSBT_GLOBAL_VERSION, &[], 2u32.to_le_bytes().to_vec());
        global.insert(
            PSBT_GLOBAL_TX_VERSION,
            &[],
            tx.version.0.to_le_bytes().to_vec(),
        );
        global.insert(
            PSBT_GLOBAL_FALLBACK_LOCKTIME,
            &[],
            tx.lock_time.to_consensus_u32().to_le_bytes().to_vec(),
        );

        // the fields of PSBTv2 must not be in a PSBTv0 already
        let set = |map: &mut Map, key_type, value: Vec<u8>| match map.insert(key_type, &[], value) {
            Some(_) => Err(PsbtV2Error::InvalidVersion),
            None => Ok(()),
        };
        let mut inputs = Vec::with_capacity(tx.input.len());
        for txin in &tx.input {
            let mut input = Input(Map::read(&mut data)?);
            let outpoint = txin.previous_output;
            set(
                &mut input,
                PSBT_IN_PREVIOUS_TXID,
                outpoint.txid.to_byte_array().to_vec(),
            )?;
            set(
                &mut input,
                PSBT_IN_OUTPUT_INDEX,
                outpoint.vout.to_le_bytes().to_vec(),
            )?;
            set(
                &mut input,
                PSBT_IN_SEQUENCE,
                txin.sequence.0.to_le_bytes().to_vec(),
            )?;
            inputs.push(input);
        }
        let mut outputs = Vec::with_capacity(tx.output.len());
        for txout in &tx.output {
            let mut output = Output(Map::read(&mut data)?);
            set(
                &mut output,
                PSBT_OUT_AMOUNT,
                txout.value.to_sat().to_le_bytes().to_vec(),
            )?;
            set(&mut output, PSBT_OUT_SCRIPT, txout.script_pubkey.to_bytes())?;
            outputs.push(output);
        }
        if !data.is_empty() {
            return Err(PsbtV2Error::InvalidEncoding);
        }
        Ok(Self {
            global,
            inputs,
            outputs,
        })
    }

    /// Serializes the PSBT, with each map sorted by key.
    pub fn serialize(&self) -> Vec<u8> {
        let mut global = self.global.clone();
        global.insert(
            PSBT_GLOBAL_INPUT_COUNT,
            &[],
            compact_size(self.inputs.len() as u64),
        );
        global.insert(
            PSBT_GLOBAL_OUTPUT_COUNT,
            &[],
            compact_size(self.outputs.len() as u64),
        );

        let mut res = MAGIC.to_vec();
        global.write(&mut res);
        for input in &self.inputs {
            input.write(&mut res);
        }
        for output in &self.outputs {
            output.write(&mut res);
        }
        res
    }
}

impl GlobalHasProprietaryFields for PsbtV2 {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.global.iter_proprietary()
    }
}

impl InputHasProprietaryFields for Input {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.0.iter_proprietary()
    }
}

impl OutputHasProprietaryFields for Output {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.0.iter_proprietary()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use bitcoin::{
        bip32::KeySource,
        psbt::{raw, Psbt},
        secp256k1::{PublicKey, XOnlyPublicKey},
        Amount, TapLeafHash,
    };
    use hex_literal::hex;

    use super::*;
    use crate::fastpsbt;

    const PSBT_V0: &str = "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";
    const PSBT_V2: &str = "cHNidP8BAgQBAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABAP2qAgIAAAACi2Zf4OfqcC9dP65eJYTdm2lEN3xrnoEYNkv/hkQqOWYTAAAAUH9xQ+dl/v00udlaANFBQ8e8ZWi3c/8Z0+0VpGehUw6m+yXOnVtzCPM7aeSUm5QDs4ouBwzvGEwrHIOfJSApchGgqu0M+c6UDXq2s6RX1mHKAAAAABoOiW2ZTQbNg34JFFvnTHKomMgn83CJhxG7mIJ3naqVCAAAAFDB+Dkn1WRZaoy+4uHRa+OvMG/0njULECR32KQwLveX/e8envK98kFzGeZ7f3QRkTjFrNWwSMTpQdRQdhO/7Og6qIRCmBJklYV5Keo6+aRcnAAAAAAKvZcHBAAAAAAiACBUAxjw2HG6OrfLFbYssfGGedd7uQ+zRhDpUy9lVZgmv1RO9wEAAAAAIgAgROs//J4l9zteFJQLgPfThvlQ/EaW7zamDjUa3Igq+Hb+tocCAAAAACIAIJikAWfDfFJz8dDGRvcZ5wT3y1Rxzho0Od3mllEPlYHlg7sgAwAAAAAiACBKVGjcCkkC2NxgguZGk9rzzqAG8KBY5MzTFfm+vVslpmLu8gEAAAAAIgAgr00MjwnaUMATFIQXZuu42pFvDEw0gMQKjkCRRCCnwi/1HSQAAAAAACIAIGYb/o9UFORFY2ROJKcziKQglXIsJdPWagIspZ3IiT1UOzm1AAAAAAAiACDh0X20Ps51dozZHB3Fs5kY/UwQzayX3D5uW75jT0I0SiF1yAQAAAAAIgAgk2tug44aCowkvN3eHI++I/v09t1lg07puohUJaitMnN16CEDAAAAACIAIKbGDEP0Qq+vkN6BPg7+h5h35z69yxPiTLW6dDx0BGuNECcAAAAAAAAiACAF42YWI29NGW9kDAYPsBXblMbaRLXPydreRe16JcPvfAAAAAABASsQJwAAAAAAACIAIAXjZhYjb00Zb2QMBg+wFduUxtpEtc/J2t5F7Xolw+98AQX9AgFUIQMZ97fwu0jrNC0PAYtW3F2DKuKwotSdPQhAI5aJjIkX3iECgXFEyxMHM5/kW0j5cAhcvppwm0iVNC0Fe3lvaRephgghA7XkdUGcyWun5uDUQByg2S2bqORWXDxuK2KKYQ+PIGdmIQPlrYVplvzvvMn4/1grtQ6JaDh+heyYF/mFMSiAnIkpXFSuc2R2qRSj/+wHoZz/UbEtXd4ziK5a50dPZ4isa3apFP7rXJfetE6jrh2H1/pnvTTS4pioiKxsk2t2qRSBEa8aKbmTOe0oiDjtmteZdh0Hc4isbJNrdqkUZxd8DR1rcAF9hUGikKJCV3yzJ3uIrGyTU4gD//8AsmgiBgMHoiONlif9tR7i5AaLjW2skP3hhmCjInLZCdyGslZGLxz1rML9MAAAgAEAAIAAAACAAgAAgAMAAAAjHAAAIgYDGfe38LtI6zQtDwGLVtxdgyrisKLUnT0IQCOWiYyJF94c9azC/TAAAIABAACAAAAAgAIAAIABAAAAIxwAAAEOIFrwzTKgg6tMc9v7Q/I8V4WAgNcjaR/75ec1yAnDtAtKAQ8ECQAAAAEQBAAAAAAAAQMIiBMAAAAAAAABBCJRILP1RJnT7QOYUMrJAGMR3YGZOsBz2w6jZ/fU/kk6FV5CAAEB/QIBVCEDJ1HzCxSlPAsnEPz/7BEzGQp/cDWxHrGzIyfoq3QCelIhA12y7TUnW8SXC/9QR0lmIM5AOSop26+9vi4po5BfzrDnIQKF9obmSKLfpCvQbZldEYgbR8H581S9ce5gmuK52THdMiECdZrk4zzp+zP22COHZLNyMLzGa2FONuWb8gIenoo7+rNUrnNkdqkUwp8TsRTegg/yHxPtVxwoGIQ6tN6IrGt2qRTXAO9/18OwUIbq4mS4Y9JoTXEcuYisbJNrdqkUrGsPP+UzVcSq/gnU5Pxzggcj4zCIrGyTa3apFHL0P3AQrNVmKXhd6agGrlaPuZVMiKxsk1OIA///ALJoIgIC3Nt/ijs79Z4Sxy/3IXG/Rz7PixSMBIsbsi3ujO0QLSYc9azC/TAAAIABAACAAAAAgAIAAIADAAAANiAAACICAydR8wsUpTwLJxD8/+wRMxkKf3A1sR6xsyMn6Kt0AnpSHPWswv0wAACAAQAAgAAAAIACAACAAQAAADYgAAABAwiHEwAAAAAAAAEEIgAgg5JTVA1kaZh98aAl0gND0Fr+jtnDZcBgvzDG+qZirW0A";

    const KEY: [u8; 33] =
        hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    fn decode(psbt: &str) -> Vec<u8> {
        STANDARD.decode(psbt).unwrap()
    }

    /// A PSBTv0 with one input and one output, both without fields.
    fn psbt_v0() -> Psbt {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        Psbt::from_unsigned_tx(tx).unwrap()
    }

    #[test]
    fn from_v0() {
        let psbt = PsbtV2::from_v0(&decode(PSBT_V0)).unwrap();
        assert_eq!(psbt.serialize(), decode(PSBT_V2));
        assert_eq!(PsbtV2::parse(&decode(PSBT_V2)).unwrap(), psbt);

        // without inputs, the unsigned transaction must not be mistaken for a segwit one
        let mut psbt = psbt_v0();
        psbt.unsigned_tx.input.clear();
        psbt.inputs.clear();
        let psbt = PsbtV2::from_v0(&psbt.serialize()).unwrap();
        assert_eq!((psbt.inputs.len(), psbt.outputs.len()), (0, 1));
    }

    #[test]
    fn from_v0_rejects_v2_fields() {
        let mut psbt = psbt_v0();
        assert!(PsbtV2::from_v0(&psbt.serialize()).is_ok());

        psbt.inputs[0].unknown.insert(
            raw::Key {
                type_value: PSBT_IN_SEQUENCE,
                key: vec![],
            },
            vec![0; 4],
        );
        assert_eq!(
            PsbtV2::from_v0(&psbt.serialize()),
            Err(PsbtV2Error::InvalidVersion)
        );
        assert_eq!(
            PsbtV2::from_v0(&decode(PSBT_V2)),
            Err(PsbtV2Error::InvalidField)
        );
    }

    #[test]
    fn from_v0_rejects_script_sigs() {
        let mut psbt = psbt_v0();
        psbt.unsigned_tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        assert_eq!(
            PsbtV2::from_v0(&psbt.serialize()),
            Err(PsbtV2Error::InvalidField)
        );
    }

    #[test]
    fn parse_rejects_invalid_psbts() {
        let raw = decode(PSBT_V2);
        assert_eq!(PsbtV2::parse(&raw[1..]), Err(PsbtV2Error::InvalidMagic));
        assert_eq!(
            PsbtV2::parse(&raw[..raw.len() - 1]),
            Err(PsbtV2Error::InvalidEncoding)
        );
        assert_eq!(
            PsbtV2::parse(&[&raw[..], &[0]].concat()),
            Err(PsbtV2Error::InvalidEncoding)
        );
        assert_eq!(
            PsbtV2::parse(&decode(PSBT_V0)),
            Err(PsbtV2Error::InvalidVersion)
        );

        // a key twice: the version, right after the magic
        let version = [&[1, PSBT_GLOBAL_VERSION, 4][..], &2u32.to_le_bytes()].concat();
        let twice = [&raw[..5], &version, &version, &raw[5..]].concat();
        assert_eq!(PsbtV2::parse(&twice), Err(PsbtV2Error::DuplicateKey));

        // no input count
        let mut psbt = PsbtV2::parse(&raw).unwrap();
        psbt.global
            .insert(PSBT_GLOBAL_VERSION, &[], 2u32.to_le_bytes().to_vec());
        let mut global = Vec::new();
        psbt.global.write(&mut global);
        assert_eq!(
            PsbtV2::parse(&[&MAGIC[..], &global].concat()),
            Err(PsbtV2Error::InvalidField)
        );
    }

    #[test]
    fn edits_serialize_sorted() {
        let mut psbt = PsbtV2::from_v0(&psbt_v0().serialize()).unwrap();
        // a silent payment output: no script, but a silent payment code
        let output = &mut psbt.outputs[0];
        assert!(output.remove(PSBT_OUT_SCRIPT, &[]).is_some());
        output.insert(PSBT_OUT_SP_V0_INFO, &[], [KEY, KEY].concat());
        output.insert_proprietary(b"TEST", 1, &[2], vec![3]);
        output.insert(PSBT_OUT_BIP32_DERIVATION, &KEY, vec![0; 4]);
        assert_eq!(
            output.get(PSBT_OUT_SP_V0_INFO, &[]).map(|v| v.len()),
            Some(66)
        );
        assert_eq!(output.script(), None);

        let raw = psbt.serialize();
        let parsed = fastpsbt::Psbt::parse(&raw).unwrap();
        assert_eq!(parsed.outputs[0].script, None);
        assert_eq!(
            parsed.outputs[0].sp_v0_info.map(|info| &info[..]),
            Some(&[KEY, KEY].concat()[..])
        );
        let entry = parsed.outputs[0].iter_proprietary().next().unwrap();
        assert_eq!(
            (entry.prefix, entry.subtype, entry.key, entry.value),
            (&b"TEST"[..], 1, &[2][..], &[3][..])
        );
        assert_eq!(PsbtV2::parse(&raw).unwrap(), psbt);
    }

    #[test]
    fn proprietary_keys_read_back() {
        // identifiers of 253 bytes and more have a length of several bytes
        for prefix in [vec![], vec![b'A'; 252], vec![b'A'; 253]] {
            let mut map = Map::default();
            map.insert_proprietary(&prefix, 1, &[2, 3], vec![4]);
            let entries: Vec<_> = map
                .iter_proprietary()
                .map(|entry| (entry.prefix, entry.subtype, entry.key, entry.value))
                .collect();
            assert_eq!(entries, [(&prefix[..], 1, &[2, 3][..], &[4][..])]);
        }
    }

    #[test]
    fn iter_type() {
        let mut map = Map::default();
        map.insert(1, &[2], vec![]);
        map.insert(2, &[], vec![1]);
        map.insert(2, &[1], vec![2]);
        map.insert(3, &[], vec![]);
        assert_eq!(
            map.iter_type(2).collect::<Vec<_>>(),
            [(&[][..], &[1][..]), (&[1][..], &[2][..])]
        );
        assert_eq!(map.iter_type(4).count(), 0);
    }

    #[test]
    fn key_origins_and_scripts() {
        let origin = |fingerprint: [u8; 4], path: &str| -> KeySource {
            (Fingerprint::from(fingerprint), path.parse().unwrap())
        };
        let mut psbt = psbt_v0();
        let input = &mut psbt.inputs[0];
        input.bip32_derivation.insert(
            PublicKey::from_slice(&KEY).unwrap(),
            origin([1; 4], "m/0/1"),
        );
        let leaf_hash = TapLeafHash::from_byte_array([7; 32]);
        input.tap_key_origins.insert(
            XOnlyPublicKey::from_slice(&KEY[1..]).unwrap(),
            (vec![leaf_hash], origin([2; 4], "m/1'/2")),
        );
        let utxo = TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
        };
        input.witness_utxo = Some(utxo.clone());
        psbt.outputs[0].tap_key_origins.insert(
            XOnlyPublicKey::from_slice(&KEY[1..]).unwrap(),
            (vec![], origin([3; 4], "m")),
        );

        let mut psbt = PsbtV2::from_v0(&psbt.serialize()).unwrap();
        assert_eq!(
            psbt.inputs[0].key_origins().unwrap(),
            [origin([1; 4], "m/0/1"), origin([2; 4], "m/1'/2")]
        );
        assert_eq!(
            psbt.inputs[0].spent_script().unwrap(),
            Some(utxo.script_pubkey.clone())
        );
        assert_eq!(
            psbt.outputs[0].key_origins().unwrap(),
            [origin([3; 4], "m")]
        );
        assert_eq!(
            psbt.outputs[0].script(),
            Some(ScriptBuf::from_bytes(vec![0x51]))
        );

        // the spent script, from the non-witness UTXO
        let input = &mut psbt.inputs[0];
        input.remove(PSBT_IN_WITNESS_UTXO, &[]);
        assert_eq!(input.spent_script().unwrap(), None);
        let funding = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut::NULL, utxo.clone()],
        };
        input.insert(
            PSBT_IN_NON_WITNESS_UTXO,
            &[],
            bitcoin::consensus::serialize(&funding),
        );
        input.insert(PSBT_IN_OUTPUT_INDEX, &[], 1u32.to_le_bytes().to_vec());
        assert_eq!(input.spent_script().unwrap(), Some(utxo.script_pubkey));
        input.insert(PSBT_IN_OUTPUT_INDEX, &[], 2u32.to_le_bytes().to_vec());
        assert_eq!(input.spent_script(), Err(PsbtV2Error::InvalidField));

        // key origins that aren't whole steps
        input.insert(PSBT_IN_BIP32_DERIVATION, &KEY, vec![0; 5]);
        assert_eq!(input.key_origins(), Err(PsbtV2Error::InvalidField));
    }
}
