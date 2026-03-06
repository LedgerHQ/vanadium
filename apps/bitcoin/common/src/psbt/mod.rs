pub mod account;
pub mod id_auth;

pub use account::*;
pub use id_auth::*;

use bitcoin::psbt;

/// A single proprietary key-value entry from a PSBT map section.
pub struct ProprietaryEntry<'a> {
    pub prefix: &'a [u8],
    pub subtype: u8,
    pub key: &'a [u8],
    pub value: &'a [u8],
}

fn parse_proprietary_key_data<'a>(kd: &'a [u8], value: &'a [u8]) -> Option<ProprietaryEntry<'a>> {
    if kd.len() < 2 {
        return None;
    }
    let prefix_len = kd[0] as usize;
    if kd.len() < 1 + prefix_len + 1 {
        return None;
    }
    Some(ProprietaryEntry {
        prefix: &kd[1..1 + prefix_len],
        subtype: kd[1 + prefix_len],
        key: &kd[1 + prefix_len + 1..],
        value,
    })
}

/// Trait for types that expose PSBT global proprietary key-value fields.
pub trait GlobalHasProprietaryFields {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_;
}

/// Trait for types that expose PSBT per-input proprietary key-value fields.
pub trait InputHasProprietaryFields {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_;
}

/// Trait for types that expose PSBT per-output proprietary key-value fields.
pub trait OutputHasProprietaryFields {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_;
}

impl GlobalHasProprietaryFields for psbt::Psbt {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.proprietary.iter().map(|(k, v)| ProprietaryEntry {
            prefix: &k.prefix,
            subtype: k.subtype,
            key: &k.key,
            value: v,
        })
    }
}

impl InputHasProprietaryFields for psbt::Input {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.proprietary.iter().map(|(k, v)| ProprietaryEntry {
            prefix: &k.prefix,
            subtype: k.subtype,
            key: &k.key,
            value: v,
        })
    }
}

impl OutputHasProprietaryFields for psbt::Output {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.proprietary.iter().map(|(k, v)| ProprietaryEntry {
            prefix: &k.prefix,
            subtype: k.subtype,
            key: &k.key,
            value: v,
        })
    }
}

impl<'a> GlobalHasProprietaryFields for crate::fastpsbt::Psbt<'a> {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.iter_keys(0xFC)
            .filter_map(|(kd, value)| parse_proprietary_key_data(kd, value))
    }
}

impl<'a> InputHasProprietaryFields for crate::fastpsbt::Input<'a> {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.iter_keys(0xFC)
            .filter_map(|(kd, value)| parse_proprietary_key_data(kd, value))
    }
}

impl<'a> OutputHasProprietaryFields for crate::fastpsbt::Output<'a> {
    fn iter_proprietary(&self) -> impl Iterator<Item = ProprietaryEntry<'_>> + '_ {
        self.iter_keys(0xFC)
            .filter_map(|(kd, value)| parse_proprietary_key_data(kd, value))
    }
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
