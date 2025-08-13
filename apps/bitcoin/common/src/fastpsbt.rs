// This module is a fast implementation of a read-only version of PSBTv2 (Partially Signed Bitcoin Transaction)
// as specified in BIP-370.
// It is created by parsing a &[u8] once, and creating an indexed view of the PSBT for fast access, with minimal
// overhead and validation.
// Fields that are small are also stored as variables during parsing, while fields that can be large will be stored
// as slices into the original PSBT data.
//
// It is assumed that keys in each map of the PSBT are unique and sorted in ascending order.

use alloc::vec::Vec;
use core::cmp::Ordering;

const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_XPUB: u8 = 0x01;
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
const PSBT_GLOBAL_VERSION: u8 = 0xFB;
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xFC;

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
    DuplicateKey,   // exact duplicate key bytes in same map
    UnsortedKeys,   // only PSBTs with lexicographically sorted maps are supported
    BadSmallField,  // wrong length for known small field
    MissingCounts,  // missing PSBT_GLOBAL_INPUT_COUNT or PSBT_GLOBAL_OUTPUT_COUNT
    CountsTooLarge, // counts don't fit in usize
    NotAllowed,     // not allowed in PSBT v2
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
}

#[derive(Debug)]
pub struct Input<'a> {
    map: ParsedMap<'a>,
}

#[derive(Debug)]
pub struct Output<'a> {
    map: ParsedMap<'a>,
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

    // Update get() to compare keys correctly
    fn get(&self, key: &[u8]) -> Option<&'a [u8]> {
        if key.is_empty() {
            return None;
        }
        let search_key_type = key[0];
        let search_key_data = &key[1..];
        self.pairs
            .binary_search_by(|p| {
                p.key_type
                    .cmp(&search_key_type)
                    .then_with(|| p.key_data.cmp(search_key_data))
            })
            .ok()
            .map(|idx| self.pairs[idx].value)
    }
}

impl<'a> Psbt<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, PsbtError> {
        const MAGIC: &[u8; 5] = b"psbt\xff";
        if raw.len() < MAGIC.len() || &raw[..5] != MAGIC {
            return Err(PsbtError::InvalidMagic);
        }
        let mut cur = Cursor::new(raw, MAGIC.len());

        let mut n_inputs = None;
        let mut n_outputs = None;

        let global_map = ParsedMap::from_cursor(&mut cur, |pair: &MapPair| {
            match pair.key_type {
                PSBT_GLOBAL_INPUT_COUNT => {
                    n_inputs = Some(u64_from_compact_size(pair.value)?);
                }
                PSBT_GLOBAL_OUTPUT_COUNT => {
                    n_outputs = Some(u64_from_compact_size(pair.value)?);
                }
                _ => {}
            }
            Ok(())
        })?;

        let n_inputs = n_inputs.ok_or(PsbtError::MissingCounts)?;
        let n_outputs = n_outputs.ok_or(PsbtError::MissingCounts)?;

        let inputs = (0..n_inputs)
            .map(|_| Input::from_cursor(&mut cur))
            .collect::<Result<Vec<_>, _>>()?;

        let outputs = (0..n_outputs)
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
        })
    }
}

impl<'a> Input<'a> {
    fn from_cursor(cur: &mut Cursor<'a>) -> Result<Self, PsbtError> {
        let map = ParsedMap::from_cursor(cur, |_pair: &MapPair| Ok(()))?;
        Ok(Self { map })
    }
}
impl<'a> Output<'a> {
    fn from_cursor(cur: &mut Cursor<'a>) -> Result<Self, PsbtError> {
        let map = ParsedMap::from_cursor(cur, |_pair: &MapPair| Ok(()))?;

        Ok(Self { map })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    const VALID_PSBT: &'static str = "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";

    #[test]
    fn test_parse_psbt() {
        let psbt_bin = STANDARD.decode(&VALID_PSBT).unwrap();
        let psbt = Psbt::parse(&psbt_bin).unwrap();
        assert_eq!(psbt.raw_psbt, psbt_bin);
        assert_eq!(psbt.inputs.len(), 1);
        assert_eq!(psbt.outputs.len(), 2);
    }
}
