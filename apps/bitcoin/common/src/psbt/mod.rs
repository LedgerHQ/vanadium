pub mod account;
pub mod id_auth;
pub mod v2;

pub use account::*;
pub use id_auth::*;
pub use v2::{PsbtV2, PsbtV2Error};

use bitcoin::consensus::{encode::VarInt, Decodable};
use bitcoin::psbt;

/// A single proprietary key-value entry from a PSBT map section.
pub struct ProprietaryEntry<'a> {
    pub prefix: &'a [u8],
    pub subtype: u8,
    pub key: &'a [u8],
    pub value: &'a [u8],
}

/// Splits the key data of a proprietary key: the compact size length of the identifier, the
/// identifier, the subtype, then the key.
fn parse_proprietary_key_data<'a>(kd: &'a [u8], value: &'a [u8]) -> Option<ProprietaryEntry<'a>> {
    let mut kd = kd;
    let prefix_len = usize::try_from(VarInt::consensus_decode(&mut kd).ok()?.0).ok()?;
    if kd.len() < prefix_len + 1 {
        return None;
    }
    let (prefix, rest) = kd.split_at(prefix_len);
    Some(ProprietaryEntry {
        prefix,
        subtype: rest[0],
        key: &rest[1..],
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
