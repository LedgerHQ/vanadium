//! Custom minicbor codec for [`bip388::WalletPolicy`].
//!
//! ```text
//! WalletPolicy    = { 0: tstr template, 1: [* KeyInformation] }
//! KeyInformation  = { 0: bstr xpub_bytes, ? 1: KeyOrigin }   // origin omitted if None
//! KeyOrigin       = { 0: uint fingerprint, 1: [* uint] path }
//! ```
//!
//! Used via `#[cbor(with = "bip388_codec")]` on the
//! `Account::WalletPolicy` variant's inner field.

use alloc::{string::String, vec::Vec};
use bitcoin::bip32::{ChildNumber, Xpub};
use minicbor::{
    decode as cbor_decode,
    encode::{self, Write},
    Decoder, Encoder,
};

use crate::bip388::{self, KeyInformation, KeyOrigin};

pub fn encode<C, W: Write>(
    wp: &bip388::WalletPolicy,
    e: &mut Encoder<W>,
    _ctx: &mut C,
) -> Result<(), encode::Error<W::Error>> {
    e.map(2)?;
    e.u8(0)?;
    e.str(wp.descriptor_template_raw())?;
    e.u8(1)?;
    e.array(wp.key_information().len() as u64)?;
    for ki in wp.key_information() {
        encode_key_information(ki, e)?;
    }
    Ok(())
}

pub fn decode<'b, C>(
    d: &mut Decoder<'b>,
    _ctx: &mut C,
) -> Result<bip388::WalletPolicy, cbor_decode::Error> {
    let n = d
        .map()?
        .ok_or_else(|| cbor_decode::Error::message("indefinite-length maps not supported"))?;
    let mut template: Option<String> = None;
    let mut keys: Option<Vec<KeyInformation>> = None;
    for _ in 0..n {
        match d.u8()? {
            0 => template = Some(d.str()?.into()),
            1 => {
                let m = d.array()?.ok_or_else(|| {
                    cbor_decode::Error::message("indefinite-length arrays not supported")
                })?;
                let mut v = Vec::with_capacity(m as usize);
                for _ in 0..m {
                    v.push(decode_key_information(d)?);
                }
                keys = Some(v);
            }
            _ => d.skip()?,
        }
    }
    let template = template.ok_or_else(|| cbor_decode::Error::message("missing template"))?;
    let keys = keys.ok_or_else(|| cbor_decode::Error::message("missing keys information"))?;
    bip388::WalletPolicy::new(&template, keys)
        .map_err(|_| cbor_decode::Error::message("invalid wallet policy"))
}

fn encode_key_information<W: Write>(
    ki: &KeyInformation,
    e: &mut Encoder<W>,
) -> Result<(), encode::Error<W::Error>> {
    let entries: u64 = if ki.origin_info.is_some() { 2 } else { 1 };
    e.map(entries)?;
    e.u8(0)?;
    e.bytes(&ki.pubkey.encode())?;
    if let Some(origin) = &ki.origin_info {
        e.u8(1)?;
        encode_key_origin(origin, e)?;
    }
    Ok(())
}

fn decode_key_information<'b>(d: &mut Decoder<'b>) -> Result<KeyInformation, cbor_decode::Error> {
    let n = d
        .map()?
        .ok_or_else(|| cbor_decode::Error::message("indefinite-length maps not supported"))?;
    let mut pubkey: Option<Xpub> = None;
    let mut origin: Option<KeyOrigin> = None;
    for _ in 0..n {
        match d.u8()? {
            0 => {
                let bytes = d.bytes()?;
                pubkey = Some(
                    Xpub::decode(bytes).map_err(|_| cbor_decode::Error::message("invalid xpub"))?,
                );
            }
            1 => origin = Some(decode_key_origin(d)?),
            _ => d.skip()?,
        }
    }
    let pubkey = pubkey.ok_or_else(|| cbor_decode::Error::message("missing pubkey"))?;
    Ok(KeyInformation {
        pubkey,
        origin_info: origin,
    })
}

fn encode_key_origin<W: Write>(
    origin: &KeyOrigin,
    e: &mut Encoder<W>,
) -> Result<(), encode::Error<W::Error>> {
    e.map(2)?;
    e.u8(0)?;
    e.u32(origin.fingerprint)?;
    e.u8(1)?;
    e.array(origin.derivation_path.len() as u64)?;
    for step in &origin.derivation_path {
        e.u32(u32::from(*step))?;
    }
    Ok(())
}

fn decode_key_origin<'b>(d: &mut Decoder<'b>) -> Result<KeyOrigin, cbor_decode::Error> {
    let n = d
        .map()?
        .ok_or_else(|| cbor_decode::Error::message("indefinite-length maps not supported"))?;
    let mut fingerprint: Option<u32> = None;
    let mut path: Option<Vec<ChildNumber>> = None;
    for _ in 0..n {
        match d.u8()? {
            0 => fingerprint = Some(d.u32()?),
            1 => {
                let m = d.array()?.ok_or_else(|| {
                    cbor_decode::Error::message("indefinite-length arrays not supported")
                })?;
                let mut v = Vec::with_capacity(m as usize);
                for _ in 0..m {
                    v.push(ChildNumber::from(d.u32()?));
                }
                path = Some(v);
            }
            _ => d.skip()?,
        }
    }
    let fingerprint =
        fingerprint.ok_or_else(|| cbor_decode::Error::message("missing fingerprint"))?;
    let derivation_path = path.ok_or_else(|| cbor_decode::Error::message("missing path"))?;
    Ok(KeyOrigin {
        fingerprint,
        derivation_path,
    })
}
