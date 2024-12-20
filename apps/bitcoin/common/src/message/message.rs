// Automatically generated rust module for 'message.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use alloc::vec::Vec;
use alloc::borrow::Cow;
use quick_protobuf::{MessageInfo, MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestGetVersion { }

impl<'a> MessageRead<'a> for RequestGetVersion {
    fn from_reader(r: &mut BytesReader, _: &[u8]) -> Result<Self> {
        r.read_to_end();
        Ok(Self::default())
    }
}

impl MessageWrite for RequestGetVersion { }

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseGetVersion<'a> {
    pub version: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for ResponseGetVersion<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.version = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseGetVersion<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.version == "" { 0 } else { 1 + sizeof_len((&self.version).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.version != "" { w.write_with_tag(10, |w| w.write_string(&**&self.version))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestExit { }

impl<'a> MessageRead<'a> for RequestExit {
    fn from_reader(r: &mut BytesReader, _: &[u8]) -> Result<Self> {
        r.read_to_end();
        Ok(Self::default())
    }
}

impl MessageWrite for RequestExit { }

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestGetMasterFingerprint { }

impl<'a> MessageRead<'a> for RequestGetMasterFingerprint {
    fn from_reader(r: &mut BytesReader, _: &[u8]) -> Result<Self> {
        r.read_to_end();
        Ok(Self::default())
    }
}

impl MessageWrite for RequestGetMasterFingerprint { }

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseGetMasterFingerprint {
    pub fingerprint: u32,
}

impl<'a> MessageRead<'a> for ResponseGetMasterFingerprint {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.fingerprint = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ResponseGetMasterFingerprint {
    fn get_size(&self) -> usize {
        0
        + if self.fingerprint == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.fingerprint) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.fingerprint != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.fingerprint))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestGetExtendedPubkey {
    pub display: bool,
    pub bip32_path: Vec<u32>,
}

impl<'a> MessageRead<'a> for RequestGetExtendedPubkey {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.display = r.read_bool(bytes)?,
                Ok(18) => msg.bip32_path = r.read_packed(bytes, |r, bytes| Ok(r.read_uint32(bytes)?))?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for RequestGetExtendedPubkey {
    fn get_size(&self) -> usize {
        0
        + if self.display == false { 0 } else { 1 + sizeof_varint(*(&self.display) as u64) }
        + if self.bip32_path.is_empty() { 0 } else { 1 + sizeof_len(self.bip32_path.iter().map(|s| sizeof_varint(*(s) as u64)).sum::<usize>()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.display != false { w.write_with_tag(8, |w| w.write_bool(*&self.display))?; }
        w.write_packed_with_tag(18, &self.bip32_path, |w, m| w.write_uint32(*m), &|m| sizeof_varint(*(m) as u64))?;
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseGetExtendedPubkey<'a> {
    pub pubkey: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for ResponseGetExtendedPubkey<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.pubkey = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseGetExtendedPubkey<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.pubkey == "" { 0 } else { 1 + sizeof_len((&self.pubkey).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.pubkey != "" { w.write_with_tag(10, |w| w.write_string(&**&self.pubkey))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestRegisterWallet<'a> {
    pub name: Cow<'a, str>,
    pub descriptor_template: Cow<'a, str>,
    pub keys_info: Vec<Cow<'a, str>>,
}

impl<'a> MessageRead<'a> for RequestRegisterWallet<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.name = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(18) => msg.descriptor_template = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.keys_info.push(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for RequestRegisterWallet<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.name == "" { 0 } else { 1 + sizeof_len((&self.name).len()) }
        + if self.descriptor_template == "" { 0 } else { 1 + sizeof_len((&self.descriptor_template).len()) }
        + self.keys_info.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.name != "" { w.write_with_tag(10, |w| w.write_string(&**&self.name))?; }
        if self.descriptor_template != "" { w.write_with_tag(18, |w| w.write_string(&**&self.descriptor_template))?; }
        for s in &self.keys_info { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseRegisterWallet<'a> {
    pub wallet_id: Cow<'a, [u8]>,
    pub wallet_hmac: Cow<'a, [u8]>,
}

impl<'a> MessageRead<'a> for ResponseRegisterWallet<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.wallet_id = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(18) => msg.wallet_hmac = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseRegisterWallet<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.wallet_id == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.wallet_id).len()) }
        + if self.wallet_hmac == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.wallet_hmac).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.wallet_id != Cow::Borrowed(b"") { w.write_with_tag(10, |w| w.write_bytes(&**&self.wallet_id))?; }
        if self.wallet_hmac != Cow::Borrowed(b"") { w.write_with_tag(18, |w| w.write_bytes(&**&self.wallet_hmac))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestGetWalletAddress<'a> {
    pub display: bool,
    pub name: Cow<'a, str>,
    pub descriptor_template: Cow<'a, str>,
    pub keys_info: Vec<Cow<'a, str>>,
    pub wallet_hmac: Cow<'a, [u8]>,
    pub change: bool,
    pub address_index: u32,
}

impl<'a> MessageRead<'a> for RequestGetWalletAddress<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.display = r.read_bool(bytes)?,
                Ok(18) => msg.name = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.descriptor_template = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(34) => msg.keys_info.push(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(42) => msg.wallet_hmac = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(48) => msg.change = r.read_bool(bytes)?,
                Ok(56) => msg.address_index = r.read_uint32(bytes)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for RequestGetWalletAddress<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.display == false { 0 } else { 1 + sizeof_varint(*(&self.display) as u64) }
        + if self.name == "" { 0 } else { 1 + sizeof_len((&self.name).len()) }
        + if self.descriptor_template == "" { 0 } else { 1 + sizeof_len((&self.descriptor_template).len()) }
        + self.keys_info.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
        + if self.wallet_hmac == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.wallet_hmac).len()) }
        + if self.change == false { 0 } else { 1 + sizeof_varint(*(&self.change) as u64) }
        + if self.address_index == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.address_index) as u64) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.display != false { w.write_with_tag(8, |w| w.write_bool(*&self.display))?; }
        if self.name != "" { w.write_with_tag(18, |w| w.write_string(&**&self.name))?; }
        if self.descriptor_template != "" { w.write_with_tag(26, |w| w.write_string(&**&self.descriptor_template))?; }
        for s in &self.keys_info { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        if self.wallet_hmac != Cow::Borrowed(b"") { w.write_with_tag(42, |w| w.write_bytes(&**&self.wallet_hmac))?; }
        if self.change != false { w.write_with_tag(48, |w| w.write_bool(*&self.change))?; }
        if self.address_index != 0u32 { w.write_with_tag(56, |w| w.write_uint32(*&self.address_index))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseGetWalletAddress<'a> {
    pub address: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for ResponseGetWalletAddress<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.address = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseGetWalletAddress<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.address == "" { 0 } else { 1 + sizeof_len((&self.address).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.address != "" { w.write_with_tag(10, |w| w.write_string(&**&self.address))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct RequestSignPsbt<'a> {
    pub psbt: Cow<'a, [u8]>,
    pub name: Cow<'a, str>,
    pub descriptor_template: Cow<'a, str>,
    pub keys_info: Vec<Cow<'a, str>>,
    pub wallet_hmac: Cow<'a, [u8]>,
}

impl<'a> MessageRead<'a> for RequestSignPsbt<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.psbt = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(18) => msg.name = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.descriptor_template = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(34) => msg.keys_info.push(r.read_string(bytes).map(Cow::Borrowed)?),
                Ok(42) => msg.wallet_hmac = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for RequestSignPsbt<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.psbt == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.psbt).len()) }
        + if self.name == "" { 0 } else { 1 + sizeof_len((&self.name).len()) }
        + if self.descriptor_template == "" { 0 } else { 1 + sizeof_len((&self.descriptor_template).len()) }
        + self.keys_info.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
        + if self.wallet_hmac == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.wallet_hmac).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.psbt != Cow::Borrowed(b"") { w.write_with_tag(10, |w| w.write_bytes(&**&self.psbt))?; }
        if self.name != "" { w.write_with_tag(18, |w| w.write_string(&**&self.name))?; }
        if self.descriptor_template != "" { w.write_with_tag(26, |w| w.write_string(&**&self.descriptor_template))?; }
        for s in &self.keys_info { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        if self.wallet_hmac != Cow::Borrowed(b"") { w.write_with_tag(42, |w| w.write_bytes(&**&self.wallet_hmac))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct PartialSignature<'a> {
    pub input_index: u32,
    pub signature: Cow<'a, [u8]>,
    pub public_key: Cow<'a, [u8]>,
    pub leaf_hash: Cow<'a, [u8]>,
}

impl<'a> MessageRead<'a> for PartialSignature<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.input_index = r.read_uint32(bytes)?,
                Ok(18) => msg.signature = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.public_key = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(34) => msg.leaf_hash = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for PartialSignature<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.input_index == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.input_index) as u64) }
        + if self.signature == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.signature).len()) }
        + if self.public_key == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.public_key).len()) }
        + if self.leaf_hash == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.leaf_hash).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.input_index != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.input_index))?; }
        if self.signature != Cow::Borrowed(b"") { w.write_with_tag(18, |w| w.write_bytes(&**&self.signature))?; }
        if self.public_key != Cow::Borrowed(b"") { w.write_with_tag(26, |w| w.write_bytes(&**&self.public_key))?; }
        if self.leaf_hash != Cow::Borrowed(b"") { w.write_with_tag(34, |w| w.write_bytes(&**&self.leaf_hash))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct MusigPublicNonce<'a> {
    pub input_index: u32,
    pub pubnonce: Cow<'a, [u8]>,
    pub participant_public_key: Cow<'a, [u8]>,
    pub xonly_key: Cow<'a, [u8]>,
    pub leaf_hash: Cow<'a, [u8]>,
}

impl<'a> MessageRead<'a> for MusigPublicNonce<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.input_index = r.read_uint32(bytes)?,
                Ok(18) => msg.pubnonce = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.participant_public_key = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(34) => msg.xonly_key = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(42) => msg.leaf_hash = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for MusigPublicNonce<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.input_index == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.input_index) as u64) }
        + if self.pubnonce == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.pubnonce).len()) }
        + if self.participant_public_key == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.participant_public_key).len()) }
        + if self.xonly_key == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.xonly_key).len()) }
        + if self.leaf_hash == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.leaf_hash).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.input_index != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.input_index))?; }
        if self.pubnonce != Cow::Borrowed(b"") { w.write_with_tag(18, |w| w.write_bytes(&**&self.pubnonce))?; }
        if self.participant_public_key != Cow::Borrowed(b"") { w.write_with_tag(26, |w| w.write_bytes(&**&self.participant_public_key))?; }
        if self.xonly_key != Cow::Borrowed(b"") { w.write_with_tag(34, |w| w.write_bytes(&**&self.xonly_key))?; }
        if self.leaf_hash != Cow::Borrowed(b"") { w.write_with_tag(42, |w| w.write_bytes(&**&self.leaf_hash))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct MusigPartialSignature<'a> {
    pub input_index: u32,
    pub signature: Cow<'a, [u8]>,
    pub participant_public_key: Cow<'a, [u8]>,
    pub xonly_key: Cow<'a, [u8]>,
    pub leaf_hash: Cow<'a, [u8]>,
}

impl<'a> MessageRead<'a> for MusigPartialSignature<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.input_index = r.read_uint32(bytes)?,
                Ok(18) => msg.signature = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(26) => msg.participant_public_key = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(34) => msg.xonly_key = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(42) => msg.leaf_hash = r.read_bytes(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for MusigPartialSignature<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.input_index == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.input_index) as u64) }
        + if self.signature == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.signature).len()) }
        + if self.participant_public_key == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.participant_public_key).len()) }
        + if self.xonly_key == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.xonly_key).len()) }
        + if self.leaf_hash == Cow::Borrowed(b"") { 0 } else { 1 + sizeof_len((&self.leaf_hash).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.input_index != 0u32 { w.write_with_tag(8, |w| w.write_uint32(*&self.input_index))?; }
        if self.signature != Cow::Borrowed(b"") { w.write_with_tag(18, |w| w.write_bytes(&**&self.signature))?; }
        if self.participant_public_key != Cow::Borrowed(b"") { w.write_with_tag(26, |w| w.write_bytes(&**&self.participant_public_key))?; }
        if self.xonly_key != Cow::Borrowed(b"") { w.write_with_tag(34, |w| w.write_bytes(&**&self.xonly_key))?; }
        if self.leaf_hash != Cow::Borrowed(b"") { w.write_with_tag(42, |w| w.write_bytes(&**&self.leaf_hash))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseSignPsbt<'a> {
    pub partial_signatures: Vec<PartialSignature<'a>>,
    pub musig_public_nonces: Vec<MusigPublicNonce<'a>>,
    pub musig_partial_signatures: Vec<MusigPartialSignature<'a>>,
}

impl<'a> MessageRead<'a> for ResponseSignPsbt<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.partial_signatures.push(r.read_message::<PartialSignature>(bytes)?),
                Ok(18) => msg.musig_public_nonces.push(r.read_message::<MusigPublicNonce>(bytes)?),
                Ok(26) => msg.musig_partial_signatures.push(r.read_message::<MusigPartialSignature>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseSignPsbt<'a> {
    fn get_size(&self) -> usize {
        0
        + self.partial_signatures.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.musig_public_nonces.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.musig_partial_signatures.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.partial_signatures { w.write_with_tag(10, |w| w.write_message(s))?; }
        for s in &self.musig_public_nonces { w.write_with_tag(18, |w| w.write_message(s))?; }
        for s in &self.musig_partial_signatures { w.write_with_tag(26, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ResponseError<'a> {
    pub error_msg: Cow<'a, str>,
}

impl<'a> MessageRead<'a> for ResponseError<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.error_msg = r.read_string(bytes).map(Cow::Borrowed)?,
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for ResponseError<'a> {
    fn get_size(&self) -> usize {
        0
        + if self.error_msg == "" { 0 } else { 1 + sizeof_len((&self.error_msg).len()) }
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.error_msg != "" { w.write_with_tag(10, |w| w.write_string(&**&self.error_msg))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Request<'a> {
    pub request: mod_Request::OneOfrequest<'a>,
}

impl<'a> MessageRead<'a> for Request<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.request = mod_Request::OneOfrequest::get_version(r.read_message::<RequestGetVersion>(bytes)?),
                Ok(18) => msg.request = mod_Request::OneOfrequest::exit(r.read_message::<RequestExit>(bytes)?),
                Ok(26) => msg.request = mod_Request::OneOfrequest::get_master_fingerprint(r.read_message::<RequestGetMasterFingerprint>(bytes)?),
                Ok(34) => msg.request = mod_Request::OneOfrequest::get_extended_pubkey(r.read_message::<RequestGetExtendedPubkey>(bytes)?),
                Ok(42) => msg.request = mod_Request::OneOfrequest::register_wallet(r.read_message::<RequestRegisterWallet>(bytes)?),
                Ok(50) => msg.request = mod_Request::OneOfrequest::get_wallet_address(r.read_message::<RequestGetWalletAddress>(bytes)?),
                Ok(58) => msg.request = mod_Request::OneOfrequest::sign_psbt(r.read_message::<RequestSignPsbt>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Request<'a> {
    fn get_size(&self) -> usize {
        0
        + match self.request {
            mod_Request::OneOfrequest::get_version(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::exit(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::get_master_fingerprint(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::get_extended_pubkey(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::register_wallet(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::get_wallet_address(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::sign_psbt(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Request::OneOfrequest::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.request {            mod_Request::OneOfrequest::get_version(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::exit(ref m) => { w.write_with_tag(18, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::get_master_fingerprint(ref m) => { w.write_with_tag(26, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::get_extended_pubkey(ref m) => { w.write_with_tag(34, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::register_wallet(ref m) => { w.write_with_tag(42, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::get_wallet_address(ref m) => { w.write_with_tag(50, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::sign_psbt(ref m) => { w.write_with_tag(58, |w| w.write_message(m))? },
            mod_Request::OneOfrequest::None => {},
    }        Ok(())
    }
}

pub mod mod_Request {

use alloc::vec::Vec;
use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfrequest<'a> {
    get_version(RequestGetVersion),
    exit(RequestExit),
    get_master_fingerprint(RequestGetMasterFingerprint),
    get_extended_pubkey(RequestGetExtendedPubkey),
    register_wallet(RequestRegisterWallet<'a>),
    get_wallet_address(RequestGetWalletAddress<'a>),
    sign_psbt(RequestSignPsbt<'a>),
    None,
}

impl<'a> Default for OneOfrequest<'a> {
    fn default() -> Self {
        OneOfrequest::None
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Response<'a> {
    pub response: mod_Response::OneOfresponse<'a>,
}

impl<'a> MessageRead<'a> for Response<'a> {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.response = mod_Response::OneOfresponse::get_version(r.read_message::<ResponseGetVersion>(bytes)?),
                Ok(18) => msg.response = mod_Response::OneOfresponse::get_master_fingerprint(r.read_message::<ResponseGetMasterFingerprint>(bytes)?),
                Ok(26) => msg.response = mod_Response::OneOfresponse::get_extended_pubkey(r.read_message::<ResponseGetExtendedPubkey>(bytes)?),
                Ok(34) => msg.response = mod_Response::OneOfresponse::register_wallet(r.read_message::<ResponseRegisterWallet>(bytes)?),
                Ok(42) => msg.response = mod_Response::OneOfresponse::get_wallet_address(r.read_message::<ResponseGetWalletAddress>(bytes)?),
                Ok(50) => msg.response = mod_Response::OneOfresponse::sign_psbt(r.read_message::<ResponseSignPsbt>(bytes)?),
                Ok(58) => msg.response = mod_Response::OneOfresponse::error(r.read_message::<ResponseError>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl<'a> MessageWrite for Response<'a> {
    fn get_size(&self) -> usize {
        0
        + match self.response {
            mod_Response::OneOfresponse::get_version(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::get_master_fingerprint(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::get_extended_pubkey(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::register_wallet(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::get_wallet_address(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::sign_psbt(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::error(ref m) => 1 + sizeof_len((m).get_size()),
            mod_Response::OneOfresponse::None => 0,
    }    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        match self.response {            mod_Response::OneOfresponse::get_version(ref m) => { w.write_with_tag(10, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::get_master_fingerprint(ref m) => { w.write_with_tag(18, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::get_extended_pubkey(ref m) => { w.write_with_tag(26, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::register_wallet(ref m) => { w.write_with_tag(34, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::get_wallet_address(ref m) => { w.write_with_tag(42, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::sign_psbt(ref m) => { w.write_with_tag(50, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::error(ref m) => { w.write_with_tag(58, |w| w.write_message(m))? },
            mod_Response::OneOfresponse::None => {},
    }        Ok(())
    }
}

pub mod mod_Response {

use alloc::vec::Vec;
use super::*;

#[derive(Debug, PartialEq, Clone)]
pub enum OneOfresponse<'a> {
    get_version(ResponseGetVersion<'a>),
    get_master_fingerprint(ResponseGetMasterFingerprint),
    get_extended_pubkey(ResponseGetExtendedPubkey<'a>),
    register_wallet(ResponseRegisterWallet<'a>),
    get_wallet_address(ResponseGetWalletAddress<'a>),
    sign_psbt(ResponseSignPsbt<'a>),
    error(ResponseError<'a>),
    None,
}

impl<'a> Default for OneOfresponse<'a> {
    fn default() -> Self {
        OneOfresponse::None
    }
}

}

