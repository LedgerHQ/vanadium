//! Local BIP-388 facade that reuses upstream descriptor parsing while extending key origins and
//! wallet-policy serialization with Vanadium signing-policy commitments.

use alloc::{string::String, vec, vec::Vec};
use bitcoin::{
    bip32::{ChainCode, ChildNumber, Xpub},
    consensus::{encode, Decodable, Encodable},
    io::Read,
    VarInt,
};
use core::{fmt, str::FromStr};
use hex::FromHex;

pub use bip388_core::{
    ClearText, DescriptorTemplate, DescriptorTemplateIter, DescriptorTemplateIterMut,
    KeyExpression, KeyExpressionType, ParseError, TapTree, TapleavesIter, MAX_CONFUSION_SCORE,
};

const MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN: usize = 4096;
const MAX_SERIALIZED_KEY_COUNT: usize = 999;
const MAX_BIP32_DERIVATION_PATH_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyOrigin {
    pub fingerprint: u32,
    pub derivation_path: Vec<ChildNumber>,
    pub signing_policy_hash: Option<[u8; 32]>,
}

impl fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.fingerprint)?;
        for step in &self.derivation_path {
            write!(f, "/{}", step)?;
        }
        if let Some(hash) = self.signing_policy_hash {
            write!(f, "/{}", hex::encode(hash))?;
        }
        Ok(())
    }
}

impl TryFrom<&str> for KeyOrigin {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(ParseError::EmptyInput);
        }

        let parts: Vec<&str> = value.split('/').collect();
        if parts[0].len() != 8 {
            return Err(ParseError::InvalidLength);
        }
        let fingerprint = u32::from_str_radix(parts[0], 16).map_err(|_| ParseError::InvalidKey)?;

        let signing_policy_hash = match parts.last() {
            Some(candidate) if candidate.len() == 64 => {
                if !candidate
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(ParseError::InvalidHex);
                }
                Some(<[u8; 32]>::from_hex(candidate).map_err(|_| ParseError::InvalidHex)?)
            }
            _ => None,
        };
        let path_end = parts.len() - usize::from(signing_policy_hash.is_some());
        let derivation_path = parts[1..path_end]
            .iter()
            .map(|step| ChildNumber::from_str(step).map_err(|_| ParseError::InvalidKey))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            fingerprint,
            derivation_path,
            signing_policy_hash,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct KeyInformation {
    pub pubkey: Xpub,
    pub origin_info: Option<KeyOrigin>,
}

impl fmt::Display for KeyInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.origin_info {
            Some(origin) => write!(f, "[{}]{}", origin, self.pubkey),
            None => write!(f, "{}", self.pubkey),
        }
    }
}

impl TryFrom<&str> for KeyInformation {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(ParseError::EmptyInput);
        }
        let (origin_info, pubkey_pos) = if value.starts_with('[') {
            let end = value.find(']').ok_or(ParseError::InvalidKey)?;
            (Some(KeyOrigin::try_from(&value[1..end])?), end + 1)
        } else {
            (None, 0)
        };
        let mut pubkey =
            Xpub::from_str(&value[pubkey_pos..]).map_err(|_| ParseError::InvalidKey)?;
        if let Some(hash) = origin_info
            .as_ref()
            .and_then(|origin| origin.signing_policy_hash)
        {
            pubkey.chain_code = ChainCode::from(hash);
        }
        Ok(Self {
            pubkey,
            origin_info,
        })
    }
}

fn to_core_key_information(key_info: &KeyInformation) -> bip388_core::KeyInformation {
    bip388_core::KeyInformation {
        pubkey: key_info.pubkey,
        origin_info: key_info
            .origin_info
            .as_ref()
            .map(|origin| bip388_core::KeyOrigin {
                fingerprint: origin.fingerprint,
                derivation_path: origin.derivation_path.clone(),
            }),
    }
}

pub trait ToDescriptor {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError>;
}

impl ToDescriptor for DescriptorTemplate {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let core_keys = key_information
            .iter()
            .map(to_core_key_information)
            .collect::<Vec<_>>();
        bip388_core::ToDescriptor::to_descriptor(self, &core_keys, is_change, address_index)
    }
}

impl ToDescriptor for TapTree {
    fn to_descriptor(
        &self,
        key_information: &[KeyInformation],
        is_change: bool,
        address_index: u32,
    ) -> Result<String, ParseError> {
        let core_keys = key_information
            .iter()
            .map(to_core_key_information)
            .collect::<Vec<_>>();
        bip388_core::ToDescriptor::to_descriptor(self, &core_keys, is_change, address_index)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    descriptor_template: DescriptorTemplate,
    key_information: Vec<KeyInformation>,
    descriptor_template_raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegwitVersion {
    Legacy,
    SegwitV0,
    Taproot,
}

impl SegwitVersion {
    pub fn is_segwit(&self) -> bool {
        matches!(self, Self::SegwitV0 | Self::Taproot)
    }
}

impl WalletPolicy {
    pub fn new(
        descriptor_template: &str,
        key_information: Vec<KeyInformation>,
    ) -> Result<Self, ParseError> {
        Ok(Self {
            descriptor_template: DescriptorTemplate::from_str(descriptor_template)?,
            key_information,
            descriptor_template_raw: descriptor_template.into(),
        })
    }

    pub fn descriptor_template(&self) -> &DescriptorTemplate {
        &self.descriptor_template
    }

    pub fn key_information(&self) -> &[KeyInformation] {
        &self.key_information
    }

    pub fn descriptor_template_raw(&self) -> &str {
        &self.descriptor_template_raw
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        VarInt(self.descriptor_template_raw.len() as u64)
            .consensus_encode(&mut result)
            .expect("writing to Vec is infallible");
        result.extend_from_slice(self.descriptor_template_raw.as_bytes());
        VarInt(self.key_information.len() as u64)
            .consensus_encode(&mut result)
            .expect("writing to Vec is infallible");

        for key_info in &self.key_information {
            match &key_info.origin_info {
                None => result.push(0),
                Some(origin) => {
                    result.push(if origin.signing_policy_hash.is_some() {
                        2
                    } else {
                        1
                    });
                    result.extend_from_slice(&origin.fingerprint.to_be_bytes());
                    VarInt(origin.derivation_path.len() as u64)
                        .consensus_encode(&mut result)
                        .expect("writing to Vec is infallible");
                    for step in &origin.derivation_path {
                        result.extend_from_slice(&u32::from(*step).to_le_bytes());
                    }
                    if let Some(hash) = origin.signing_policy_hash {
                        result.extend_from_slice(&hash);
                    }
                }
            }
            result.extend_from_slice(&key_info.pubkey.encode());
        }
        result
    }

    pub fn deserialize<R: Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        let VarInt(descriptor_len) = VarInt::consensus_decode(reader)?;
        if descriptor_len > MAX_SERIALIZED_DESCRIPTORTEMPLATE_LEN as u64 {
            return Err(encode::Error::ParseFailed("Descriptor template too long"));
        }
        let mut descriptor_bytes = vec![0; descriptor_len as usize];
        reader.read_exact(&mut descriptor_bytes)?;
        let descriptor_template = String::from_utf8(descriptor_bytes)
            .map_err(|_| encode::Error::ParseFailed("Invalid UTF-8 in descriptor"))?;

        let VarInt(key_count) = VarInt::consensus_decode(reader)?;
        if key_count > MAX_SERIALIZED_KEY_COUNT as u64 {
            return Err(encode::Error::ParseFailed("Too many keys"));
        }
        let mut key_information = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let mut flag = [0; 1];
            reader.read_exact(&mut flag)?;
            let origin_info = match flag[0] {
                0 => None,
                flag @ (1 | 2) => {
                    let mut fingerprint = [0; 4];
                    reader.read_exact(&mut fingerprint)?;
                    let VarInt(path_len) = VarInt::consensus_decode(reader)?;
                    if path_len > (MAX_BIP32_DERIVATION_PATH_LEN - 2) as u64 {
                        return Err(encode::Error::ParseFailed("Derivation path too long"));
                    }
                    let mut derivation_path = Vec::with_capacity(path_len as usize);
                    for _ in 0..path_len {
                        let mut step = [0; 4];
                        reader.read_exact(&mut step)?;
                        derivation_path.push(ChildNumber::from(u32::from_le_bytes(step)));
                    }
                    let signing_policy_hash = if flag == 2 {
                        let mut hash = [0; 32];
                        reader.read_exact(&mut hash)?;
                        Some(hash)
                    } else {
                        None
                    };
                    Some(KeyOrigin {
                        fingerprint: u32::from_be_bytes(fingerprint),
                        derivation_path,
                        signing_policy_hash,
                    })
                }
                _ => return Err(encode::Error::ParseFailed("Invalid key information flag")),
            };

            let mut xpub = [0; 78];
            reader.read_exact(&mut xpub)?;
            key_information.push(KeyInformation {
                pubkey: Xpub::decode(&xpub)
                    .map_err(|_| encode::Error::ParseFailed("Invalid xpub"))?,
                origin_info,
            });
        }

        let mut trailing = [0; 1];
        if reader.read(&mut trailing)? != 0 {
            return Err(encode::Error::ParseFailed(
                "Extra data after deserializing WalletPolicy",
            ));
        }

        Self::new(&descriptor_template, key_information).map_err(|_| {
            encode::Error::ParseFailed("Invalid descriptor template or key information")
        })
    }

    pub fn get_segwit_version(&self) -> Result<SegwitVersion, ParseError> {
        match &self.descriptor_template {
            DescriptorTemplate::Tr(_, _) => Ok(SegwitVersion::Taproot),
            DescriptorTemplate::Pkh(_) => Ok(SegwitVersion::Legacy),
            DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => Ok(SegwitVersion::SegwitV0),
            DescriptorTemplate::Sh(inner) => match inner.as_ref() {
                DescriptorTemplate::Wpkh(_) | DescriptorTemplate::Wsh(_) => {
                    Ok(SegwitVersion::SegwitV0)
                }
                _ => Ok(SegwitVersion::Legacy),
            },
            _ => Err(ParseError::InvalidTopLevelPolicy),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::por::Registerable;
    use alloc::format;

    const XPUB: &str = "tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P";

    fn key_with_policy_hash(hash: [u8; 32]) -> KeyInformation {
        KeyInformation::try_from(
            format!("[f5acc2fd/84'/1'/0'/{}]{}", hex::encode(hash), XPUB).as_str(),
        )
        .unwrap()
    }

    #[test]
    fn ordinary_key_origin_matches_upstream_serialization() {
        let key_string = format!("[f5acc2fd/84'/1'/0']{}", XPUB);
        let key = KeyInformation::try_from(key_string.as_str()).unwrap();
        let policy = WalletPolicy::new("wpkh(@0/**)", vec![key]).unwrap();

        let core_key = bip388_core::KeyInformation::try_from(key_string.as_str()).unwrap();
        let core_policy = bip388_core::WalletPolicy::new("wpkh(@0/**)", vec![core_key]).unwrap();

        assert_eq!(policy.serialize(), core_policy.serialize());
        assert_eq!(policy.key_information()[0].to_string(), key_string);
    }

    #[test]
    fn policy_hash_suffix_patches_chain_code_and_roundtrips() {
        let hash = [0x42; 32];
        let key = key_with_policy_hash(hash);
        let origin = key.origin_info.as_ref().unwrap();

        assert_eq!(origin.signing_policy_hash, Some(hash));
        assert_eq!(origin.derivation_path.len(), 3);
        assert_eq!(key.pubkey.chain_code, ChainCode::from(hash));

        let displayed = key.to_string();
        assert!(displayed.contains(&format!("/{}]", hex::encode(hash))));
        assert_eq!(KeyInformation::try_from(displayed.as_str()).unwrap(), key);
    }

    #[test]
    fn concrete_descriptor_uses_policy_bound_xpub() {
        let key = key_with_policy_hash([0x42; 32]);
        let policy = WalletPolicy::new("wpkh(@0/**)", vec![key]).unwrap();

        let descriptor = policy
            .descriptor_template()
            .to_descriptor(policy.key_information(), false, 7)
            .unwrap();

        assert!(descriptor.contains(&policy.key_information()[0].pubkey.to_string()));
        assert!(descriptor.ends_with("/0/7)"));
    }

    #[test]
    fn policy_hash_suffix_must_be_lowercase_hex() {
        let uppercase = "A1".repeat(32);
        let non_hex = "gg".repeat(32);
        let too_short = "ab".repeat(31);

        assert_eq!(
            KeyInformation::try_from(format!("[f5acc2fd/{}]{}", uppercase, XPUB).as_str()),
            Err(ParseError::InvalidHex)
        );
        assert_eq!(
            KeyInformation::try_from(format!("[f5acc2fd/{}]{}", non_hex, XPUB).as_str()),
            Err(ParseError::InvalidHex)
        );
        assert!(
            KeyInformation::try_from(format!("[f5acc2fd/{}]{}", too_short, XPUB).as_str()).is_err()
        );
    }

    #[test]
    fn wallet_policy_binary_roundtrip_preserves_policy_hash() {
        let policy =
            WalletPolicy::new("wpkh(@0/**)", vec![key_with_policy_hash([0x24; 32])]).unwrap();
        let serialized = policy.serialize();

        let decoded = WalletPolicy::deserialize(&mut serialized.as_slice()).unwrap();
        assert_eq!(decoded, policy);
        let origin_discriminator = 1 + policy.descriptor_template_raw().len() + 1;
        assert_eq!(serialized[origin_discriminator], 2);
    }

    #[test]
    fn wallet_policy_account_version_remains_one() {
        assert_eq!(<WalletPolicy as Account>::VERSION, 1);
    }

    #[test]
    fn signing_policy_hash_changes_registration_id() {
        let first =
            WalletPolicy::new("wpkh(@0/**)", vec![key_with_policy_hash([0x11; 32])]).unwrap();
        let second =
            WalletPolicy::new("wpkh(@0/**)", vec![key_with_policy_hash([0x22; 32])]).unwrap();

        assert_ne!(
            first.registration_id("Policy account"),
            second.registration_id("Policy account")
        );
    }
}
