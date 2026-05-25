use crate::{
    account::{AccountCoordinates, WalletPolicy, WalletPolicyCoordinates},
    bip388::KeyExpression,
};

use alloc::{collections::btree_map::BTreeMap, string::String, vec::Vec};
use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    consensus::Encodable,
    psbt::{self, raw::ProprietaryKey, Psbt},
    TapLeafHash,
};

use super::{GlobalHasProprietaryFields, InputHasProprietaryFields, OutputHasProprietaryFields};

/// Proprietary key prefix for account-related data in PSBT fields
pub const PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER: [u8; 7] = *b"ACCOUNT";

pub const PSBT_ACCOUNT_GLOBAL_ACCOUNT_DESCRIPTOR: u8 = 0x00;
pub const PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME: u8 = 0x01;
pub const PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR: u8 = 0x02;

pub const PSBT_ACCOUNT_IN_COORDINATES: u8 = 0x00;
pub const PSBT_ACCOUNT_OUT_COORDINATES: u8 = 0x00;

// the largest value that is represented as a single byte in compact size
const MAX_SINGLE_BYTE_COMPACTSIZE: u8 = 252;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtAccountError {
    EmptyValue,
    InvalidAccountName,
    UnknownAccountType,
    AccountIdTooLarge,
    InvalidValue,
    TooManyAccounts,
    DeserializeError,
    Unsupported,
}

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

pub trait PsbtAccountGlobalRead: GlobalHasProprietaryFields {
    fn get_accounts(&self) -> Result<Vec<PsbtAccount>, PsbtAccountError> {
        let mut id = 0u32;
        let mut res = Vec::new();
        loop {
            match self.get_account(id)? {
                Some(account) => {
                    res.push(account);
                    id += 1;
                }
                None => break,
            }
        }
        Ok(res)
    }
    fn get_account(&self, id: u32) -> Result<Option<PsbtAccount>, PsbtAccountError> {
        let mut id_raw = Vec::with_capacity(1);
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        for entry in self.iter_proprietary() {
            if entry.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && entry.subtype == PSBT_ACCOUNT_GLOBAL_ACCOUNT_DESCRIPTOR
                && entry.key == id_raw.as_slice()
            {
                let value = entry.value;
                if value.is_empty() {
                    return Err(PsbtAccountError::EmptyValue);
                }
                return match value[0] {
                    0 => {
                        let wp = WalletPolicy::deserialize(&mut &value[1..])
                            .map_err(|_| PsbtAccountError::DeserializeError)?;
                        Ok(Some(PsbtAccount::WalletPolicy(wp)))
                    }
                    _ => Err(PsbtAccountError::UnknownAccountType),
                };
            }
        }
        Ok(None)
    }
    fn get_account_name(&self, id: u32) -> Result<Option<String>, PsbtAccountError> {
        let mut id_raw = Vec::with_capacity(1);
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        for entry in self.iter_proprietary() {
            if entry.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && entry.subtype == PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME
                && entry.key == id_raw.as_slice()
            {
                if !is_valid_account_name(entry.value) {
                    return Err(PsbtAccountError::InvalidAccountName);
                }
                return Ok(Some(String::from_utf8(entry.value.to_vec()).unwrap()));
            }
        }
        Ok(None)
    }
    fn get_account_proof_of_registration(
        &self,
        id: u32,
    ) -> Result<Option<Vec<u8>>, PsbtAccountError> {
        let mut id_raw = Vec::with_capacity(1);
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        for entry in self.iter_proprietary() {
            if entry.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && entry.subtype == PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR
                && entry.key == id_raw.as_slice()
            {
                if entry.value.is_empty() {
                    return Err(PsbtAccountError::EmptyValue);
                }
                return Ok(Some(entry.value.to_vec()));
            }
        }
        Ok(None)
    }
}

impl<T: GlobalHasProprietaryFields> PsbtAccountGlobalRead for T {}

pub trait PsbtAccountGlobalWrite {
    fn set_account(&mut self, id: u32, account: PsbtAccount) -> Result<(), PsbtAccountError>;
    fn set_accounts(&mut self, accounts: Vec<PsbtAccount>) -> Result<(), PsbtAccountError> {
        for (i, account) in accounts.into_iter().enumerate() {
            self.set_account(i as u32, account)?;
        }
        Ok(())
    }
    fn set_account_name(&mut self, id: u32, name: &str) -> Result<(), PsbtAccountError>;
    fn set_account_proof_of_registration(
        &mut self,
        id: u32,
        por: &[u8],
    ) -> Result<(), PsbtAccountError>;
}

pub trait PsbtAccountInputRead: InputHasProprietaryFields {
    fn get_account_coordinates(
        &self,
    ) -> Result<Option<(u32, PsbtAccountCoordinates)>, PsbtAccountError> {
        for entry in self.iter_proprietary() {
            if entry.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && entry.subtype == PSBT_ACCOUNT_IN_COORDINATES
                && entry.key.is_empty()
            {
                let value = entry.value;
                if value.len() < 3 {
                    return Err(PsbtAccountError::InvalidValue);
                }
                let account_id = value[0] as u32;
                if account_id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
                    return Err(PsbtAccountError::AccountIdTooLarge);
                }
                match value[1] {
                    0 => {
                        let coords = AccountCoordinates::deserialize(&mut &value[2..])
                            .map_err(|_| PsbtAccountError::DeserializeError)?;
                        return Ok(Some((
                            account_id,
                            PsbtAccountCoordinates::WalletPolicy(coords),
                        )));
                    }
                    _ => return Err(PsbtAccountError::UnknownAccountType),
                }
            }
        }
        Ok(None)
    }
}

impl<T: InputHasProprietaryFields> PsbtAccountInputRead for T {}

pub trait PsbtAccountOutputRead: OutputHasProprietaryFields {
    fn get_account_coordinates(
        &self,
    ) -> Result<Option<(u32, PsbtAccountCoordinates)>, PsbtAccountError> {
        for entry in self.iter_proprietary() {
            if entry.prefix == PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER
                && entry.subtype == PSBT_ACCOUNT_OUT_COORDINATES
                && entry.key.is_empty()
            {
                let value = entry.value;
                if value.len() < 3 {
                    return Err(PsbtAccountError::InvalidValue);
                }
                let account_id = value[0] as u32;
                if account_id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
                    return Err(PsbtAccountError::AccountIdTooLarge);
                }
                match value[1] {
                    0 => {
                        let coords = AccountCoordinates::deserialize(&mut &value[2..])
                            .map_err(|_| PsbtAccountError::DeserializeError)?;
                        return Ok(Some((
                            account_id,
                            PsbtAccountCoordinates::WalletPolicy(coords),
                        )));
                    }
                    _ => return Err(PsbtAccountError::UnknownAccountType),
                }
            }
        }
        Ok(None)
    }
}

impl<T: OutputHasProprietaryFields> PsbtAccountOutputRead for T {}

pub trait PsbtAccountInputWrite {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), PsbtAccountError>;
}

pub trait PsbtAccountOutputWrite {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), PsbtAccountError>;
}

impl PsbtAccountGlobalWrite for Psbt {
    fn set_account(&mut self, id: u32, account: PsbtAccount) -> Result<(), PsbtAccountError> {
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

    fn set_account_name(&mut self, id: u32, name: &str) -> Result<(), PsbtAccountError> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_NAME,
            key: id_raw,
        };

        if !is_valid_account_name(name.as_bytes()) {
            return Err(PsbtAccountError::InvalidAccountName);
        }
        self.proprietary.insert(key, name.as_bytes().to_vec());

        Ok(())
    }

    fn set_account_proof_of_registration(
        &mut self,
        id: u32,
        por: &[u8],
    ) -> Result<(), PsbtAccountError> {
        let mut id_raw = Vec::with_capacity(1); // unlikely to be more than 1 byte
        let _ = id.consensus_encode(&mut id_raw).unwrap();
        let key = ProprietaryKey {
            prefix: PSBT_ACCOUNT_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_ACCOUNT_GLOBAL_ACCOUNT_POR,
            key: id_raw,
        };

        if por.len() < 1 {
            return Err(PsbtAccountError::EmptyValue);
        }

        self.proprietary.insert(key, por.to_vec());

        Ok(())
    }
}

impl PsbtAccountInputWrite for psbt::Input {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), PsbtAccountError> {
        if id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
            return Err(PsbtAccountError::AccountIdTooLarge);
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

impl PsbtAccountOutputWrite for psbt::Output {
    fn set_account_coordinates(
        &mut self,
        id: u32,
        coordinates: PsbtAccountCoordinates,
    ) -> Result<(), PsbtAccountError> {
        if id > MAX_SINGLE_BYTE_COMPACTSIZE as u32 {
            // specs would want a compact size, but we use 1 byte for simplicity
            return Err(PsbtAccountError::TooManyAccounts);
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
    fingerprint: Fingerprint,
    origin_path_len: usize,
    key_placeholder: &KeyExpression,
) -> Option<WalletPolicyCoordinates> {
    // iterate over all derivations; if it's a key derived from the internal key,
    // deduce the coordinates and insert them
    for (_, (fpr, der)) in bip32_derivation.iter() {
        if *fpr != fingerprint {
            continue;
        }
        if origin_path_len + 2 != der.len() {
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
        if *fpr != fingerprint {
            continue;
        }
        if origin_path_len + 2 != der.len() {
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
    key_placeholder: &KeyExpression,
    account_id: u32,
) -> Result<(), PsbtAccountError> {
    psbt.set_account(account_id, PsbtAccount::WalletPolicy(wallet_policy.clone()))?;
    if let Some(name) = name {
        psbt.set_account_name(account_id, name)?;
    }
    if let Some(por) = proof_of_registrations {
        psbt.set_account_proof_of_registration(account_id, por)?;
    }

    // For a plain key, look up the single referenced KeyInformation.
    // For a musig key, every participant is a candidate; the input matches if
    // any one of them has a derivation in the PSBT under the placeholder.
    let key_indices: Vec<u32> = match (
        key_placeholder.plain_key_index(),
        key_placeholder.musig_key_indices(),
    ) {
        (Some(idx), _) => alloc::vec![idx],
        (None, Some(indices)) => indices.clone(),
        _ => return Err(PsbtAccountError::Unsupported),
    };

    // For each candidate participant, build the (fingerprint, origin_path_len)
    // pair used to identify its derivations inside the PSBT.
    let mut lookups: Vec<(Fingerprint, usize)> = key_indices
        .iter()
        .map(|&idx| {
            let key_expr = wallet_policy
                .key_information()
                .get(idx as usize)
                .ok_or(PsbtAccountError::InvalidValue)?;
            Ok(match &key_expr.origin_info {
                Some(orig) => (
                    orig.fingerprint.to_be_bytes().into(),
                    orig.derivation_path.len(),
                ),
                None => (key_expr.pubkey.fingerprint(), 0),
            })
        })
        .collect::<Result<_, _>>()?;

    // For a musig placeholder, the BIP-373 `tap_bip32_derivation` entry is
    // keyed by the BIP-32-derived *aggregate* xonly key — with the aggregate
    // BIP-388 synthetic xpub's fingerprint, not any single participant's.
    // Add that as an extra lookup candidate so we don't miss the entry.
    if key_placeholder.is_musig() {
        let participant_xpubs: alloc::vec::Vec<_> = key_indices
            .iter()
            .map(|&idx| {
                wallet_policy
                    .key_information()
                    .get(idx as usize)
                    .ok_or(PsbtAccountError::InvalidValue)
                    .map(|ki| ki.pubkey)
            })
            .collect::<Result<_, _>>()?;
        if let Ok(agg) = crate::musig::aggregate_xpub(&participant_xpubs) {
            lookups.push((agg.fingerprint(), 0));
        }
    }

    let find_coords = |bip32: &_, tap: &_| -> Option<WalletPolicyCoordinates> {
        for (fingerprint, origin_path_len) in &lookups {
            if let Some(c) = get_wallet_policy_coordinates(
                bip32,
                tap,
                *fingerprint,
                *origin_path_len,
                key_placeholder,
            ) {
                return Some(c);
            }
        }
        None
    };

    for input in psbt.inputs.iter_mut() {
        if let Some(coords) = find_coords(&input.bip32_derivation, &input.tap_key_origins) {
            input.set_account_coordinates(
                account_id,
                PsbtAccountCoordinates::WalletPolicy(coords),
            )?;
        }
    }

    for output in psbt.outputs.iter_mut() {
        if let Some(coords) = find_coords(&output.bip32_derivation, &output.tap_key_origins) {
            output.set_account_coordinates(
                account_id,
                PsbtAccountCoordinates::WalletPolicy(coords),
            )?;
        }
    }

    Ok(())
}

// Fills the PSBT with accounts and coordinates.
pub fn prepare_psbt(
    psbt: &mut Psbt,
    named_accounts: &[(&WalletPolicy, &str, &[u8; 32])],
) -> Result<(), PsbtAccountError> {
    // TODO: generalize this function to support transactions involving multiple accounts, and accounts of different types.
    assert!(named_accounts.len() == 1);
    for (wallet_policy, account_name, por) in named_accounts {
        let placeholders: Vec<KeyExpression> = wallet_policy
            .descriptor_template()
            .placeholders()
            .map(|(k, _)| k.clone())
            .collect();

        for key_placeholder in &placeholders {
            fill_psbt_with_bip388_coordinates(
                psbt,
                wallet_policy,
                Some(&account_name),
                Some(*por),
                key_placeholder,
                0,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use bitcoin::psbt::{self, Psbt};

    use super::*;

    const TEST_PSBT: &str = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";

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

        let placeholders: Vec<KeyExpression> = wallet_policy
            .descriptor_template()
            .placeholders()
            .map(|(k, _)| k.clone())
            .collect();
        assert!(placeholders.len() == 1);
        let key_placeholder = &placeholders[0];

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

    /// Coordinate filling for a `tr(musig(@0,@1)/**)` wallet policy: a
    /// derivation entry under *any* participant's fingerprint must yield
    /// matching coordinates.
    #[test]
    fn test_fill_psbt_with_bip388_coordinates_musig() {
        use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};

        let xpub0_str = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
        let xpub1_str = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm";

        let wallet_policy = WalletPolicy::new(
            "tr(musig(@0,@1)/**)",
            vec![xpub0_str.try_into().unwrap(), xpub1_str.try_into().unwrap()],
        )
        .unwrap();

        // Derive cosigner #1's child at /0/7 (is_change = false, address_index = 7).
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let xpub1: Xpub = xpub1_str.parse().unwrap();
        let path = DerivationPath::from(vec![
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 7 },
        ]);
        let child = xpub1.derive_pub(&secp, &path).unwrap();
        let xonly = child.public_key.x_only_public_key().0;

        // Build a minimal one-input PSBT and inject a tap_key_origins entry
        // for cosigner 1's child key.
        let unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0]
            .tap_key_origins
            .insert(xonly, (vec![], (xpub1.fingerprint(), path)));

        let key_placeholder = wallet_policy
            .descriptor_template()
            .placeholders()
            .next()
            .unwrap()
            .0
            .clone();

        fill_psbt_with_bip388_coordinates(&mut psbt, &wallet_policy, None, None, &key_placeholder, 0)
            .unwrap();

        assert_eq!(
            psbt.inputs[0].get_account_coordinates().unwrap(),
            Some((
                0,
                PsbtAccountCoordinates::WalletPolicy(WalletPolicyCoordinates::new(false, 7))
            )),
        );
    }
}
