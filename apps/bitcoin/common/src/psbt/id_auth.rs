use alloc::{string::String, vec::Vec};

use super::{v2, GlobalHasProprietaryFields, OutputHasProprietaryFields, PsbtV2};

/// Proprietary key prefix for output authentication data in PSBT fields
pub const PSBT_IDAUTH_PROPRIETARY_IDENTIFIER: [u8; 6] = *b"IDAUTH";

/// Subkey type for a registered identity key in the global PSBT map
pub const PSBT_IDAUTH_GLOBAL_REGISTERED_IDENTITY_KEY: u8 = 0x00;

/// Subkey type for output authentication proof (per-output only)
pub const PSBT_IDAUTH_OUT_SIGNATURE: u8 = 0x00;

/// auth_tag value for identity-based Schnorr signatures
pub const PSBT_IDAUTH_TAG_IDENTITY: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtIdAuthError {
    MalformedEntry,
    InvalidNameLength,
    InvalidUtf8,
    InvalidSignatureLength,
}

/// A registered identity key entry stored in the global PSBT section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredIdentityKey {
    /// The compressed secp256k1 public key (33 bytes).
    pub pubkey: [u8; 33],
    /// The registered name of the identity key.
    pub name: String,
    /// The 32-byte proof of registration.
    pub por: [u8; 32],
}

/// An output authentication proof, stored in a per-output PSBT proprietary field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputAuthProof {
    /// An identity-based Schnorr signature over the output's scriptPubKey.
    IdentitySignature {
        /// The compressed identity public key (33 bytes).
        pubkey: [u8; 33],
        /// The 64-byte Schnorr signature.
        sig: [u8; 64],
    },
    // other auth types will be added here
}

pub trait PsbtIdAuthGlobalRead: GlobalHasProprietaryFields {
    /// Returns all well-formed registered identity key entries from the global PSBT map.
    /// Malformed entries return an error.
    fn get_registered_identity_keys(&self) -> Result<Vec<RegisteredIdentityKey>, PsbtIdAuthError> {
        let mut entries = Vec::new();
        for entry in self.iter_proprietary() {
            if entry.prefix != PSBT_IDAUTH_PROPRIETARY_IDENTIFIER {
                continue;
            }
            if entry.subtype != PSBT_IDAUTH_GLOBAL_REGISTERED_IDENTITY_KEY {
                continue;
            }
            if entry.key.len() != 33 {
                return Err(PsbtIdAuthError::MalformedEntry);
            }
            let mut pubkey = [0u8; 33];
            pubkey.copy_from_slice(entry.key);

            let value = entry.value;
            if value.len() < 1 + 1 + 32 {
                return Err(PsbtIdAuthError::MalformedEntry);
            }
            let name_len = value[0] as usize;
            if name_len == 0 {
                return Err(PsbtIdAuthError::MalformedEntry);
            }
            if value.len() != 1 + name_len + 32 {
                return Err(PsbtIdAuthError::MalformedEntry);
            }
            let name = String::from_utf8(value[1..1 + name_len].to_vec())
                .map_err(|_| PsbtIdAuthError::InvalidUtf8)?;
            let mut por = [0u8; 32];
            por.copy_from_slice(&value[1 + name_len..1 + name_len + 32]);

            entries.push(RegisteredIdentityKey { pubkey, name, por });
        }
        Ok(entries)
    }
}

impl<T: GlobalHasProprietaryFields> PsbtIdAuthGlobalRead for T {}

pub trait PsbtIdAuthGlobalWrite {
    /// Adds a registered identity key entry to the global PSBT map.
    fn add_registered_identity_key(
        &mut self,
        entry: &RegisteredIdentityKey,
    ) -> Result<(), PsbtIdAuthError>;
}

pub trait PsbtOutputAuthRead: OutputHasProprietaryFields {
    /// Returns all well-formed output authentication proofs for this output.
    /// Unknown auth_tag values and malformed entries are silently skipped.
    fn get_auth_proofs(&self) -> Result<Vec<OutputAuthProof>, PsbtIdAuthError> {
        let mut proofs = Vec::new();
        for entry in self.iter_proprietary() {
            if entry.prefix != PSBT_IDAUTH_PROPRIETARY_IDENTIFIER {
                continue;
            }
            if entry.subtype != PSBT_IDAUTH_OUT_SIGNATURE {
                continue;
            }
            // key must be: [auth_tag (1 byte), pubkey (33 bytes)]
            if entry.key.len() != 34 {
                return Err(PsbtIdAuthError::MalformedEntry);
            }
            let auth_tag = entry.key[0];
            if entry.value.len() != 64 {
                return Err(PsbtIdAuthError::MalformedEntry);
            }
            match auth_tag {
                PSBT_IDAUTH_TAG_IDENTITY => {
                    let mut pubkey = [0u8; 33];
                    pubkey.copy_from_slice(&entry.key[1..34]);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(entry.value);
                    proofs.push(OutputAuthProof::IdentitySignature { pubkey, sig });
                }
                _ => return Err(PsbtIdAuthError::MalformedEntry), // unknown auth_tag — error
            }
        }
        Ok(proofs)
    }
}

impl<T: OutputHasProprietaryFields> PsbtOutputAuthRead for T {}

pub trait PsbtOutputAuthWrite {
    /// Adds an output authentication proof to this output.
    /// The proprietary key is `(PSBT_IDAUTH_OUT_SIGNATURE, [auth_tag, pubkey])` and the
    /// value is the 64-byte Schnorr signature.
    fn add_auth_proof(&mut self, proof: &OutputAuthProof) -> Result<(), PsbtIdAuthError>;
}

impl PsbtIdAuthGlobalWrite for PsbtV2 {
    fn add_registered_identity_key(
        &mut self,
        entry: &RegisteredIdentityKey,
    ) -> Result<(), PsbtIdAuthError> {
        if entry.name.is_empty() || entry.name.len() > 255 {
            return Err(PsbtIdAuthError::InvalidNameLength);
        }
        let name_bytes = entry.name.as_bytes();
        // value: <name_len (1 byte)> <name> <32-byte por>
        let mut value = Vec::with_capacity(1 + name_bytes.len() + 32);
        value.push(name_bytes.len() as u8);
        value.extend_from_slice(name_bytes);
        value.extend_from_slice(&entry.por);
        self.global.insert_proprietary(
            &PSBT_IDAUTH_PROPRIETARY_IDENTIFIER,
            PSBT_IDAUTH_GLOBAL_REGISTERED_IDENTITY_KEY,
            &entry.pubkey,
            value,
        );
        Ok(())
    }
}

impl PsbtOutputAuthWrite for v2::Output {
    fn add_auth_proof(&mut self, proof: &OutputAuthProof) -> Result<(), PsbtIdAuthError> {
        match proof {
            OutputAuthProof::IdentitySignature { pubkey, sig } => {
                let mut key_bytes = Vec::with_capacity(34);
                key_bytes.push(PSBT_IDAUTH_TAG_IDENTITY);
                key_bytes.extend_from_slice(pubkey);
                self.insert_proprietary(
                    &PSBT_IDAUTH_PROPRIETARY_IDENTIFIER,
                    PSBT_IDAUTH_OUT_SIGNATURE,
                    &key_bytes,
                    sig.to_vec(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Psbt;

    use super::*;

    /// A PSBT without inputs and outputs.
    fn empty_psbt() -> PsbtV2 {
        let unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        PsbtV2::from_v0(&psbt.serialize()).unwrap()
    }

    // --- Global identity key tests ---

    #[test]
    fn test_add_and_get_registered_identity_key() {
        let mut psbt = empty_psbt();

        let entry = RegisteredIdentityKey {
            pubkey: [0x02u8; 33],
            name: "My Identity".to_string(),
            por: [0xAAu8; 32],
        };

        psbt.add_registered_identity_key(&entry).unwrap();

        let entries = psbt.get_registered_identity_keys().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }

    #[test]
    fn test_add_multiple_registered_identity_keys() {
        let mut psbt = empty_psbt();

        let entry1 = RegisteredIdentityKey {
            pubkey: [0x02u8; 33],
            name: "Alice".to_string(),
            por: [0x11u8; 32],
        };
        let entry2 = RegisteredIdentityKey {
            pubkey: [0x03u8; 33],
            name: "Bob".to_string(),
            por: [0x22u8; 32],
        };

        psbt.add_registered_identity_key(&entry1).unwrap();
        psbt.add_registered_identity_key(&entry2).unwrap();

        let entries = psbt.get_registered_identity_keys().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&entry1));
        assert!(entries.contains(&entry2));
    }

    #[test]
    fn test_registered_identity_key_empty_name_rejected() {
        let mut psbt = empty_psbt();

        let entry = RegisteredIdentityKey {
            pubkey: [0x02u8; 33],
            name: "".to_string(),
            por: [0xAAu8; 32],
        };
        assert!(psbt.add_registered_identity_key(&entry).is_err());
    }

    // --- Per-output auth proof tests ---

    #[test]
    fn test_add_and_get_output_auth_proof() {
        let mut output = v2::Output::default();
        let pubkey = [0x02u8; 33]; // dummy compressed pubkey
        let sig = [0x11u8; 64]; // dummy Schnorr signature
        let proof = OutputAuthProof::IdentitySignature { pubkey, sig };

        output.add_auth_proof(&proof).unwrap();

        let proofs = output.get_auth_proofs().unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0], proof);
    }

    #[test]
    fn test_output_auth_multiple_proofs() {
        let mut output = v2::Output::default();
        let pubkey1 = [0x02u8; 33];
        let sig1 = [0x11u8; 64];
        let pubkey2 = [0x03u8; 33];
        let sig2 = [0x22u8; 64];

        output
            .add_auth_proof(&OutputAuthProof::IdentitySignature {
                pubkey: pubkey1,
                sig: sig1,
            })
            .unwrap();
        output
            .add_auth_proof(&OutputAuthProof::IdentitySignature {
                pubkey: pubkey2,
                sig: sig2,
            })
            .unwrap();

        let proofs = output.get_auth_proofs().unwrap();
        assert_eq!(proofs.len(), 2);
    }

    #[test]
    fn test_output_auth_malformed_value_returns_error() {
        let mut output = v2::Output::default();
        // Manually insert a malformed entry (wrong signature length)
        let mut key_bytes = Vec::with_capacity(34);
        key_bytes.push(PSBT_IDAUTH_TAG_IDENTITY);
        key_bytes.extend_from_slice(&[0x02u8; 33]);
        output.insert_proprietary(
            &PSBT_IDAUTH_PROPRIETARY_IDENTIFIER,
            PSBT_IDAUTH_OUT_SIGNATURE,
            &key_bytes,
            vec![0x11u8; 32], // wrong: 32 bytes instead of 64
        );

        let proofs = output.get_auth_proofs();
        assert_eq!(proofs, Err(PsbtIdAuthError::MalformedEntry));
    }
}
