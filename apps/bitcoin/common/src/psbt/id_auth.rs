use alloc::vec::Vec;
use bitcoin::psbt::{self, raw::ProprietaryKey};

/// Proprietary key prefix for output authentication data in PSBT fields
pub const PSBT_IDAUTH_PROPRIETARY_IDENTIFIER: [u8; 6] = *b"IDAUTH";

/// Subkey type for output authentication proof (per-output only)
pub const PSBT_IDAUTH_OUT_SIGNATURE: u8 = 0x00;

/// auth_tag value for identity-based Schnorr signatures
pub const PSBT_IDAUTH_TAG_IDENTITY: u8 = 0x00;

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

pub trait PsbtOutputAuthRead {
    /// Returns all well-formed output authentication proofs for this output.
    /// Unknown auth_tag values and malformed entries are silently skipped.
    fn get_auth_proofs(&self) -> Result<Vec<OutputAuthProof>, &'static str>;
}

pub trait PsbtOutputAuthWrite {
    /// Adds an output authentication proof to this output.
    /// The proprietary key is `(PSBT_IDAUTH_OUT_SIGNATURE, [auth_tag, pubkey])` and the
    /// value is the 64-byte Schnorr signature.
    fn add_auth_proof(&mut self, proof: &OutputAuthProof) -> Result<(), &'static str>;
}

impl PsbtOutputAuthRead for psbt::Output {
    fn get_auth_proofs(&self) -> Result<Vec<OutputAuthProof>, &'static str> {
        let mut proofs = Vec::new();
        for (key, value) in &self.proprietary {
            if key.prefix != PSBT_IDAUTH_PROPRIETARY_IDENTIFIER.to_vec() {
                continue;
            }
            if key.subtype != PSBT_IDAUTH_OUT_SIGNATURE {
                continue;
            }
            // key.key must be: [auth_tag (1 byte), pubkey (33 bytes)]
            if key.key.len() != 34 {
                continue; // malformed — skip
            }
            let auth_tag = key.key[0];
            // value must be exactly 64 bytes
            if value.len() != 64 {
                continue; // malformed — skip
            }
            match auth_tag {
                PSBT_IDAUTH_TAG_IDENTITY => {
                    let mut pubkey = [0u8; 33];
                    pubkey.copy_from_slice(&key.key[1..34]);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(&value[..64]);
                    proofs.push(OutputAuthProof::IdentitySignature { pubkey, sig });
                }
                _ => continue, // unknown auth_tag — skip
            }
        }
        Ok(proofs)
    }
}

impl PsbtOutputAuthWrite for psbt::Output {
    fn add_auth_proof(&mut self, proof: &OutputAuthProof) -> Result<(), &'static str> {
        match proof {
            OutputAuthProof::IdentitySignature { pubkey, sig } => {
                let mut key_bytes = Vec::with_capacity(34);
                key_bytes.push(PSBT_IDAUTH_TAG_IDENTITY);
                key_bytes.extend_from_slice(pubkey);
                let key = ProprietaryKey {
                    prefix: PSBT_IDAUTH_PROPRIETARY_IDENTIFIER.to_vec(),
                    subtype: PSBT_IDAUTH_OUT_SIGNATURE,
                    key: key_bytes,
                };
                self.proprietary.insert(key, sig.to_vec());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::psbt::{self, raw::ProprietaryKey};

    use super::*;

    #[test]
    fn test_add_and_get_output_auth_proof() {
        let mut output = psbt::Output::default();
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
        let mut output = psbt::Output::default();
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
    fn test_output_auth_malformed_value_skipped() {
        let mut output = psbt::Output::default();
        // Manually insert a malformed entry (wrong signature length)
        let mut key_bytes = Vec::with_capacity(34);
        key_bytes.push(PSBT_IDAUTH_TAG_IDENTITY);
        key_bytes.extend_from_slice(&[0x02u8; 33]);
        let key = ProprietaryKey {
            prefix: PSBT_IDAUTH_PROPRIETARY_IDENTIFIER.to_vec(),
            subtype: PSBT_IDAUTH_OUT_SIGNATURE,
            key: key_bytes,
        };
        output.proprietary.insert(key, vec![0x11u8; 32]); // wrong: 32 bytes instead of 64

        let proofs = output.get_auth_proofs().unwrap();
        assert_eq!(proofs.len(), 0); // malformed entry is skipped
    }
}

impl<'a> PsbtOutputAuthRead for crate::fastpsbt::Output<'a> {
    fn get_auth_proofs(&self) -> Result<Vec<OutputAuthProof>, &'static str> {
        // Proprietary key_data format for ID_AUTH:
        // [prefix_len=7][b"ID_AUTH"][subtype=0x00][auth_tag(1)][pubkey(33)]
        // total key_data length: 1 + 7 + 1 + 1 + 33 = 43
        const EXPECTED_KD_LEN: usize = 1 + 7 + 1 + 1 + 33;

        let mut proofs = Vec::new();
        for (kd, value) in self.iter_keys(0xFC) {
            if kd.len() != EXPECTED_KD_LEN {
                continue;
            }
            let prefix_len = kd[0] as usize;
            if prefix_len != PSBT_IDAUTH_PROPRIETARY_IDENTIFIER.len() {
                continue;
            }
            let prefix = &kd[1..1 + prefix_len];
            if prefix != PSBT_IDAUTH_PROPRIETARY_IDENTIFIER {
                continue;
            }
            let subtype = kd[1 + prefix_len];
            if subtype != PSBT_IDAUTH_OUT_SIGNATURE {
                continue;
            }
            let auth_tag = kd[1 + prefix_len + 1];
            if value.len() != 64 {
                continue; // malformed — skip
            }
            match auth_tag {
                PSBT_IDAUTH_TAG_IDENTITY => {
                    let mut pubkey = [0u8; 33];
                    pubkey.copy_from_slice(&kd[1 + prefix_len + 2..1 + prefix_len + 2 + 33]);
                    let mut sig = [0u8; 64];
                    sig.copy_from_slice(value);
                    proofs.push(OutputAuthProof::IdentitySignature { pubkey, sig });
                }
                _ => continue, // unknown auth_tag — skip
            }
        }
        Ok(proofs)
    }
}
