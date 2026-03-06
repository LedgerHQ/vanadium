use alloc::vec::Vec;
use common::{errors::Error, identity, message::IdentitySignature};
use sdk::curve::{Curve, EcfpPrivateKey, Secp256k1, ToPublicKey};

/// Derives the i-th identity key and signs the given object with it.
pub(crate) fn compute_identity_signature(
    msg_type: &[u8],
    object: &[u8],
    identity_index: u32,
) -> Result<IdentitySignature, Error> {
    let id_path = identity::identity_derivation_path(Some(identity_index));
    let id_node =
        sdk::curve::Secp256k1::derive_hd_node(&id_path).map_err(|_| Error::KeyDerivationFailed)?;
    let id_privkey: EcfpPrivateKey<Secp256k1, 32> = EcfpPrivateKey::new(*id_node.privkey);
    let id_pubkey = id_privkey.to_public_key();
    let id_pubkey_bytes = id_pubkey.as_ref().to_bytes();

    // Compressed public key: 0x02 or 0x03 prefix + 32-byte x-coordinate
    let mut compressed_pubkey = Vec::with_capacity(33);
    compressed_pubkey.push(id_pubkey_bytes[64] % 2 + 0x02);
    compressed_pubkey.extend_from_slice(&id_pubkey_bytes[1..33]);

    let msg = identity::build_identity_message(msg_type, object)?;
    let signature = id_privkey
        .schnorr_sign(&msg, None)
        .map_err(|_| Error::SigningFailed)?;

    Ok(IdentitySignature {
        identity_pubkey: compressed_pubkey,
        signature,
    })
}
