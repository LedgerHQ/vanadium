use common::{errors::Error, identity, message::IdentitySignature};
use sdk::curve::{EcfpPrivateKey, Secp256k1, ToPublicKey};

use crate::bip32::{self, KeyTree};

/// Derives the i-th identity key and signs the given object with it.
pub(crate) fn compute_identity_signature(
    msg_type: &[u8],
    object: &[u8],
    identity_index: u32,
) -> Result<IdentitySignature, Error> {
    let id_path = identity::identity_derivation_path(Some(identity_index));
    let id_node = bip32::derive_hd_node(KeyTree::Standard, &id_path)?;
    let id_privkey: EcfpPrivateKey<Secp256k1, 32> = EcfpPrivateKey::new(*id_node.privkey);

    let msg = identity::build_identity_message(msg_type, object)?;
    let signature = id_privkey
        .schnorr_sign(&msg, None)
        .map_err(|_| Error::SigningFailed)?;

    Ok(IdentitySignature {
        identity_pubkey: id_privkey.to_public_key().to_compressed().to_vec(),
        signature,
    })
}
