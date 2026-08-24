//! Identifies whether a wallet-policy key is locally controlled, and resolves it to
//! the private key material needed for signing.

use alloc::vec::Vec;

use bitcoin::bip32::ChildNumber;
use common::errors::Error;
use sdk::curve::{Curve, EcfpPrivateKey, HDPrivNode, ToPublicKey};

use crate::bip32::KeyTree;
use crate::resident_key::derive_resident_hd_node;

/// Identifies how the signing private key should be obtained: a key tree and a
/// full BIP-32 derivation path relative to that tree's master.
pub(super) struct KeySource {
    pub(super) tree: KeyTree,
    pub(super) path: Vec<ChildNumber>,
}

/// Resolves a `KeySource` into an `HDPrivNode` containing the final private key.
pub(super) fn resolve_private_key(
    key_source: &KeySource,
) -> Result<HDPrivNode<sdk::curve::Secp256k1, 32>, Error> {
    let path: Vec<u32> = key_source.path.iter().map(|&x| x.into()).collect();
    match key_source.tree {
        KeyTree::Standard => {
            sdk::curve::Secp256k1::derive_hd_node(&path).map_err(|_| Error::KeyDerivationFailed)
        }
        KeyTree::Resident => derive_resident_hd_node(&path),
    }
}

/// Identifies whether `key_info` refers to a locally-controlled key (Standard
/// or Resident tree) and, if so, returns the [`KeySource`] for signing.
///
/// If `child_steps` is `Some((change_step, address_index))`, the returned
/// `KeySource` includes those as the final two BIP-32 steps — this is the
/// plain-key signing path. If `child_steps` is `None`, the `KeySource` stops
/// at the master xpub (no extra derivation) — this is the BIP-388 musig
/// signing path, where the master key signs and BIP-32 derivation is folded
/// into [`SessionContext`] tweaks.
///
/// In both cases, the master derivation is recomputed locally and compared
/// against `key_info.pubkey` to defeat fingerprint collisions.
///
/// Returns `None` if:
/// - the key has no origin info (bare xpub, can't be derived locally), or
/// - the fingerprint matches neither local tree, or
/// - the local derivation doesn't yield the claimed pubkey/chaincode.
pub(super) fn resolve_local_key_source(
    key_info: &common::bip388::KeyInformation,
    child_steps: Option<(ChildNumber, ChildNumber)>,
    standard_fpr: u32,
    resident_fpr: u32,
) -> Option<KeySource> {
    let key_origin = key_info.origin_info.as_ref()?;

    let tree = if key_origin.fingerprint == standard_fpr {
        KeyTree::Standard
    } else if key_origin.fingerprint == resident_fpr {
        KeyTree::Resident
    } else {
        return None;
    };

    // Derive the master xpub locally and check it matches what the wallet
    // policy claims; defeats fingerprint collisions.
    let master_path_u32: Vec<u32> = key_origin
        .derivation_path
        .iter()
        .map(|&s| u32::from(s))
        .collect();
    let claim_node = match tree {
        KeyTree::Standard => sdk::curve::Secp256k1::derive_hd_node(&master_path_u32).ok()?,
        KeyTree::Resident => derive_resident_hd_node(&master_path_u32).ok()?,
    };
    let derived_pubkey = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*claim_node.privkey)
        .to_public_key()
        .to_compressed();
    let expected_pubkey = key_info.pubkey.public_key.serialize();
    let expected_chaincode: &[u8; 32] = key_info.pubkey.chain_code.as_ref();
    if derived_pubkey != expected_pubkey || claim_node.chaincode != *expected_chaincode {
        return None;
    }

    let mut path: Vec<ChildNumber> = key_origin.derivation_path.iter().copied().collect();
    if let Some((change_step, address_index)) = child_steps {
        path.push(change_step);
        path.push(address_index);
    }
    Some(KeySource { tree, path })
}
