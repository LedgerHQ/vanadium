//! Identifies whether a wallet-policy key is locally controlled, and resolves it to
//! the private key material needed for signing.

use alloc::vec::Vec;

use bitcoin::bip32::ChildNumber;
use common::{bip388::KeyInformation, errors::Error};
use sdk::curve::{Curve, EcfpPrivateKey, HDPrivNode, ToPublicKey};

use crate::bip32::KeyTree;
use crate::resident_key::{derive_resident_hd_node, get_resident_master_fingerprint};

/// Identifies how the signing private key should be obtained: a key tree and a
/// full BIP-32 derivation path relative to that tree's master.
pub(super) struct KeySource {
    pub(super) tree: KeyTree,
    pub(super) path: Vec<ChildNumber>,
}

fn derive_hd_node(
    tree: KeyTree,
    path: &[u32],
) -> Result<HDPrivNode<sdk::curve::Secp256k1, 32>, Error> {
    match tree {
        KeyTree::Standard => {
            sdk::curve::Secp256k1::derive_hd_node(path).map_err(|_| Error::KeyDerivationFailed)
        }
        KeyTree::Resident => derive_resident_hd_node(path),
    }
}

/// Resolves a `KeySource` into an `HDPrivNode` containing the final private key.
pub(super) fn resolve_private_key(
    key_source: &KeySource,
) -> Result<HDPrivNode<sdk::curve::Secp256k1, 32>, Error> {
    let path: Vec<u32> = key_source.path.iter().map(|&x| x.into()).collect();
    derive_hd_node(key_source.tree, &path)
}

/// The device's two key trees, and which wallet-policy keys have been found to live in
/// them.
///
/// Deciding that re-derives a key's claimed master node from the seed, which is
/// expensive; the answer depends only on the key, but the question gets asked once per
/// (input, placeholder). So each answer is remembered.
pub(super) struct LocalKeys {
    standard_fpr: u32,
    resident_fpr: u32,
    /// `(account id, key-information index)` → the tree that key lives in, if any.
    seen: Vec<((u32, u32), Option<KeyTree>)>,
}

impl LocalKeys {
    pub(super) fn new() -> Result<Self, Error> {
        Ok(Self {
            standard_fpr: sdk::curve::Secp256k1::get_master_fingerprint(),
            resident_fpr: get_resident_master_fingerprint()?,
            seen: Vec::new(),
        })
    }

    /// Identifies whether `key_info` refers to a locally-controlled key (Standard
    /// or Resident tree) and, if so, returns the [`KeySource`] for signing.
    ///
    /// `key_id` is `(account id, index into that account's key information)`, and only
    /// identifies the key for caching purposes.
    ///
    /// If `child_steps` is `Some((change_step, address_index))`, the returned
    /// `KeySource` includes those as the final two BIP-32 steps — this is the
    /// plain-key signing path. If `child_steps` is `None`, the `KeySource` stops
    /// at the master xpub (no extra derivation) — this is the BIP-388 musig
    /// signing path, where the master key signs and BIP-32 derivation is folded
    /// into `crate::handlers::musig_signing`'s session tweaks.
    ///
    /// Returns `None` if:
    /// - the key has no origin info (bare xpub, can't be derived locally), or
    /// - the fingerprint matches neither local tree, or
    /// - the local derivation doesn't yield the claimed pubkey/chaincode.
    pub(super) fn resolve(
        &mut self,
        key_info: &KeyInformation,
        key_id: (u32, u32),
        child_steps: Option<(ChildNumber, ChildNumber)>,
    ) -> Option<KeySource> {
        let tree = self.tree_of(key_info, key_id)?;
        let key_origin = key_info.origin_info.as_ref()?;

        let mut path: Vec<ChildNumber> = key_origin.derivation_path.to_vec();
        if let Some((change_step, address_index)) = child_steps {
            path.push(change_step);
            path.push(address_index);
        }
        Some(KeySource { tree, path })
    }

    fn tree_of(&mut self, key_info: &KeyInformation, key_id: (u32, u32)) -> Option<KeyTree> {
        if let Some((_, tree)) = self.seen.iter().find(|(id, _)| *id == key_id) {
            return *tree;
        }
        let tree = self.check_key_origin(key_info);
        self.seen.push((key_id, tree));
        tree
    }

    /// Derives the master xpub locally and checks it matches what the wallet policy
    /// claims; defeats fingerprint collisions.
    fn check_key_origin(&self, key_info: &KeyInformation) -> Option<KeyTree> {
        let key_origin = key_info.origin_info.as_ref()?;

        let tree = if key_origin.fingerprint == self.standard_fpr {
            KeyTree::Standard
        } else if key_origin.fingerprint == self.resident_fpr {
            KeyTree::Resident
        } else {
            return None;
        };

        let master_path_u32: Vec<u32> = key_origin
            .derivation_path
            .iter()
            .map(|&s| u32::from(s))
            .collect();
        let claim_node = derive_hd_node(tree, &master_path_u32).ok()?;
        let derived_pubkey = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*claim_node.privkey)
            .to_public_key()
            .to_compressed();
        let expected_pubkey = key_info.pubkey.public_key.serialize();
        let expected_chaincode: &[u8; 32] = key_info.pubkey.chain_code.as_ref();
        if derived_pubkey != expected_pubkey || claim_node.chaincode != *expected_chaincode {
            return None;
        }

        Some(tree)
    }
}
