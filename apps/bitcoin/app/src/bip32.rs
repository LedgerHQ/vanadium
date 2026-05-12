/// The bitcoin app supports derivation of BIP-32 keys from two different trees: the standard tree,
/// which is derived from the device seed; and the resident tree, which is derived from a random
/// seed that is generated in the app and stored in its storage, and never exported.
/// This module implements simple derivation logic for both trees.
use common::errors::Error;
use sdk::curve::{Curve, HDPrivNode, Secp256k1};

use crate::resident_key::{derive_resident_hd_node, get_resident_master_fingerprint};

pub use common::message::KeyTree;

/// Derives an HD node at the given path under the selected key tree.
pub fn derive_hd_node(tree: KeyTree, path: &[u32]) -> Result<HDPrivNode<Secp256k1, 32>, Error> {
    match tree {
        KeyTree::Standard => {
            Secp256k1::derive_hd_node(path).map_err(|_| Error::KeyDerivationFailed)
        }
        KeyTree::Resident => derive_resident_hd_node(path),
    }
}

/// Returns the master fingerprint of the selected key tree.
pub fn master_fingerprint(tree: KeyTree) -> Result<u32, Error> {
    match tree {
        KeyTree::Standard => Ok(Secp256k1::get_master_fingerprint()),
        KeyTree::Resident => get_resident_master_fingerprint(),
    }
}
