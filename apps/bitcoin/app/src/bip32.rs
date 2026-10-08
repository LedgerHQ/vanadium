/// The bitcoin app supports derivation of BIP-32 keys from two different trees: the standard tree,
/// which is derived from the device seed; and the resident tree, which is derived from a random
/// seed that is generated in the app and stored in its storage, and never exported.
/// This module implements simple derivation logic for both trees.
use common::errors::Error;
use sdk::curve::{Curve, HDPrivNode, Secp256k1, MAX_BIP32_PATH_LEN};

use crate::resident_key::{derive_resident_hd_node, get_resident_master_fingerprint};

pub use common::message::KeyTree;

/// Derives an HD node at the given path under the selected key tree.
///
/// The standard tree is derived by the device, which accepts paths of at most
/// [`MAX_BIP32_PATH_LEN`] steps.
pub fn derive_hd_node(tree: KeyTree, path: &[u32]) -> Result<HDPrivNode<Secp256k1, 32>, Error> {
    match tree {
        KeyTree::Standard => {
            if path.len() > MAX_BIP32_PATH_LEN {
                return Err(Error::DerivationPathTooLong);
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_tree_path_length() {
        let longest = [0x8000_0000u32; MAX_BIP32_PATH_LEN];
        assert!(derive_hd_node(KeyTree::Standard, &longest).is_ok());
        assert_eq!(
            derive_hd_node(KeyTree::Standard, &[0x8000_0000u32; MAX_BIP32_PATH_LEN + 1]).err(),
            Some(Error::DerivationPathTooLong)
        );
    }
}
