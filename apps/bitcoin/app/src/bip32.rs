/// The bitcoin app supports derivation of BIP-32 keys from two different trees: the standard tree,
/// which is derived from the device seed; and the resident tree, which is derived from a random
/// seed that is generated in the app and stored in its storage, and never exported.
/// This module implements simple derivation logic for both trees.
use common::errors::Error;
use sdk::curve::{Curve, EcfpPrivateKey, HDPrivNode, Secp256k1, ToPublicKey, MAX_BIP32_PATH_LEN};

use crate::resident_key::{derive_resident_hd_node, get_resident_master_fingerprint};

pub use common::message::KeyTree;

/// Derives an HD node at the given path under the selected key tree.
///
/// The standard tree is derived by the device, which accepts paths of at most
/// [`MAX_BIP32_PATH_LEN`] steps.
pub fn derive_hd_node(tree: KeyTree, path: &[u32]) -> Result<HDPrivNode<Secp256k1, 32>, Error> {
    check_path_len(tree, path)?;
    match tree {
        KeyTree::Standard => {
            Secp256k1::derive_hd_node(path).map_err(|_| Error::KeyDerivationFailed)
        }
        KeyTree::Resident => derive_resident_hd_node(path),
    }
}

/// Fails if `path` is too long to derive under `tree`.
fn check_path_len(tree: KeyTree, path: &[u32]) -> Result<(), Error> {
    if tree == KeyTree::Standard && path.len() > MAX_BIP32_PATH_LEN {
        return Err(Error::DerivationPathTooLong);
    }
    Ok(())
}

/// Derives the HD node at `path` under `tree`, and the fingerprint of its parent (0 for the master
/// node), which its xpub records. The parent is derived once, and the node is one step from it.
pub fn derive_hd_node_and_parent_fingerprint(
    tree: KeyTree,
    path: &[u32],
) -> Result<(HDPrivNode<Secp256k1, 32>, u32), Error> {
    check_path_len(tree, path)?;
    let Some((&child, parent_path)) = path.split_last() else {
        return Ok((derive_hd_node(tree, &[])?, 0));
    };
    let parent = derive_hd_node(tree, parent_path)?;
    let parent_fingerprint = EcfpPrivateKey::<Secp256k1, 32>::new(*parent.privkey)
        .to_public_key()
        .fingerprint();
    let node = parent
        .ckd_priv(child)
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok((node, parent_fingerprint))
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
        assert_eq!(
            derive_hd_node_and_parent_fingerprint(
                KeyTree::Standard,
                &[0x8000_0000u32; MAX_BIP32_PATH_LEN + 1]
            )
            .err(),
            Some(Error::DerivationPathTooLong)
        );
    }

    /// The node is the one at the whole path, and its parent's fingerprint is the master
    /// fingerprint for a node at depth 1.
    #[test]
    fn test_derive_hd_node_and_parent_fingerprint() {
        for tree in [KeyTree::Standard, KeyTree::Resident] {
            for path in [&[][..], &[0x8000_002c], &[0x8000_002c, 0x8000_0001, 0, 5]] {
                let (node, parent_fpr) = derive_hd_node_and_parent_fingerprint(tree, path).unwrap();
                let expected = derive_hd_node(tree, path).unwrap();
                assert_eq!(*node.privkey, *expected.privkey);
                assert_eq!(node.chaincode, expected.chaincode);
                match path.len() {
                    0 => assert_eq!(parent_fpr, 0),
                    1 => assert_eq!(parent_fpr, master_fingerprint(tree).unwrap()),
                    _ => {}
                }
            }
        }
    }
}
