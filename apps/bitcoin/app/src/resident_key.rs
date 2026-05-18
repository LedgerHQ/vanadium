use common::errors::Error;
use sdk::curve::{Curve, EcfpPrivateKey, HDPrivNode, Secp256k1, ToPublicKey};
use sdk::hash::{Hasher, Sha512};

#[cfg(not(any(test, feature = "fixed_resident_seed")))]
use sdk::storage::{is_slot_empty, read_slot, write_slot};

#[cfg(not(any(test, feature = "fixed_resident_seed")))]
const RESIDENT_SEED_SLOT: u32 = 0;

#[cfg(any(test, feature = "fixed_resident_seed"))]
// this is a 32-byte seed that is part of test vectors for BIP-32
pub const FIXED_RESIDENT_SEED: [u8; 32] =
    hex_literal::hex!("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678");

/// Returns the resident BIP-32 seed from storage slot 0, generating and storing
/// a fresh random seed on first use (detected by the slot being all-zeros).
///
/// If the `fixed_resident_seed` feature is enabled, always returns the fixed
/// compile-time seed `FIXED_RESIDENT_SEED`. This is only useful for testing.
pub fn get_or_init_resident_seed() -> Result<[u8; 32], Error> {
    #[cfg(any(test, feature = "fixed_resident_seed"))]
    return Ok(FIXED_RESIDENT_SEED);

    #[cfg(not(any(test, feature = "fixed_resident_seed")))]
    if is_slot_empty(RESIDENT_SEED_SLOT).map_err(|_| Error::StorageError)? {
        let standard_fpr = Secp256k1::get_master_fingerprint();
        // avoid generating a seed that would produce the same master fingerprint
        let random_seed: [u8; 32] = loop {
            let candidate: [u8; 32] = sdk::rand::random_bytes(32).try_into().unwrap();
            if master_fingerprint(&master_hd_node_from_seed(&candidate)) != standard_fpr {
                break candidate;
            }
        };
        write_slot(RESIDENT_SEED_SLOT, &random_seed).map_err(|_| Error::StorageError)?;
        Ok(random_seed)
    } else {
        read_slot(RESIDENT_SEED_SLOT).map_err(|_| Error::StorageError)
    }
}

/// Derives the BIP-32 master HD node from a 32-byte seed
/// (`HMAC-SHA512("Bitcoin seed", seed) -> (privkey || chaincode)`).
fn master_hd_node_from_seed(seed: &[u8; 32]) -> HDPrivNode<Secp256k1, 32> {
    let hmac = hmac_sha512(b"Bitcoin seed", seed);

    let mut privkey = [0u8; 32];
    privkey.copy_from_slice(&hmac[0..32]);
    let mut chaincode = [0u8; 32];
    chaincode.copy_from_slice(&hmac[32..64]);

    EcfpPrivateKey::<Secp256k1, 32>::new(privkey).into_hd_node(&chaincode)
}

/// Returns the BIP-32 fingerprint of the public key associated with the given master HD node.
fn master_fingerprint(node: &HDPrivNode<Secp256k1, 32>) -> u32 {
    EcfpPrivateKey::<Secp256k1, 32>::new(*node.privkey)
        .to_public_key()
        .fingerprint()
}

/// Returns the resident BIP-32 master HD node derived from the resident seed.
pub fn get_resident_master_hd_node() -> Result<HDPrivNode<Secp256k1, 32>, Error> {
    let seed = get_or_init_resident_seed()?;
    Ok(master_hd_node_from_seed(&seed))
}

/// Derives the resident HD node at the given BIP-32 path, starting from the
/// resident master HD node.
pub fn derive_resident_hd_node(path: &[u32]) -> Result<HDPrivNode<Secp256k1, 32>, Error> {
    let mut node = get_resident_master_hd_node()?;
    for &step in path {
        node = node
            .ckd_priv(step)
            .map_err(|_| Error::KeyDerivationFailed)?;
    }
    Ok(node)
}

/// Returns the BIP-32 fingerprint of the resident master public key.
pub fn get_resident_master_fingerprint() -> Result<u32, Error> {
    Ok(master_fingerprint(&get_resident_master_hd_node()?))
}

/// HMAC-SHA512 with an arbitrary-length key.
/// TODO: Implement a proper HMAC-SHA512 in the app-sdk and use that instead.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    const BLOCK_SIZE: usize = 128;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut h = Sha512::new();
        h.update(key);
        let mut digest = [0u8; 64];
        h.digest(&mut digest);
        key_block[..64].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad_key = [0x36u8; BLOCK_SIZE];
    let mut opad_key = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad_key[i] ^= key_block[i];
        opad_key[i] ^= key_block[i];
    }

    let mut inner = Sha512::new();
    inner.update(&ipad_key);
    inner.update(data);
    let mut inner_digest = [0u8; 64];
    inner.digest(&mut inner_digest);

    let mut outer = Sha512::new();
    outer.update(&opad_key);
    outer.update(&inner_digest);
    let mut result = [0u8; 64];
    outer.digest(&mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vector 4 (seed 3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678),
    // which equals FIXED_RESIDENT_SEED used in tests.

    /// Chain m
    #[test]
    fn test_bip32_tv4_master() {
        let node = get_resident_master_hd_node().unwrap();
        assert_eq!(
            &*node.privkey,
            &hex_literal::hex!("12c0d59c7aa3a10973dbd3f478b65f2516627e3fe61e00c345be9a477ad2e215")
        );
        assert_eq!(
            node.chaincode,
            hex_literal::hex!("d0c8a1f6edf2500798c3e0b54f1b56e45f6d03e6076abd36e5e2f54101e44ce6")
        );
        // fingerprint of master pubkey = parent fingerprint stored in the m/0H xpub
        assert_eq!(get_resident_master_fingerprint().unwrap(), 0xad85d955);
    }

    /// Chain m/0H
    #[test]
    fn test_bip32_tv4_m_0h() {
        let node = derive_resident_hd_node(&[0x80000000]).unwrap();
        assert_eq!(
            &*node.privkey,
            &hex_literal::hex!("00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e")
        );
        assert_eq!(
            node.chaincode,
            hex_literal::hex!("cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b")
        );
    }

    /// Chain m/0H/1H
    #[test]
    fn test_bip32_tv4_m_0h_1h() {
        let node = derive_resident_hd_node(&[0x80000000, 0x80000001]).unwrap();
        assert_eq!(
            &*node.privkey,
            &hex_literal::hex!("3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d")
        );
        assert_eq!(
            node.chaincode,
            hex_literal::hex!("a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d")
        );
    }
}
