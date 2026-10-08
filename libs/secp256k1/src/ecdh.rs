//! Elliptic-curve Diffie-Hellman.
//!
//! Only [`shared_secret_point`] is provided, which returns the shared point itself, as protocols
//! like BIP-352 need; `SharedSecret`, which hashes it, is not.

use crate::key::{PublicKey, SecretKey};

/// Creates the shared point `scalar * point`, returned as its 64-byte uncompressed encoding
/// `x || y`, without the SEC1 prefix.
pub fn shared_secret_point(point: &PublicKey, scalar: &SecretKey) -> [u8; 64] {
    let scalar = sdk::curve::Secp256k1Scalar::from_be_bytes(&scalar.secret_bytes())
        .expect("a secret key is smaller than n");
    // neither factor is 0, so neither is the product
    let shared = point.as_point() * &scalar;
    let mut res = [0u8; 64];
    res[..32].copy_from_slice(shared.x());
    res[32..].copy_from_slice(shared.y());
    res
}
