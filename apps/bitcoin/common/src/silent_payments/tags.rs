//! The tagged hashes of BIP-352.

use hashes::sha256t_hash_newtype;
use sdk::curve::Secp256k1Scalar;

use super::Error;

sha256t_hash_newtype! {
    pub struct InputsTag = hash_str("BIP0352/Inputs");
    pub struct InputsHash(_);

    pub struct SharedSecretTag = hash_str("BIP0352/SharedSecret");
    pub struct SharedSecretHash(_);

    pub struct LabelTag = hash_str("BIP0352/Label");
    pub struct LabelHash(_);
}

/// A tagged hash as a scalar: BIP-352 fails if it is 0 or not smaller than the curve order.
pub(super) fn hash_to_scalar(hash: &[u8; 32]) -> Result<Secp256k1Scalar, Error> {
    Secp256k1Scalar::from_be_bytes(hash)
        .filter(|s| !s.is_zero())
        .ok_or(Error::InvalidHash)
}
