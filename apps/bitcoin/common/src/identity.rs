use alloc::vec::Vec;

use crate::por::{Registerable, RegistrationId};
use sdk::hash::{Hasher, Sha256};

/// The hardened root path component for identity keys: `1229210958'`
/// 1229210958 is the decimal encoding of the ASCII string "IDEN".
pub const IDENTITY_ROOT_PATH_COMPONENT: u32 = 1229210958 | 0x8000_0000;

/// Magic prefix for identity signing messages: `\x09IDEN/SIGN`
pub const SIGN_MAGIC: &[u8] = b"\x09IDEN/SIGN";

/// Message type prefix for xpub signing.
pub const MSG_TYPE_XPUB: &[u8] = b"XPUB";

/// Message type prefix for output script signing.
pub const MSG_TYPE_OUTPUT: &[u8] = b"OUTPUT";

/// Returns the BIP-32 derivation path for the i-th identity key: `[1229210958', i]`.
/// If `index` is `None`, returns the root identity path `[1229210958']`, which can be used to derive a master identity key for signing non-identity messages or as a fallback identity key.
///
/// Unhardened derivation is used for `i`, allowing user-level applications to manage
/// various uncorrelated identities for the same user.
pub fn identity_derivation_path(index: Option<u32>) -> Vec<u32> {
    match index {
        Some(i) => alloc::vec![IDENTITY_ROOT_PATH_COMPONENT, i],
        None => alloc::vec![IDENTITY_ROOT_PATH_COMPONENT],
    }
}

/// Checks whether a BIP-32 path corresponds to an identity key path.
///
/// Returns:
/// - `Some(Some(i))` if the path is `m/1229210958'/i` (the i-th identity key)
/// - `Some(None)` if the path is `m/1229210958'` (the root identity key)
/// - `None` otherwise
pub fn is_identity_path(path: &[u32]) -> Option<Option<u32>> {
    match path {
        [root] if *root == IDENTITY_ROOT_PATH_COMPONENT => Some(None),
        [root, index] if *root == IDENTITY_ROOT_PATH_COMPONENT => Some(Some(*index)),
        _ => None,
    }
}

pub(crate) const IDENTITY_KEY_MAGIC: [u8; 13] = *b"\x0CIDENTITY_KEY";

/// A newtype wrapping a 33-byte compressed secp256k1 public key used as an
/// identity key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKey(pub [u8; 33]);

impl IdentityKey {
    /// Creates a new `IdentityKey` from a 33-byte compressed public key.
    ///
    /// Returns `Err` if the first byte is not `0x02` or `0x03`.
    pub fn new(compressed: [u8; 33]) -> Result<Self, &'static str> {
        if compressed[0] != 0x02 && compressed[0] != 0x03 {
            return Err("Invalid compressed key prefix");
        }
        Ok(Self(compressed))
    }

    /// Returns a reference to the 33-byte compressed public key.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    /// Returns a unique identifier for the named identity key.
    ///
    /// The identifier is the SHA-256 hash of:
    /// - the magic constant `IDENTITY_KEY_MAGIC`
    /// - the length of the name (as a single byte)
    /// - the name itself
    /// - the 33-byte compressed public key
    fn get_id(&self, name: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&IDENTITY_KEY_MAGIC);
        hasher.update(&[name.len() as u8]);
        hasher.update(name.as_bytes());
        hasher.update(&self.0);
        hasher.finalize().into()
    }
}

impl Registerable for IdentityKey {
    type Context = str;

    fn registration_id(&self, name: &Self::Context) -> RegistrationId<Self> {
        RegistrationId::<Self>::from_bytes(self.get_id(name))
    }
}

/// Builds the signing message for an identity-authenticated object.
///
/// Format: `SIGN_MAGIC || length(msg_type) || msg_type || length(object) || object`
///
/// Lengths are encoded as a single byte (u8).
pub fn build_identity_message(msg_type: &[u8], object: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGN_MAGIC.len() + 1 + msg_type.len() + 1 + object.len());
    msg.extend_from_slice(SIGN_MAGIC);
    msg.push(msg_type.len() as u8);
    msg.extend_from_slice(msg_type);
    msg.push(object.len() as u8);
    msg.extend_from_slice(object);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_derivation_path() {
        let path = identity_derivation_path(Some(0));
        assert_eq!(path, alloc::vec![0x8000_0000 | 1229210958, 0]);

        let path = identity_derivation_path(Some(42));
        assert_eq!(path, alloc::vec![0x8000_0000 | 1229210958, 42]);

        let path = identity_derivation_path(None);
        assert_eq!(path, alloc::vec![0x8000_0000 | 1229210958]);
    }

    #[test]
    fn test_is_identity_path() {
        // Root identity path
        assert_eq!(
            is_identity_path(&[IDENTITY_ROOT_PATH_COMPONENT]),
            Some(None)
        );

        // i-th identity key
        assert_eq!(
            is_identity_path(&[IDENTITY_ROOT_PATH_COMPONENT, 0]),
            Some(Some(0))
        );
        assert_eq!(
            is_identity_path(&[IDENTITY_ROOT_PATH_COMPONENT, 5]),
            Some(Some(5))
        );

        // Not an identity path
        assert_eq!(is_identity_path(&[]), None);
        assert_eq!(
            is_identity_path(&[0x8000_002C, 0x8000_0001, 0x8000_0000]),
            None
        );
        assert_eq!(
            is_identity_path(&[IDENTITY_ROOT_PATH_COMPONENT, 0, 1]),
            None
        );
    }

    #[test]
    fn test_build_identity_message() {
        let msg = build_identity_message(b"XPUB", &[0xAA; 78]);
        assert_eq!(&msg[..SIGN_MAGIC.len()], SIGN_MAGIC);
        assert_eq!(msg[SIGN_MAGIC.len()], 4); // length of "XPUB"
        assert_eq!(&msg[SIGN_MAGIC.len() + 1..SIGN_MAGIC.len() + 5], b"XPUB");
        assert_eq!(msg[SIGN_MAGIC.len() + 5], 78); // length of object
        assert_eq!(&msg[SIGN_MAGIC.len() + 6..], &[0xAA; 78]);
    }
}
