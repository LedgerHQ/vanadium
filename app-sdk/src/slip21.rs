use crate::ecalls;
use alloc::vec::Vec;
use core::ops::Deref;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// An opaque type representing a SLIP-21 derived key.
///
/// This type prevents direct access to the key material to mitigate side-channel attacks.
/// The key is automatically zeroed on drop.
///
/// # Security
///
/// - Implements constant-time equality comparison to prevent timing attacks.
/// - Does not implement `Debug` to prevent accidental logging of key material.
/// - Does not implement `Clone` to limit the number of copies in memory.
/// - Automatically zeros memory on drop using `Zeroizing`.
pub struct Slip21Key {
    key: Zeroizing<[u8; 32]>,
}

impl Slip21Key {
    /// Creates a new `Slip21Key` from raw bytes.
    ///
    /// # Security
    ///
    /// The provided bytes will be stored in a `Zeroizing` wrapper and automatically
    /// zeroed when this instance is dropped.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    /// Compares this key with a 32-byte buffer in constant time.
    ///
    /// This method provides an explicit constant-time comparison that is safe
    /// to use for verification purposes without risking timing attacks.
    ///
    /// # Returns
    ///
    /// `true` if the keys are equal, `false` otherwise.
    pub fn ct_compare(&self, other: &[u8; 32]) -> bool {
        self.key.deref().ct_eq(other).into()
    }

    /// Returns a reference to the raw bytes of the key.
    ///
    /// # Warning
    ///
    /// Accessing the raw bytes of cryptographic key material is dangerous and can lead to
    /// side-channel attacks if the bytes are used incorrectly. This method should only be
    /// used when absolutely necessary, such as when passing the key to cryptographic
    /// operations that require raw byte access.
    ///
    /// When comparing keys, prefer using the `==` operator (which uses constant-time
    /// comparison) or the `ct_compare` method instead of accessing raw bytes.
    pub fn dangerous_as_raw_bytes(&self) -> &[u8; 32] {
        self.key.deref()
    }
}

impl PartialEq for Slip21Key {
    /// Compares two keys in constant time to prevent timing attacks.
    fn eq(&self, other: &Self) -> bool {
        self.key.deref().ct_eq(other.key.deref()).into()
    }
}

impl Eq for Slip21Key {}

/// Derives a SLIP-21 key node, based on the BIP39 seed.
/// The key corresponds to the last 32-bytes of the corresponding SLIP-21 node.
/// The initial 32 bytes (only used for further derivations) are not returned.
///
/// # Returns
/// A `Slip21Key` opaque type representing the derived SLIP-21 key.
///
/// # Panics
/// This function will panic if either:
/// - The total length of the encoded labels exceeds 256 bytes.
/// - Any individual label exceeds 252 bytes.
/// - (Ledger-specific) `labels` has length 0 (no master key derivation)
/// - (Ledger-specific) Any label contains a '/' character.
///
/// # Security
///
/// The returned key is wrapped in an opaque type that:
/// - Prevents direct access to raw bytes (unless explicitly using `dangerous_as_raw_bytes()`)
/// - Implements constant-time equality comparison
/// - Automatically zeros memory on drop
pub fn derive_slip21_key(labels: &[&[u8]]) -> Slip21Key {
    // compute the total length of the encoded labels as the sum of their lengths,
    // each increased by 1 because of the length prefix.
    let encoded_length = labels.iter().map(|label| label.len() + 1).sum::<usize>();
    if encoded_length > 256 {
        panic!("Total length of encoded labels exceeds maximum allowed size of 256 bytes");
    }
    let mut encoded_labels = Vec::with_capacity(encoded_length);

    for label in labels {
        if label.len() > 252 {
            panic!("Label length exceeds maximum allowed size of 252 bytes");
        }
        // Write the length prefix, followed by the label
        encoded_labels.push(label.len() as u8);
        encoded_labels.extend_from_slice(label);
    }

    let mut node = [0u8; 64];
    if ecalls::derive_slip21_node(
        encoded_labels.as_ptr(),
        encoded_labels.len(),
        node.as_mut_ptr(),
    ) == 0
    {
        panic!("Failed to derive SLIP-21 node");
    }
    // only return the last 32 bytes, which are the SLIP-21 key
    let mut key = [0u8; 32];
    key.copy_from_slice(&node[32..64]);
    Slip21Key::from_bytes(key)
}
