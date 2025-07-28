use crate::ecalls;
use alloc::vec::Vec;

/// Derives a SLIP-21 key node, based on the BIP39 seed.
/// The key corresponds to the last 32-bytes of the corresponding SLIP-21 node.
/// The initial 32 bytes (only used for further derivations) are not returned.
///
/// # Returns
/// A 32-byte array representing the derived SLIP-21 key.
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
/// Accessing the raw bytes of the derived key is dangerous and can lead to
/// side-channel attacks.
// TODO: it would be better to return an opaque type that doesn't directly allow
// accessing the raw bytes, as incorrect usage could lead to side channel attacks.
pub fn derive_slip21_key(labels: &[&[u8]]) -> [u8; 32] {
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
    key
}
