//! secp384r1 validation for DNSSEC signatures

/// Validates the given signature against the given public key and message digest.
///
/// This is DNSSEC algorithm 14 (ECDSA P-384 with SHA-384). The public key is a bare `X || Y` per
/// RFC 6605 and the signature a fixed-width `r || s`; see [`super::ecdsa`] for the conversion and
/// for why the whole verification is now a single ECALL.
pub fn validate_ecdsa(pk: &[u8], sig: &[u8], hash_input: &[u8]) -> Result<(), ()> {
    super::ecdsa::validate_p384(pk, sig, hash_input)
}
