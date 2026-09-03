//! RSA validation for DNSSEC signatures
//!
//! Upstream implements `s^e mod n` over its own `U4096`. Here it is one `bn_powm` ECALL, reached
//! through `sdk::rsa`, which also builds the `EMSA-PKCS1-v1_5` encoding. All that is left in this
//! module is decoding the DNSKEY wire format.

use sdk::rsa::{RsaHash, RsaPublicKey};

/// Splits a DNSSEC RSA public key into its exponent and modulus, both big-endian with no leading
/// zero bytes.
///
/// The wire format is RFC 3110 §2: a one-byte exponent length, or a zero byte followed by a
/// two-byte length if the exponent needs more than 255 bytes, then the exponent, then the
/// modulus.
fn split_dnskey_rsa(pubkey: &[u8]) -> Result<(&[u8], &[u8]), ()> {
    if pubkey.len() <= 3 {
        return Err(());
    }

    let mut pos = 0;
    let exponent_length;
    if pubkey[0] == 0 {
        exponent_length = ((pubkey[1] as usize) << 8) | (pubkey[2] as usize);
        pos += 3;
    } else {
        exponent_length = pubkey[0] as usize;
        pos += 1;
    }

    if pubkey.len() <= pos + exponent_length {
        return Err(());
    }
    // The time a verification takes is linear in the bit length of the exponent, so a host must
    // not be able to hand the device an arbitrarily expensive key. Four bytes covers every
    // exponent in use (65537 needs three) and is the bound upstream applies too.
    if exponent_length > 4 {
        return Err(());
    }

    let exponent = strip_leading_zeros(&pubkey[pos..pos + exponent_length]);
    let modulus = strip_leading_zeros(&pubkey[pos + exponent_length..]);
    if exponent.is_empty() || modulus.is_empty() {
        return Err(());
    }
    Ok((exponent, modulus))
}

/// `sdk::rsa` takes raw unsigned big-endian integers, so any leading zero bytes the wire format
/// happened to carry have to come off first: for the modulus they would otherwise inflate `k`,
/// the length a signature is required to have.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// Validates the given RSA signature against the given RSA public key (up to 4096-bit, in
/// DNSSEC-encoded form) and given message digest.
pub fn validate_rsa(pk: &[u8], sig_bytes: &[u8], hash_input: &[u8]) -> Result<(), ()> {
    let (exponent, modulus) = split_dnskey_rsa(pk)?;

    // RFC 5702: the only RSA DNSSEC algorithms `validation` accepts are 8 (SHA-256) and 10
    // (SHA-512), so the digest length identifies the hash unambiguously.
    let hash = match hash_input.len() {
        32 => RsaHash::Sha256,
        64 => RsaHash::Sha512,
        _ => return Err(()),
    };

    // RFC 4034 §3.1.8.1 fixes the signature length at the modulus length, but upstream accepts a
    // shorter big-endian encoding of the same integer, so keep doing that: zero-extension does
    // not change the value being exponentiated, and the recovered encoded message is still
    // compared against the expected one in full.
    let k = modulus.len();
    let sig = strip_leading_zeros(sig_bytes);
    if sig.len() > k {
        return Err(());
    }
    let mut padded_sig = alloc::vec![0u8; k];
    padded_sig[k - sig.len()..].copy_from_slice(sig);

    let key = RsaPublicKey::new(modulus, exponent);
    if key.verify_pkcs1_v1_5(hash, hash_input, &padded_sig) {
        Ok(())
    } else {
        Err(())
    }
}
