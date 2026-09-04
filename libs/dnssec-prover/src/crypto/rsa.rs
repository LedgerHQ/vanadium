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
    // An even modulus must be turned away here rather than left to fail later, and the reason is
    // not that it is a nonsense key -- though it is, since one of its factors would be two.
    //
    // `bn_powm` is `cx_math_powm` on the device, which requires an odd modulus and returns an
    // error otherwise; the VM turns that error into a fatal `CommEcallError`, killing the V-App
    // instead of returning failure to it. A DNSKEY comes out of an attacker-supplied PSBT, so
    // letting one reach the ECALL would hand the host a way to abort signing at will.
    //
    // Note that no test of `validate_rsa` can catch the loss of this check: `bn_powm` on native
    // is `num-bigint::modpow`, which handles an even modulus perfectly well and just produces a
    // digest that does not match, so the outcome is `Err` either way. That is why the test for it
    // below calls `split_dnskey_rsa` directly.
    if modulus[modulus.len() - 1] % 2 == 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an RFC 3110 DNSKEY body with a one-byte exponent length.
    fn dnskey(exponent: &[u8], modulus: &[u8]) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec![exponent.len() as u8];
        v.extend_from_slice(exponent);
        v.extend_from_slice(modulus);
        v
    }

    const E: &[u8] = &[0x01, 0x00, 0x01];

    #[test]
    fn accepts_a_well_formed_key() {
        let modulus = [0xc5u8; 128];
        assert_eq!(
            split_dnskey_rsa(&dnskey(E, &modulus)),
            Ok((E, &modulus[..]))
        );
    }

    #[test]
    fn rejects_an_even_modulus() {
        // The check this pins keeps an even modulus away from `bn_powm`, which is fatal to the
        // V-App on the device; see the comment on it. Testing `validate_rsa` instead would prove
        // nothing, since native `bn_powm` accepts an even modulus and merely fails the digest.
        let mut modulus = [0xc5u8; 128];
        modulus[127] = 0xc4;
        assert_eq!(split_dnskey_rsa(&dnskey(E, &modulus)), Err(()));
    }

    #[test]
    fn rejects_an_even_modulus_hidden_behind_leading_zeros() {
        // Parity has to be read after the leading zeros come off, not from the wire bytes.
        let mut modulus = [0u8; 130];
        modulus[2..].copy_from_slice(&[0xc5u8; 128]);
        modulus[129] = 0xc4;
        assert_eq!(split_dnskey_rsa(&dnskey(E, &modulus)), Err(()));
    }

    #[test]
    fn strips_leading_zeros_so_the_modulus_length_is_the_signature_length() {
        let mut wire = [0u8; 130];
        wire[2..].copy_from_slice(&[0xc5u8; 128]);
        let key = dnskey(E, &wire);
        let (e, m) = split_dnskey_rsa(&key).unwrap();
        assert_eq!(e, E);
        assert_eq!(m.len(), 128);
    }

    #[test]
    fn rejects_a_zero_or_absent_modulus() {
        assert_eq!(split_dnskey_rsa(&dnskey(E, &[0u8; 64])), Err(()));
        assert_eq!(split_dnskey_rsa(&dnskey(E, &[])), Err(()));
    }

    #[test]
    fn rejects_an_oversized_exponent() {
        // Verification time is linear in the exponent's bit length, so the bound is a DoS bound.
        let big_e = [0xffu8; 5];
        assert_eq!(split_dnskey_rsa(&dnskey(&big_e, &[0xc5u8; 128])), Err(()));
    }
}
