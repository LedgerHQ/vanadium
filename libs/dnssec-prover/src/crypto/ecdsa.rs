//! ECDSA verification, delegated to the `ecdsa_verify` ECALL.
//!
//! This replaces the Jacobian group law and double-and-add ladder that used to live in
//! `crypto/ec.rs`. Those ran as interpreted Rust over the modular-arithmetic ECALLs, at roughly
//! **14,000 ECALLs per signature**; one full DNSSEC chain (two RSA-2048 and four P-256
//! signatures) cost 56,315. Each verification is now a single ECALL, so the same chain costs
//! about thirty.
//!
//! Two shapes have to be converted, because DNSSEC and the ECALL disagree:
//!
//!  * **Public keys.** RFC 6605 stores them as bare `X || Y`, with no SEC1 prefix; the ECALL
//!    wants uncompressed SEC1, `0x04 || X || Y`.
//!  * **Signatures.** RFC 6605 stores a fixed-width `r || s`; the ECALL wants DER, because that
//!    is what `cx_ecdsa_verify_no_throw` takes.

use sdk::curve::{EcfpPublicKey, Point, Secp256r1, Secp384r1};

/// Longest DER encoding of a signature on any curve here: a `SEQUENCE` of two `INTEGER`s, each at
/// worst `48 + 1` content bytes plus a two-byte header.
const MAX_DER_SIGNATURE_LEN: usize = 2 + 2 * (3 + 48);

/// Largest digest the ECALL accepts. Exceeding it is a caller bug and terminates the V-App, so it
/// is checked here rather than relied upon: every hash `validation.rs` can select tops out at
/// SHA-512, but that is an invariant of code elsewhere in this crate, not of the input.
const MAX_HASH_LEN: usize = 64;

/// Writes `value` as a DER `INTEGER` and returns how many bytes were used.
///
/// DER integers are signed and minimally encoded: leading zero bytes come off, and a `0x00` goes
/// back on if the top bit of the first remaining byte is set. Zero encodes as a single `0x00`.
fn write_der_integer(value: &[u8], out: &mut [u8]) -> usize {
    let first_significant = value.iter().position(|b| *b != 0).unwrap_or(value.len());
    let magnitude = &value[first_significant..];

    let needs_pad = magnitude.first().is_some_and(|b| b & 0x80 != 0);
    let content_len = if magnitude.is_empty() {
        1
    } else {
        magnitude.len() + usize::from(needs_pad)
    };

    out[0] = 0x02;
    out[1] = content_len as u8;
    if magnitude.is_empty() {
        out[2] = 0x00;
    } else {
        let mut pos = 2;
        if needs_pad {
            out[pos] = 0x00;
            pos += 1;
        }
        out[pos..pos + magnitude.len()].copy_from_slice(magnitude);
    }
    2 + content_len
}

/// Re-encodes a fixed-width `r || s` signature as a DER `SEQUENCE` of two `INTEGER`s.
///
/// Returns the encoding and its length, or `None` if `sig` is not two equal halves.
fn raw_to_der(sig: &[u8]) -> Option<([u8; MAX_DER_SIGNATURE_LEN], usize)> {
    if sig.is_empty() || sig.len() % 2 != 0 || sig.len() / 2 > 48 {
        return None;
    }
    let (r, s) = sig.split_at(sig.len() / 2);

    let mut body = [0u8; MAX_DER_SIGNATURE_LEN];
    let mut body_len = write_der_integer(r, &mut body);
    body_len += write_der_integer(s, &mut body[body_len..]);

    let mut der = [0u8; MAX_DER_SIGNATURE_LEN];
    der[0] = 0x30;
    der[1] = body_len as u8;
    der[2..2 + body_len].copy_from_slice(&body[..body_len]);
    Some((der, 2 + body_len))
}

/// Generates `validate_ecdsa` for one curve.
///
/// A macro because `Point::from_bytes` takes `&[u8; 1 + 2 * SCALAR_LENGTH]`, which cannot be
/// named generically without `generic_const_exprs`.
macro_rules! impl_validate_ecdsa {
    ($name:ident, $curve:ty, $scalar_len:expr, $point_len:expr) => {
        /// Validates a DNSSEC ECDSA signature against a bare `X || Y` public key and a digest.
        pub(super) fn $name(pk: &[u8], sig: &[u8], hash_input: &[u8]) -> Result<(), ()> {
            if pk.len() != 2 * $scalar_len {
                return Err(());
            }
            if sig.len() != 2 * $scalar_len {
                return Err(());
            }
            if hash_input.is_empty() || hash_input.len() > MAX_HASH_LEN {
                return Err(());
            }

            // RFC 6605 omits the SEC1 prefix, so put it back. Going through `Point::from_bytes`
            // rather than straight to `EcfpPublicKey::new` is deliberate: it rejects a point that
            // is not on the curve, which the upstream implementation also did and which the
            // wycheproof suites exercise.
            let mut sec1 = [0u8; $point_len];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(pk);
            let point = Point::<$curve, $scalar_len>::from_bytes(&sec1).map_err(|_| ())?;

            let (der, der_len) = raw_to_der(sig).ok_or(())?;

            EcfpPublicKey::from(point)
                .ecdsa_verify_hash(hash_input, &der[..der_len])
                .map_err(|_| ())
        }
    };
}

impl_validate_ecdsa!(validate_p256, Secp256r1, 32, 65);
impl_validate_ecdsa!(validate_p384, Secp384r1, 48, 97);

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn der(sig: &[u8]) -> Vec<u8> {
        let (out, len) = raw_to_der(sig).expect("well-formed input");
        out[..len].to_vec()
    }

    #[test]
    fn encodes_small_positive_integers() {
        // r = 1, s = 2 -> SEQUENCE { INTEGER 1, INTEGER 2 }
        let mut sig = [0u8; 64];
        sig[31] = 1;
        sig[63] = 2;
        assert_eq!(der(&sig), [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn pads_when_the_high_bit_is_set() {
        // A leading byte >= 0x80 must gain a 0x00, or it would decode as negative.
        let mut sig = [0u8; 64];
        sig[0] = 0xff;
        sig[32] = 0x7f;
        let out = der(&sig);
        assert_eq!(&out[..3], &[0x30, 0x45, 0x02]);
        assert_eq!(out[3], 33, "r gains a padding byte");
        assert_eq!(out[4], 0x00);
        assert_eq!(out[5], 0xff);
        // s starts with 0x7f, which needs no padding.
        assert_eq!(out[2 + 35], 0x02);
        assert_eq!(out[2 + 36], 32);
    }

    #[test]
    fn encodes_zero_as_a_single_zero_byte() {
        // Not a valid signature, but it must produce well-formed DER rather than a truncated
        // INTEGER: the ECALL is entitled to reject it, not to be handed garbage.
        let sig = [0u8; 64];
        assert_eq!(der(&sig), [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn encodes_a_full_width_p384_signature() {
        let sig = [0x7fu8; 96];
        let out = der(&sig);
        assert_eq!(out[0], 0x30);
        // Two INTEGERs of 48 content bytes, each with a 2-byte header.
        assert_eq!(out.len(), 2 + 2 * (2 + 48));
        assert_eq!(out[1] as usize, 2 * (2 + 48));
    }

    #[test]
    fn rejects_malformed_lengths() {
        assert!(raw_to_der(&[]).is_none());
        assert!(raw_to_der(&[0u8; 65]).is_none(), "odd length");
        assert!(raw_to_der(&[0u8; 128]).is_none(), "half is wider than 48 bytes");
    }

    /// The encoder must never overflow its buffer, whatever the input bytes are.
    #[test]
    fn output_always_fits_the_buffer() {
        for width in [32usize, 48] {
            for fill in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let sig = alloc::vec![fill; width * 2];
                let (_, len) = raw_to_der(&sig).unwrap();
                assert!(len <= MAX_DER_SIGNATURE_LEN, "{width}/{fill:#x} produced {len}");
            }
        }
    }
}
