//! Input validation for the cryptographic ECALLs.
//!
//! The ECALLs have two implementations: the VM, which calls the device's cryptographic library,
//! and the native target used in tests. The libraries underneath have different preconditions,
//! and on the device a violated precondition can kill the V-App or produce an undefined result.
//! So both implementations run the checks in this module before doing any arithmetic, and accept
//! and reject exactly the same inputs; a rejected input makes the ECALL return 0.
//!
//! What stays implementation-specific is only what needs curve arithmetic, like checking that a
//! point is on the curve.

use core::cmp::Ordering;

use crate::ecall_constants::{HashId, MAX_BIGNUMBER_SIZE};

/// The secp256k1 field prime p.
pub const SECP256K1_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

/// The order n of the secp256k1 group.
pub const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Maximum number of steps of a BIP-32 derivation path.
pub const MAX_BIP32_PATH_LEN: usize = 16;

/// Maximum number of bytes returned by a single `get_random_bytes` ECALL.
pub const MAX_RANDOM_BYTES: usize = 256;

/// Maximum length of the length-prefixed SLIP-21 labels buffer.
pub const MAX_SLIP21_LABELS_LEN: usize = 256;

/// Maximum length of a single SLIP-21 label.
pub const MAX_SLIP21_LABEL_LEN: usize = 252;

/// Maximum length of the message signed or verified by the Schnorr ECALLs.
pub const MAX_SCHNORR_MSG_LEN: usize = 512;

/// Maximum length of a DER-encoded secp256k1 ECDSA signature.
pub const MAX_ECDSA_SIGNATURE_LEN: usize = 72;

/// Compares two unsigned big-endian integers, which may have different lengths.
///
/// It inspects every byte of both inputs, whatever their values, so that it can be used on secrets.
pub fn cmp_be(a: &[u8], b: &[u8]) -> Ordering {
    let len = a.len().max(b.len());
    // byte `i` of the number left-padded with zeros to `len` bytes
    let byte = |x: &[u8], i: usize| -> u8 {
        let pad = len - x.len();
        if i < pad {
            0
        } else {
            x[i - pad]
        }
    };

    // 1 if a > b, 2 if a < b, 0 while the bytes seen so far are equal
    let mut res: u8 = 0;
    for i in 0..len {
        let (x, y) = (byte(a, i), byte(b, i));
        let undecided = ((res == 0) as u8).wrapping_neg();
        res |= undecided & (((x > y) as u8) | (((x < y) as u8) << 1));
    }
    match res {
        0 => Ordering::Equal,
        1 => Ordering::Greater,
        _ => Ordering::Less,
    }
}

/// Whether the big-endian integer `a` is zero; it inspects every byte.
pub fn is_zero(a: &[u8]) -> bool {
    a.iter().fold(0u8, |acc, &x| acc | x) == 0
}

/// Whether the big-endian integer `a` is odd.
pub fn is_odd(a: &[u8]) -> bool {
    a.last().is_some_and(|x| x & 1 == 1)
}

/// Whether `a` is canonical modulo `m`, that is `a < m`.
pub fn is_reduced(a: &[u8], m: &[u8]) -> bool {
    cmp_be(a, m) == Ordering::Less
}

/// Whether `len` is an acceptable operand length for the big number ECALLs.
pub fn is_bignum_len(len: usize) -> bool {
    len <= MAX_BIGNUMBER_SIZE
}

/// Whether `m` is an acceptable modulus: non-zero, and odd if `require_odd`.
///
/// `bn_multm`, `bn_powm` and `bn_modinv_prime` require an odd modulus; the device's
/// implementation is based on Montgomery multiplication, which does not support even moduli.
pub fn is_modulus(m: &[u8], require_odd: bool) -> bool {
    !is_zero(m) && (!require_odd || is_odd(m))
}

/// Whether `k` is a canonical secp256k1 scalar: at most 32 bytes, and smaller than n.
/// Zero is a valid scalar.
pub fn is_secp256k1_scalar(k: &[u8]) -> bool {
    k.len() <= 32 && is_reduced(k, &SECP256K1_N)
}

/// Whether `d` is a valid secp256k1 private key: 32 bytes, in the range `[1, n - 1]`.
pub fn is_secp256k1_private_key(d: &[u8]) -> bool {
    d.len() == 32 && !is_zero(d) && is_reduced(d, &SECP256K1_N)
}

/// Whether `x` is a canonical secp256k1 field element, that is `x < p`.
pub fn is_secp256k1_field_element(x: &[u8]) -> bool {
    x.len() <= 32 && is_reduced(x, &SECP256K1_P)
}

/// How a 65-byte point passed to the curve ECALLs is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointEncoding {
    /// The point at infinity, encoded as 65 zero bytes.
    Infinity,
    /// An uncompressed SEC1 point `0x04 || x || y` with canonical coordinates. Whether the point
    /// is on the curve still has to be checked.
    Affine,
}

/// Classifies the encoding of a 65-byte point, or returns `None` if it is not a valid encoding:
/// a prefix other than `0x04` (or `0x00` with all-zero coordinates), or a coordinate that is not
/// smaller than p.
pub fn classify_secp256k1_point(p: &[u8; 65]) -> Option<PointEncoding> {
    match p[0] {
        0x00 if is_zero(&p[1..]) => Some(PointEncoding::Infinity),
        0x04 if is_secp256k1_field_element(&p[1..33]) && is_secp256k1_field_element(&p[33..65]) => {
            Some(PointEncoding::Affine)
        }
        _ => None,
    }
}

/// Whether the two halves `r || s` of a BIP-340 signature are in range: `0 < r < p` and
/// `0 < s < n`.
///
/// BIP-340 itself only requires `r < p` and `s < n`. `r = 0` is never a valid signature, since no
/// point of secp256k1 has x-coordinate 0; a valid signature with `s = 0` would require knowing
/// the discrete logarithm of the challenge, so rejecting it changes nothing in practice, and it
/// is what the device's library does.
pub fn is_schnorr_signature_in_range(sig: &[u8; 64]) -> bool {
    let (r, s) = sig.split_at(32);
    !is_zero(r) && is_secp256k1_field_element(r) && !is_zero(s) && is_secp256k1_scalar(s)
}

/// Parses a strictly DER-encoded ECDSA signature `0x30 len 0x02 rlen r 0x02 slen s`, as required
/// by BIP-66, and returns `(r, s)` as 32-byte big-endian integers.
///
/// Returns `None` unless the encoding is minimal and both integers are in the range
/// `[1, n - 1]`. High-S signatures are accepted.
pub fn parse_der_ecdsa_signature(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if sig.len() < 8 || sig.len() > MAX_ECDSA_SIGNATURE_LEN {
        return None;
    }
    if sig[0] != 0x30 || sig[1] as usize != sig.len() - 2 {
        return None;
    }

    // Parses an INTEGER at `pos`; returns its value and the position after it.
    let parse_int = |pos: usize| -> Option<([u8; 32], usize)> {
        if pos + 2 > sig.len() || sig[pos] != 0x02 {
            return None;
        }
        let len = sig[pos + 1] as usize;
        let start = pos + 2;
        if len == 0 || start + len > sig.len() {
            return None;
        }
        let bytes = &sig[start..start + len];
        // negative numbers are not allowed
        if bytes[0] & 0x80 != 0 {
            return None;
        }
        // a leading zero is only allowed if the next byte would otherwise make the number negative
        if len > 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0 {
            return None;
        }
        let bytes = if bytes[0] == 0 { &bytes[1..] } else { bytes };
        if bytes.len() > 32 {
            return None;
        }
        let mut value = [0u8; 32];
        value[32 - bytes.len()..].copy_from_slice(bytes);
        if is_zero(&value) || !is_secp256k1_scalar(&value) {
            return None;
        }
        Some((value, start + len))
    };

    let (r, pos) = parse_int(2)?;
    let (s, pos) = parse_int(pos)?;
    if pos != sig.len() {
        return None;
    }
    Some((r, s))
}

/// Splits a composite hash identifier (see [`HashId::ecall_id`]) into the algorithm and the
/// output size, or returns `None` if the identifier is not supported by the hash ECALLs.
///
/// Supported are RIPEMD-160 (20 bytes), SHA-256 (32), SHA-384 (48), SHA-512 (64), and Keccak and
/// SHA-3 with an output of 28, 32, 48 or 64 bytes.
pub fn parse_hash_identifier(hash_identifier: u32) -> Option<(HashId, usize)> {
    if hash_identifier >> 24 != 0 {
        return None;
    }
    let output_size = (hash_identifier & 0xFFFF) as usize;
    let (algorithm, valid_size) = match (hash_identifier >> 16) as u8 {
        x if x == HashId::Ripemd160 as u8 => (HashId::Ripemd160, output_size == 20),
        x if x == HashId::Sha256 as u8 => (HashId::Sha256, output_size == 32),
        x if x == HashId::Sha384 as u8 => (HashId::Sha384, output_size == 48),
        x if x == HashId::Sha512 as u8 => (HashId::Sha512, output_size == 64),
        x if x == HashId::Keccak as u8 => {
            (HashId::Keccak, matches!(output_size, 28 | 32 | 48 | 64))
        }
        x if x == HashId::Sha3 as u8 => (HashId::Sha3, matches!(output_size, 28 | 32 | 48 | 64)),
        _ => return None,
    };
    valid_size.then_some((algorithm, output_size))
}

/// Iterates over the labels of a SLIP-21 labels buffer, the concatenation of the labels, each
/// prefixed by its length in one byte.
///
/// Returns `None` if the buffer is longer than [`MAX_SLIP21_LABELS_LEN`], a label is longer than
/// [`MAX_SLIP21_LABEL_LEN`], or the last label is truncated. An empty buffer has no labels, and
/// denotes the master node.
pub fn parse_slip21_labels(labels: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    if labels.len() > MAX_SLIP21_LABELS_LEN {
        return None;
    }
    let mut pos = 0;
    while pos < labels.len() {
        let len = labels[pos] as usize;
        if len > MAX_SLIP21_LABEL_LEN || pos + 1 + len > labels.len() {
            return None;
        }
        pos += 1 + len;
    }

    let mut pos = 0;
    Some(core::iter::from_fn(move || {
        if pos >= labels.len() {
            return None;
        }
        let len = labels[pos] as usize;
        let label = &labels[pos + 1..pos + 1 + len];
        pos += 1 + len;
        Some(label)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn test_cmp_be() {
        assert_eq!(cmp_be(&[], &[]), Ordering::Equal);
        assert_eq!(cmp_be(&[0, 0, 1], &[1]), Ordering::Equal);
        assert_eq!(cmp_be(&[1, 0], &[0xff]), Ordering::Greater);
        assert_eq!(cmp_be(&[0xff], &[1, 0]), Ordering::Less);
        assert_eq!(cmp_be(&[1, 2, 3], &[1, 2, 4]), Ordering::Less);
        assert_eq!(cmp_be(&[2, 0, 0], &[1, 0xff, 0xff]), Ordering::Greater);
        assert_eq!(cmp_be(&SECP256K1_N, &SECP256K1_P), Ordering::Less);
    }

    fn plus(x: &[u8; 32], delta: i8) -> [u8; 32] {
        let mut r = *x;
        if delta >= 0 {
            for _ in 0..delta {
                let mut i = 31;
                loop {
                    let (v, carry) = r[i].overflowing_add(1);
                    r[i] = v;
                    if !carry || i == 0 {
                        break;
                    }
                    i -= 1;
                }
            }
        } else {
            for _ in 0..-delta {
                let mut i = 31;
                loop {
                    let (v, borrow) = r[i].overflowing_sub(1);
                    r[i] = v;
                    if !borrow || i == 0 {
                        break;
                    }
                    i -= 1;
                }
            }
        }
        r
    }

    #[test]
    fn test_modulus() {
        assert!(!is_modulus(&[0, 0], false));
        assert!(!is_modulus(&[], false));
        assert!(is_modulus(&[0, 2], false));
        assert!(!is_modulus(&[0, 2], true));
        assert!(is_modulus(&[0, 3], true));
    }

    #[test]
    fn test_scalars_and_keys() {
        assert!(is_secp256k1_scalar(&[0u8; 32]));
        assert!(is_secp256k1_scalar(&[]));
        assert!(is_secp256k1_scalar(&[7]));
        assert!(is_secp256k1_scalar(&plus(&SECP256K1_N, -1)));
        assert!(!is_secp256k1_scalar(&SECP256K1_N));
        assert!(!is_secp256k1_scalar(&[1u8; 33]));

        assert!(!is_secp256k1_private_key(&[0u8; 32]));
        assert!(is_secp256k1_private_key(&plus(&[0u8; 32], 1)));
        assert!(is_secp256k1_private_key(&plus(&SECP256K1_N, -1)));
        assert!(!is_secp256k1_private_key(&SECP256K1_N));
        assert!(!is_secp256k1_private_key(&[1u8; 31]));
    }

    #[test]
    fn test_classify_point() {
        let mut p = [0u8; 65];
        assert_eq!(classify_secp256k1_point(&p), Some(PointEncoding::Infinity));
        p[64] = 1;
        assert_eq!(classify_secp256k1_point(&p), None);

        let mut p = [0u8; 65];
        p[0] = 0x04;
        assert_eq!(classify_secp256k1_point(&p), Some(PointEncoding::Affine));
        p[1..33].copy_from_slice(&SECP256K1_P);
        assert_eq!(classify_secp256k1_point(&p), None);
        p[1..33].copy_from_slice(&plus(&SECP256K1_P, -1));
        p[33..65].copy_from_slice(&SECP256K1_P);
        assert_eq!(classify_secp256k1_point(&p), None);

        for prefix in [0x02, 0x03, 0x05, 0x06, 0x07, 0xff] {
            let mut p = [0u8; 65];
            p[0] = prefix;
            assert_eq!(classify_secp256k1_point(&p), None);
        }
    }

    #[test]
    fn test_schnorr_signature_range() {
        let mut sig = [1u8; 64];
        assert!(is_schnorr_signature_in_range(&sig));
        sig[..32].copy_from_slice(&SECP256K1_P);
        assert!(!is_schnorr_signature_in_range(&sig));
        sig[..32].copy_from_slice(&plus(&SECP256K1_P, -1));
        assert!(is_schnorr_signature_in_range(&sig));
        sig[32..].copy_from_slice(&SECP256K1_N);
        assert!(!is_schnorr_signature_in_range(&sig));
        sig[32..].copy_from_slice(&[0u8; 32]);
        assert!(!is_schnorr_signature_in_range(&sig));
        sig[32..].copy_from_slice(&[1u8; 32]);
        sig[..32].copy_from_slice(&[0u8; 32]);
        assert!(!is_schnorr_signature_in_range(&sig));
    }

    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x30);
        v.push((4 + r.len() + s.len()) as u8);
        v.push(0x02);
        v.push(r.len() as u8);
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v
    }

    #[test]
    fn test_parse_der() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(
            parse_der_ecdsa_signature(&der(&[1], &[1])),
            Some((one, one))
        );

        // high bit set requires a leading zero
        let mut high = [0u8; 32];
        high[31] = 0x80;
        assert_eq!(
            parse_der_ecdsa_signature(&der(&[0, 0x80], &[1])),
            Some((high, one))
        );
        assert_eq!(parse_der_ecdsa_signature(&der(&[0x80], &[1])), None);
        // unnecessary leading zero
        assert_eq!(parse_der_ecdsa_signature(&der(&[0, 1], &[1])), None);
        // zero
        assert_eq!(parse_der_ecdsa_signature(&der(&[0], &[1])), None);
        // empty integer
        assert_eq!(parse_der_ecdsa_signature(&der(&[], &[1])), None);

        // n - 1 is in range (it is a high-S value), n is not
        let n_minus_1 = plus(&SECP256K1_N, -1);
        let mut padded = Vec::from([0u8]);
        padded.extend_from_slice(&n_minus_1);
        assert_eq!(
            parse_der_ecdsa_signature(&der(&[1], &padded)),
            Some((one, n_minus_1))
        );
        let mut padded_n = Vec::from([0u8]);
        padded_n.extend_from_slice(&SECP256K1_N);
        assert_eq!(parse_der_ecdsa_signature(&der(&[1], &padded_n)), None);

        // wrong outer length, trailing bytes, wrong tags
        let mut sig = der(&[1], &[1]);
        sig[1] += 1;
        assert_eq!(parse_der_ecdsa_signature(&sig), None);
        let mut sig = der(&[1], &[1]);
        sig.push(0);
        assert_eq!(parse_der_ecdsa_signature(&sig), None);
        let mut sig = der(&[1], &[1]);
        sig[0] = 0x31;
        assert_eq!(parse_der_ecdsa_signature(&sig), None);
        let mut sig = der(&[1], &[1]);
        sig[2] = 0x03;
        assert_eq!(parse_der_ecdsa_signature(&sig), None);

        // too long overall
        let mut sig = der(&padded, &padded);
        assert_eq!(sig.len(), 72);
        assert!(parse_der_ecdsa_signature(&sig).is_some());
        sig.push(0);
        assert_eq!(parse_der_ecdsa_signature(&sig), None);
    }

    #[test]
    fn test_parse_hash_identifier() {
        assert_eq!(
            parse_hash_identifier(HashId::Sha256.ecall_id(32)),
            Some((HashId::Sha256, 32))
        );
        assert_eq!(parse_hash_identifier(HashId::Sha256.ecall_id(64)), None);
        assert_eq!(
            parse_hash_identifier(HashId::Ripemd160.ecall_id(20)),
            Some((HashId::Ripemd160, 20))
        );
        assert_eq!(
            parse_hash_identifier(HashId::Sha384.ecall_id(48)),
            Some((HashId::Sha384, 48))
        );
        assert_eq!(parse_hash_identifier(HashId::Sha512.ecall_id(65)), None);
        for size in [28, 32, 48, 64] {
            assert!(parse_hash_identifier(HashId::Keccak.ecall_id(size)).is_some());
            assert!(parse_hash_identifier(HashId::Sha3.ecall_id(size)).is_some());
        }
        assert_eq!(parse_hash_identifier(HashId::Sha3.ecall_id(20)), None);
        assert_eq!(parse_hash_identifier(0), None);
        assert_eq!(parse_hash_identifier(2 << 16 | 32), None);
        assert_eq!(
            parse_hash_identifier(1 << 24 | HashId::Sha256.ecall_id(32)),
            None
        );
    }

    #[test]
    fn test_parse_slip21_labels() {
        fn collect(b: &[u8]) -> Option<Vec<&[u8]>> {
            parse_slip21_labels(b).map(|it| it.collect())
        }

        assert_eq!(collect(&[]), Some(Vec::new()));
        assert_eq!(collect(&[0]), Some(Vec::from([&[][..]])));
        assert_eq!(
            collect(&[2, b'a', b'b', 1, b'c']),
            Some(Vec::from([&b"ab"[..], &b"c"[..]]))
        );
        assert_eq!(collect(&[3, b'a', b'b']), None);

        let mut longest = Vec::from([252u8]);
        longest.extend_from_slice(&[b'x'; 252]);
        assert!(collect(&longest).is_some());
        let mut too_long = Vec::from([253u8]);
        too_long.extend_from_slice(&[b'x'; 253]);
        assert_eq!(collect(&too_long), None);

        assert_eq!(collect(&[0u8; 257]), None);
        assert_eq!(collect(&[0u8; 256]).map(|v| v.len()), Some(256));
    }
}
