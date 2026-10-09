//! Creating outputs to silent payment addresses (BIP-352).

use alloc::vec::Vec;

use bitcoin::OutPoint;
use hashes::{Hash, HashEngine};
use sdk::curve::{Secp256k1, Secp256k1Point, Secp256k1Scalar};

use super::tags::{hash_to_scalar, InputsHash, SharedSecretHash};
use super::{ser_p, Error, SilentPaymentCode, K_MAX};

/// BIP-352's encoding of an outpoint: the txid in the byte order of transactions, then the
/// output index, little-endian. Outpoints are compared in this encoding.
pub fn outpoint_bytes(outpoint: &OutPoint) -> [u8; 36] {
    let mut res = [0u8; 36];
    res[..32].copy_from_slice(outpoint.txid.as_byte_array());
    res[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    res
}

/// `input_hash = hash_BIP0352/Inputs(outpoint_L || A)`, where `outpoint_L` is the smallest of
/// all the outpoints that the transaction spends, eligible or not, and `A` is the sum of the
/// public keys of the eligible inputs.
pub fn input_hash(
    outpoints: &[OutPoint],
    input_key_sum: &Secp256k1Point,
) -> Result<Secp256k1Scalar, Error> {
    let smallest = outpoints
        .iter()
        .map(outpoint_bytes)
        .min()
        .ok_or(Error::NoInputs)?;
    if input_key_sum.is_zero() {
        return Err(Error::ZeroInputSum);
    }
    let mut engine = InputsHash::engine();
    engine.input(&smallest);
    engine.input(&ser_p(input_key_sum));
    hash_to_scalar(&InputsHash::from_engine(engine).to_byte_array())
}

/// The private key of an eligible input as it enters the sum `a`: for a taproot input, the key
/// of the output's x-only key, that is negated if its public key has an odd y.
pub fn input_private_key(key: &Secp256k1Scalar, is_taproot: bool) -> Secp256k1Scalar {
    if is_taproot && !(&Secp256k1::get_generator() * key).has_even_y() {
        -key
    } else {
        key.clone()
    }
}

/// The ECDH share `a·B_scan` for the scan key `scan`, from the sum `a` of the private keys of the
/// eligible inputs (or a part of it, for one input).
pub fn ecdh_share(a: &Secp256k1Scalar, scan: &Secp256k1Point) -> Secp256k1Point {
    scan * a
}

/// The shared secret `input_hash·a·B_scan`, from the ECDH share `a·B_scan` (summed over the
/// inputs, if each provided its own).
pub fn shared_secret(
    input_hash: &Secp256k1Scalar,
    share: &Secp256k1Point,
) -> Result<Secp256k1Point, Error> {
    let res = share * input_hash;
    if res.is_zero() {
        return Err(Error::InvalidKey);
    }
    Ok(res)
}

/// The tweak `t_k = hash_BIP0352/SharedSecret(ser_P(shared_secret) || ser_32(k))` of the `k`-th
/// output to the scan key of `shared_secret`.
pub(super) fn output_tweak(
    shared_secret: &Secp256k1Point,
    k: u32,
) -> Result<Secp256k1Scalar, Error> {
    if shared_secret.is_zero() {
        return Err(Error::InvalidKey);
    }
    let mut engine = SharedSecretHash::engine();
    engine.input(&ser_p(shared_secret));
    engine.input(&k.to_be_bytes());
    hash_to_scalar(&SharedSecretHash::from_engine(engine).to_byte_array())
}

/// The output key `P = B_m + t_k·G` of the `k`-th output to the scan key of `shared_secret`, with
/// the (possibly labeled) spend key `spend`. The output is the taproot output with x-only key
/// `P.x`.
pub fn output_key(
    shared_secret: &Secp256k1Point,
    spend: &Secp256k1Point,
    k: u32,
) -> Result<Secp256k1Point, Error> {
    if spend.is_zero() {
        return Err(Error::InvalidKey);
    }
    let t_k = output_tweak(shared_secret, k)?;
    let res = spend + &(&Secp256k1::get_generator() * &t_k);
    if res.is_zero() {
        return Err(Error::InvalidKey);
    }
    Ok(res)
}

/// The `k` of each recipient, in the order of `recipients`: recipients with the same scan key
/// share a counter, and take its values in the order in which they are given.
///
/// BIP-352 leaves this order free, since receivers find their outputs whatever it is. The parties
/// computing the outputs of the same transaction must agree on it, though, and BIP-375's reference
/// validator and test vectors assign `k` in the order of the outputs: callers following BIP-375
/// pass the recipients in output order. (The text of BIP-375 v0.1.2 asks instead to sort them by
/// code, which contradicts its own test vectors.)
pub fn assign_k(recipients: &[SilentPaymentCode]) -> Result<Vec<u32>, Error> {
    // the next k of each scan key seen so far
    let mut counters: Vec<(Secp256k1Point, u32)> = Vec::new();
    recipients
        .iter()
        .map(|recipient| {
            let k = match counters
                .iter_mut()
                .find(|(scan, _)| scan == recipient.scan())
            {
                Some((_, next)) => next,
                None => {
                    counters.push((*recipient.scan(), 0));
                    &mut counters.last_mut().unwrap().1
                }
            };
            if *k >= K_MAX {
                return Err(Error::TooManyRecipients);
            }
            *k += 1;
            Ok(*k - 1)
        })
        .collect()
}

/// The x-only output keys of BIP-352 for `recipients`, in their order.
///
/// `a` is the sum of the private keys of the eligible inputs, each as returned by
/// [`input_private_key`]; `outpoints` are all the outpoints the transaction spends.
pub fn create_outputs(
    a: &Secp256k1Scalar,
    outpoints: &[OutPoint],
    recipients: &[SilentPaymentCode],
) -> Result<Vec<[u8; 32]>, Error> {
    if a.is_zero() {
        return Err(Error::ZeroInputSum);
    }
    let input_hash = input_hash(outpoints, &(&Secp256k1::get_generator() * a))?;
    let ks = assign_k(recipients)?;

    // one shared secret per scan key
    let mut secrets: Vec<(Secp256k1Point, Secp256k1Point)> = Vec::new();
    let mut outputs = Vec::with_capacity(recipients.len());
    for (recipient, k) in recipients.iter().zip(ks) {
        let secret = match secrets.iter().find(|(scan, _)| scan == recipient.scan()) {
            Some((_, secret)) => *secret,
            None => {
                let secret = shared_secret(&input_hash, &ecdh_share(a, recipient.scan()))?;
                secrets.push((*recipient.scan(), secret));
                secret
            }
        };
        outputs.push(*output_key(&secret, recipient.spend(), k)?.x());
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(k: u32) -> Secp256k1Point {
        &Secp256k1::get_generator() * &Secp256k1Scalar::from_u32(k)
    }

    #[test]
    fn k_counts_per_scan_key_in_the_given_order() {
        let (s1, s2) = (point(1), point(2));
        let (a, b) = (point(10), point(11));
        let code = |scan, spend| SilentPaymentCode::new(scan, spend).unwrap();

        let recipients = [
            code(s1, b),
            code(s2, a),
            code(s1, a),
            code(s1, b),
            code(s2, a),
        ];
        assert_eq!(assign_k(&recipients).unwrap(), [0, 0, 1, 2, 1]);
    }

    #[test]
    fn k_max_per_scan_key() {
        let code = SilentPaymentCode::new(point(1), point(2)).unwrap();
        let other = SilentPaymentCode::new(point(3), point(2)).unwrap();
        let mut recipients = alloc::vec![code; K_MAX as usize];
        recipients.push(other);
        assert!(assign_k(&recipients).is_ok());
        recipients.push(code);
        assert_eq!(assign_k(&recipients), Err(Error::TooManyRecipients));
    }

    #[test]
    fn output_key_rejects_infinity() {
        let infinity = Secp256k1Point::default();
        assert_eq!(output_key(&infinity, &point(2), 0), Err(Error::InvalidKey));
        assert_eq!(output_key(&point(1), &infinity, 0), Err(Error::InvalidKey));
    }

    #[test]
    fn taproot_keys_are_normalized() {
        for k in 1..10u32 {
            let key = Secp256k1Scalar::from_u32(k);
            let normalized = input_private_key(&key, true);
            assert!((&Secp256k1::get_generator() * &normalized).has_even_y());
            assert_eq!(input_private_key(&key, false), key);
        }
    }

    #[test]
    fn create_outputs_rejects_degenerate_inputs() {
        let recipients = [SilentPaymentCode::new(point(1), point(2)).unwrap()];
        let outpoint = OutPoint::null();
        assert_eq!(
            create_outputs(&Secp256k1Scalar::zero(), &[outpoint], &recipients),
            Err(Error::ZeroInputSum)
        );
        assert_eq!(
            create_outputs(&Secp256k1Scalar::one(), &[], &recipients),
            Err(Error::NoInputs)
        );
    }
}
