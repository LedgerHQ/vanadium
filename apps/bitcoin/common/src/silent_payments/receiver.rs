//! Receiving silent payments: labels, finding a transaction's outputs, and spending them
//! (BIP-352).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::OutPoint;
use hashes::{Hash, HashEngine};
use sdk::curve::{Secp256k1, Secp256k1Point, Secp256k1Scalar};

use super::sender::output_tweak;
use super::tags::{hash_to_scalar, LabelHash};
use super::{input_hash, shared_secret, Error, K_MAX};

/// The tweak of label `m`, `hash_BIP0352/Label(ser_256(b_scan) || ser_32(m))`. Label 0 is the
/// change label, which wallets never hand out.
pub fn label_tweak(b_scan: &Secp256k1Scalar, m: u32) -> Result<Secp256k1Scalar, Error> {
    let mut engine = LabelHash::engine();
    engine.input(b_scan.as_be_bytes());
    engine.input(&m.to_be_bytes());
    hash_to_scalar(&LabelHash::from_engine(engine).to_byte_array())
}

/// The spend key of label `m`, `B_m = B_spend + label_tweak·G`.
pub fn labeled_spend_key(
    spend: &Secp256k1Point,
    b_scan: &Secp256k1Scalar,
    m: u32,
) -> Result<Secp256k1Point, Error> {
    let res = spend + &(&Secp256k1::get_generator() * &label_tweak(b_scan, m)?);
    if res.is_zero() {
        return Err(Error::InvalidKey);
    }
    Ok(res)
}

/// The private key `d = b_spend + tweak` of an output, where `tweak` is the tweak of the output
/// (including the label's, if any). Signing with BIP-340 takes care of negating it if `d·G` has
/// an odd y.
pub fn spending_key(
    b_spend: &Secp256k1Scalar,
    tweak: &Secp256k1Scalar,
) -> Result<Secp256k1Scalar, Error> {
    let d = b_spend + tweak;
    if d.is_zero() {
        return Err(Error::InvalidKey);
    }
    Ok(d)
}

/// The labels to look for when scanning, found by their point `label_tweak·G`.
#[derive(Debug, Clone, Default)]
pub struct Labels(BTreeMap<Secp256k1Point, Secp256k1Scalar>);

impl Labels {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the label `m` of the receiver with scan private key `b_scan`.
    pub fn insert(&mut self, b_scan: &Secp256k1Scalar, m: u32) -> Result<(), Error> {
        let tweak = label_tweak(b_scan, m)?;
        self.0.insert(&Secp256k1::get_generator() * &tweak, tweak);
        Ok(())
    }
}

/// An output of a transaction that pays to the receiver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundOutput {
    /// The x-only key of the taproot output.
    pub output_key: [u8; 32],
    /// The tweak to add to the spend private key to spend the output.
    pub tweak: Secp256k1Scalar,
}

/// Finds the outputs of a transaction that pay to the receiver with scan private key `b_scan`
/// and spend public key `spend`, unlabeled or with one of `labels`.
///
/// `input_key_sum` is the sum `A` of the public keys of the transaction's eligible inputs,
/// `outpoints` all the outpoints it spends, and `outputs` the x-only keys of its taproot outputs.
/// A transaction whose `A` is the point at infinity pays to nobody.
pub fn scan(
    b_scan: &Secp256k1Scalar,
    spend: &Secp256k1Point,
    input_key_sum: &Secp256k1Point,
    outpoints: &[OutPoint],
    outputs: &[[u8; 32]],
    labels: &Labels,
) -> Result<Vec<FoundOutput>, Error> {
    if spend.is_zero() {
        return Err(Error::InvalidKey);
    }
    if input_key_sum.is_zero() {
        return Ok(Vec::new());
    }
    let input_hash = input_hash(outpoints, input_key_sum)?;
    let secret = shared_secret(&input_hash, &(input_key_sum * b_scan))?;

    // the outputs that may still be found; x-only keys without a point can't match anything
    let mut remaining: Vec<([u8; 32], Secp256k1Point)> = outputs
        .iter()
        .filter_map(|x| Secp256k1Point::lift_x(x).ok().map(|p| (*x, p)))
        .collect();

    let mut found = Vec::new();
    for k in 0..K_MAX {
        let t_k = output_tweak(&secret, k)?;
        let p_k = spend + &(&Secp256k1::get_generator() * &t_k);
        let minus_p_k = -&p_k;

        let matched = remaining.iter().enumerate().find_map(|(i, (x, point))| {
            if p_k.x() == x {
                return Some((i, t_k.clone()));
            }
            if labels.0.is_empty() {
                return None;
            }
            // a labeled output is P_k + label·G, whose x-only key may be the one of either the
            // point or its negation
            for candidate in [point + &minus_p_k, &-point + &minus_p_k] {
                if let Some(label_tweak) = labels.0.get(&candidate) {
                    return Some((i, &t_k + label_tweak));
                }
            }
            None
        });
        match matched {
            Some((i, tweak)) => {
                found.push(FoundOutput {
                    output_key: remaining[i].0,
                    tweak,
                });
                remaining.remove(i);
            }
            None => break,
        }
    }
    Ok(found)
}
