//! Discrete logarithm equality proofs (BIP-374): a proof that `A = a·G` and `C = a·B` for the
//! same secret `a`, without revealing it. BIP-375 uses them to prove the ECDH shares
//! `C = a·B_scan` of a transaction's inputs.

use hashes::{Hash, HashEngine};
use sdk::curve::{Secp256k1Point, Secp256k1Scalar};
use zeroize::Zeroizing;

use super::tags::{DleqAuxHash, DleqChallengeHash, DleqNonceHash};
use super::{ser_p, Error};

/// The challenge `e`, reduced modulo n.
fn challenge(
    a: &Secp256k1Point,
    b: &Secp256k1Point,
    c: &Secp256k1Point,
    g: &Secp256k1Point,
    r1: &Secp256k1Point,
    r2: &Secp256k1Point,
    m: Option<&[u8; 32]>,
) -> Secp256k1Scalar {
    let mut engine = DleqChallengeHash::engine();
    for p in [a, b, c, g, r1, r2] {
        engine.input(&ser_p(p));
    }
    if let Some(m) = m {
        engine.input(m);
    }
    Secp256k1Scalar::from_be_bytes_reduced(&DleqChallengeHash::from_engine(engine).to_byte_array())
}

/// Generates the proof that `a·g` and `a·b` have the same discrete logarithm, with the 32 bytes
/// of auxiliary randomness `r` and the optional message `m`. BIP-375 uses the generator for `g`
/// and no message.
///
/// The proof is verified before it is returned, as BIP-374 requires.
pub fn generate_proof(
    a: &Secp256k1Scalar,
    b: &Secp256k1Point,
    r: &[u8; 32],
    g: &Secp256k1Point,
    m: Option<&[u8; 32]>,
) -> Result<[u8; 64], Error> {
    if a.is_zero() || b.is_zero() || g.is_zero() {
        return Err(Error::InvalidProofInput);
    }
    let a_pub = g * a;
    let c = b * a;

    // t = bytes(a) XOR hash_BIP0374/aux(r)
    let aux = DleqAuxHash::hash(r).to_byte_array();
    let mut t = Zeroizing::new(*a.as_be_bytes());
    for (t, aux) in t.iter_mut().zip(aux) {
        *t ^= aux;
    }

    let mut engine = DleqNonceHash::engine();
    engine.input(&t[..]);
    engine.input(&ser_p(&a_pub));
    engine.input(&ser_p(&c));
    if let Some(m) = m {
        engine.input(m);
    }
    let k = Secp256k1Scalar::from_be_bytes_reduced(&Zeroizing::new(
        DleqNonceHash::from_engine(engine).to_byte_array(),
    ));
    if k.is_zero() {
        return Err(Error::InvalidProofInput);
    }

    let e = challenge(&a_pub, b, &c, g, &(g * &k), &(b * &k), m);
    let s = &k + &(&e * a);

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(e.as_be_bytes());
    proof[32..].copy_from_slice(s.as_be_bytes());
    if !verify_proof(&a_pub, b, &c, &proof, g, m) {
        return Err(Error::InvalidProofInput);
    }
    Ok(proof)
}

/// Verifies the proof that `a = x·g` and `c = x·b` for some `x`, with the optional message `m`.
pub fn verify_proof(
    a: &Secp256k1Point,
    b: &Secp256k1Point,
    c: &Secp256k1Point,
    proof: &[u8; 64],
    g: &Secp256k1Point,
    m: Option<&[u8; 32]>,
) -> bool {
    if a.is_zero() || b.is_zero() || c.is_zero() || g.is_zero() {
        return false;
    }
    let (Some(e), Some(s)) = (
        Secp256k1Scalar::from_be_bytes(proof[..32].try_into().unwrap()),
        Secp256k1Scalar::from_be_bytes(proof[32..].try_into().unwrap()),
    ) else {
        return false;
    };

    // R1 = s·G - e·A, R2 = s·B - e·C
    let minus_e = -&e;
    let r1 = &(g * &s) + &(a * &minus_e);
    let r2 = &(b * &s) + &(c * &minus_e);
    if r1.is_zero() || r2.is_zero() {
        return false;
    }
    challenge(a, b, c, g, &r1, &r2, m) == e
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdk::curve::Secp256k1;

    #[test]
    fn proofs_verify_and_bind_their_inputs() {
        let g = Secp256k1::get_generator();
        let a = Secp256k1Scalar::from_u32(12345);
        let b = &g * &Secp256k1Scalar::from_u32(678);
        let (a_pub, c) = (&g * &a, &b * &a);
        let m = [9u8; 32];

        for msg in [None, Some(&m)] {
            let proof = generate_proof(&a, &b, &[1; 32], &g, msg).unwrap();
            assert!(verify_proof(&a_pub, &b, &c, &proof, &g, msg));

            // another C, another message, or a damaged proof do not verify
            assert!(!verify_proof(&a_pub, &b, &(&c + &g), &proof, &g, msg));
            assert!(!verify_proof(&a_pub, &b, &c, &proof, &g, Some(&[8; 32])));
            let mut damaged = proof;
            damaged[40] ^= 1;
            assert!(!verify_proof(&a_pub, &b, &c, &damaged, &g, msg));
        }

        assert_eq!(
            generate_proof(&Secp256k1Scalar::zero(), &b, &[1; 32], &g, None),
            Err(Error::InvalidProofInput)
        );
        assert_eq!(
            generate_proof(&a, &Secp256k1Point::default(), &[1; 32], &g, None),
            Err(Error::InvalidProofInput)
        );
    }
}
