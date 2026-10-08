//! Cross-checks the key operations, which use the Vanadium SDK, against k256, an independent
//! implementation of secp256k1.

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar as KScalar};

use crate::{ecdh, Error, PublicKey, Scalar, Secp256k1, SecretKey};

/// Deterministic pseudo-random scalars in [1, n - 1] (xorshift; good enough for tests).
fn scalars(count: usize) -> Vec<[u8; 32]> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut res = Vec::new();
    while res.len() < count {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_be_bytes());
        }
        if SecretKey::from_slice(&bytes).is_ok() {
            res.push(bytes);
        }
    }
    res
}

fn k_scalar(bytes: &[u8; 32]) -> KScalar {
    Option::from(KScalar::from_repr((*bytes).into())).unwrap()
}

fn k_point(pk: &PublicKey) -> ProjectivePoint {
    let encoded = k256::EncodedPoint::from_bytes(pk.serialize_uncompressed()).unwrap();
    let affine: Option<k256::AffinePoint> = k256::AffinePoint::from_encoded_point(&encoded).into();
    ProjectivePoint::from(affine.unwrap())
}

fn uncompressed(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(false).as_bytes().to_vec()
}

fn pk(bytes: &[u8; 32]) -> PublicKey {
    PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(bytes).unwrap())
}

#[test]
fn public_key_from_secret_key() {
    for d in scalars(8) {
        let expected = ProjectivePoint::GENERATOR * k_scalar(&d);
        assert_eq!(pk(&d).serialize_uncompressed().to_vec(), uncompressed(&expected));
    }
}

#[test]
fn public_key_combine() {
    let keys: Vec<PublicKey> = scalars(5).iter().map(pk).collect();
    let refs: Vec<&PublicKey> = keys.iter().collect();
    let expected = keys.iter().fold(ProjectivePoint::IDENTITY, |acc, k| acc + k_point(k));
    let sum = PublicKey::combine_keys(&refs).unwrap();
    assert_eq!(sum.serialize_uncompressed().to_vec(), uncompressed(&expected));
    assert_eq!(keys[0].combine(&keys[1]).unwrap(), PublicKey::combine_keys(&refs[..2]).unwrap());

    // a sum that is the point at infinity, and the empty sum
    let neg = keys[0].negate(&Secp256k1::new());
    assert_eq!(keys[0].combine(&neg), Err(Error::InvalidPublicKeySum));
    assert_eq!(PublicKey::combine_keys(&[]), Err(Error::InvalidPublicKeySum));
}

#[test]
fn public_key_negate_and_mul_tweak() {
    let secp = Secp256k1::new();
    let s = scalars(8);
    for pair in s.chunks(2) {
        let (key, tweak) = (pk(&pair[0]), Scalar::from_be_bytes(pair[1]).unwrap());

        let neg = key.negate(&secp);
        assert_eq!(neg.serialize_uncompressed().to_vec(), uncompressed(&-k_point(&key)));

        let product = key.mul_tweak(&secp, &tweak).unwrap();
        let expected = k_point(&key) * k_scalar(&pair[1]);
        assert_eq!(product.serialize_uncompressed().to_vec(), uncompressed(&expected));
    }
    assert_eq!(pk(&s[0]).mul_tweak(&secp, &Scalar::ZERO), Err(Error::InvalidTweak));
}

#[test]
fn secret_key_tweaks() {
    let s = scalars(8);
    for pair in s.chunks(2) {
        let key = SecretKey::from_slice(&pair[0]).unwrap();
        let tweak = Scalar::from_be_bytes(pair[1]).unwrap();
        let (kd, kt) = (k_scalar(&pair[0]), k_scalar(&pair[1]));

        assert_eq!(key.negate().secret_bytes(), <[u8; 32]>::from((-kd).to_repr()));
        assert_eq!(
            key.add_tweak(&tweak).unwrap().secret_bytes(),
            <[u8; 32]>::from((kd + kt).to_repr())
        );
        assert_eq!(
            key.mul_tweak(&tweak).unwrap().secret_bytes(),
            <[u8; 32]>::from((kd * kt).to_repr())
        );
    }

    let key = SecretKey::from_slice(&s[0]).unwrap();
    let minus_key = Scalar::from_be_bytes(key.negate().secret_bytes()).unwrap();
    assert_eq!(key.add_tweak(&minus_key), Err(Error::InvalidTweak));
    assert_eq!(key.mul_tweak(&Scalar::ZERO), Err(Error::InvalidTweak));
}

#[test]
fn ecdh_shared_secret_point() {
    let s = scalars(6);
    for pair in s.chunks(2) {
        let (d1, d2) =
            (SecretKey::from_slice(&pair[0]).unwrap(), SecretKey::from_slice(&pair[1]).unwrap());
        let (p1, p2) = (pk(&pair[0]), pk(&pair[1]));

        let shared = ecdh::shared_secret_point(&p2, &d1);
        let expected = k_point(&p2) * k_scalar(&pair[0]);
        assert_eq!(shared.to_vec(), uncompressed(&expected)[1..].to_vec());
        assert_eq!(shared, ecdh::shared_secret_point(&p1, &d2));
    }
}
