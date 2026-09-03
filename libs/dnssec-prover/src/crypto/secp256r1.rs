//! secp256r1 validation for DNSSEC signatures

use sdk::bignum::{BigNumMod, ModulusProvider, PrimeModulusProvider};

use crate::unhex::unhex;
use super::ec;

/// The curve field modulus, `p`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct P();
impl ModulusProvider<32> for P {
    const M: [u8; 32] =
        unhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
}
impl PrimeModulusProvider<32> for P {}

/// The scalar field modulus, `n`, the order of the generator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct N();
impl ModulusProvider<32> for N {
    const M: [u8; 32] =
        unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
}
impl PrimeModulusProvider<32> for N {}

#[derive(Clone, Copy)]
pub(super) struct P256();

impl ec::Curve<32> for P256 {
    type CurveModulus = P;
    type ScalarModulus = N;

    const A: ec::CurveField<32, P256> = BigNumMod::from_be_bytes_noreduce(unhex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    ));
    const B: ec::CurveField<32, P256> = BigNumMod::from_be_bytes_noreduce(unhex(
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    ));

    const G: ec::Point<32, P256> = ec::Point::from_xy_assuming_on_curve(
        BigNumMod::from_be_bytes_noreduce(unhex(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        )),
        BigNumMod::from_be_bytes_noreduce(unhex(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )),
    );
}

/// Validates the given signature against the given public key and message digest.
pub fn validate_ecdsa(pk: &[u8], sig: &[u8], hash_input: &[u8]) -> Result<(), ()> {
    ec::validate_ecdsa::<32, P256>(pk, sig, hash_input)
}
