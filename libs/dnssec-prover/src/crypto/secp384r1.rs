//! secp384r1 validation for DNSSEC signatures

use sdk::bignum::{BigNumMod, ModulusProvider, PrimeModulusProvider};

use crate::unhex::unhex;
use super::ec;

/// The curve field modulus, `p`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct P();
impl ModulusProvider<48> for P {
    const M: [u8; 48] = unhex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    );
}
impl PrimeModulusProvider<48> for P {}

/// The scalar field modulus, `n`, the order of the generator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct N();
impl ModulusProvider<48> for N {
    const M: [u8; 48] = unhex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    );
}
impl PrimeModulusProvider<48> for N {}

#[derive(Clone, Copy)]
pub(super) struct P384();

impl ec::Curve<48> for P384 {
    type CurveModulus = P;
    type ScalarModulus = N;

    const A: ec::CurveField<48, P384> = BigNumMod::from_be_bytes_noreduce(unhex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    ));
    const B: ec::CurveField<48, P384> = BigNumMod::from_be_bytes_noreduce(unhex(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    ));

    const G: ec::Point<48, P384> = ec::Point::from_xy_assuming_on_curve(
        BigNumMod::from_be_bytes_noreduce(unhex(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        )),
        BigNumMod::from_be_bytes_noreduce(unhex(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        )),
    );
}

/// Validates the given signature against the given public key and message digest.
pub fn validate_ecdsa(pk: &[u8], sig: &[u8], hash_input: &[u8]) -> Result<(), ()> {
    ec::validate_ecdsa::<48, P384>(pk, sig, hash_input)
}
