//! secp384r1 validation for DNSSEC signatures

use crate::unhex::unhex;
use super::bigint::*;
use super::ec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P();
impl PrimeModulus<U384> for P {
	const PRIME: U384 = U384::from_48_be_bytes_panicking(&unhex(
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"));
	const R_SQUARED_MOD_PRIME: U384 = U384::from_48_be_bytes_panicking(&unhex(
		"000000000000000000000000000000010000000200000000fffffffe000000000000000200000000fffffffe00000001"));
	const NEGATIVE_PRIME_INV_MOD_R: U384 = U384::from_48_be_bytes_panicking(&unhex(
		"00000014000000140000000c00000002fffffffcfffffffafffffffbfffffffe00000000000000010000000100000001"));
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct N();
impl PrimeModulus<U384> for N {
	const PRIME: U384 = U384::from_48_be_bytes_panicking(&unhex(
		"ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"));
	const R_SQUARED_MOD_PRIME: U384 = U384::from_48_be_bytes_panicking(&unhex(
		"0c84ee012b39bf213fb05b7a28266895d40d49174aab1cc5bc3e483afcb82947ff3d81e5df1aa4192d319b2419b409a9"));
	const NEGATIVE_PRIME_INV_MOD_R: U384 = U384::from_48_be_bytes_panicking(&unhex(
		"355ca87de39dbb1fa150206ce4f194ac78d4ba5866d61787ee6c8e3df45624ce54a885995d20bb2b6ed46089e88fdc45"));
}

#[derive(Clone, Copy)]
struct P384();

impl ec::Curve for P384 {
	type Int = U384;
	type CurveField = U384Mod<P>;
	type ScalarField = U384Mod<N>;

	type CurveModulus = P;
	type ScalarModulus = N;

	const A: U384Mod<P> = U384Mod::from_u384_panicking(U384::from_48_be_bytes_panicking(&unhex(
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc")));
	const B: U384Mod<P> = U384Mod::from_u384_panicking(U384::from_48_be_bytes_panicking(&unhex(
		"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef")));

	const G: ec::Point<P384> = ec::Point::from_xy_assuming_on_curve(
		U384Mod::from_u384_panicking(U384::from_48_be_bytes_panicking(&unhex(
			"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"))),
		U384Mod::from_u384_panicking(U384::from_48_be_bytes_panicking(&unhex(
			"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"))),
	);
}

/// Validates the given signature against the given public key and message digest.
pub fn validate_ecdsa(pk: &[u8], sig: &[u8], hash_input: &[u8]) -> Result<(), ()> {
	ec::validate_ecdsa::<P384>(pk, sig, hash_input)
}
