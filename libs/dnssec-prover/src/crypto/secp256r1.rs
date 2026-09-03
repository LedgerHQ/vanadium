//! secp256r1 validation for DNSSEC signatures

use crate::unhex::unhex;
use super::bigint::*;
use super::ec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P();
impl PrimeModulus<U256> for P {
	const PRIME: U256 = U256::from_32_be_bytes_panicking(
		&unhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
	const R_SQUARED_MOD_PRIME: U256 = U256::from_32_be_bytes_panicking(
		&unhex("00000004fffffffdfffffffffffffffefffffffbffffffff0000000000000003"));
	const NEGATIVE_PRIME_INV_MOD_R: U256 = U256::from_32_be_bytes_panicking(
		&unhex("ffffffff00000002000000000000000000000001000000000000000000000001"));
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct N();
impl PrimeModulus<U256> for N {
	const PRIME: U256 = U256::from_32_be_bytes_panicking(
		&unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
	const R_SQUARED_MOD_PRIME: U256 = U256::from_32_be_bytes_panicking(
		&unhex("66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2"));
	const NEGATIVE_PRIME_INV_MOD_R: U256 = U256::from_32_be_bytes_panicking(
		&unhex("60d06633a9d6281c50fe77ecc588c6f648c944087d74d2e4ccd1c8aaee00bc4f"));
}

#[derive(Clone, Copy)]
struct P256();

impl ec::Curve for P256 {
	type Int = U256;
	type CurveField = U256Mod<P>;
	type ScalarField = U256Mod<N>;

	type CurveModulus = P;
	type ScalarModulus = N;

	const A: U256Mod<P> = U256Mod::from_u256_panicking(U256::from_32_be_bytes_panicking(
		&unhex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc")));
	const B: U256Mod<P> = U256Mod::from_u256_panicking(U256::from_32_be_bytes_panicking(
		&unhex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")));

	const G: ec::Point<P256> = ec::Point::from_xy_assuming_on_curve(
		U256Mod::from_u256_panicking(U256::from_32_be_bytes_panicking(
			&unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"))),
		U256Mod::from_u256_panicking(U256::from_32_be_bytes_panicking(
			&unhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"))),
	);
}

/// Validates the given signature against the given public key and message digest.
pub fn validate_ecdsa(pk: &[u8], sig: &[u8], hash_input: &[u8]) -> Result<(), ()> {
	ec::validate_ecdsa::<P256>(pk, sig, hash_input)
}
