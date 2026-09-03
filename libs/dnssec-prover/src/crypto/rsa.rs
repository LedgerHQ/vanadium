//! A simple RSA implementation which handles DNSSEC RSA validation

use crate::unhex::unhex;
use super::bigint::*;

fn bytes_to_rsa_mod_exp_modlen(pubkey: &[u8]) -> Result<(U4096, u32, usize), ()> {
	if pubkey.len() <= 3 { return Err(()); }

	let mut pos = 0;
	let exponent_length;
	if pubkey[0] == 0 {
		exponent_length = ((pubkey[1] as usize) << 8) | (pubkey[2] as usize);
		pos += 3;
	} else {
		exponent_length = pubkey[0] as usize;
		pos += 1;
	}

	if pubkey.len() <= pos + exponent_length { return Err(()); }
	if exponent_length > 4 { return Err(()); }
	let mut exp_bytes = [0; 4];
	exp_bytes[4 - exponent_length..].copy_from_slice(&pubkey[pos..pos + exponent_length]);
	let exp = u32::from_be_bytes(exp_bytes);

	let mod_bytes = &pubkey[pos + exponent_length..];
	let modlen = pubkey.len() - pos - exponent_length;
	let modulus = U4096::from_be_bytes(mod_bytes)?;
	Ok((modulus, exp, modlen))
}

/// Validates the given RSA signature against the given RSA public key (up to 4096-bit, in
/// DNSSEC-encoded form) and given message digest.
pub fn validate_rsa(pk: &[u8], sig_bytes: &[u8], hash_input: &[u8]) -> Result<(), ()> {
	let (modulus, exponent, modulus_byte_len) = bytes_to_rsa_mod_exp_modlen(pk)?;
	if modulus_byte_len > 512 { /* implied by the U4096, but explicit here */ return Err(()); }
	let sig = U4096::from_be_bytes(sig_bytes)?;

	if sig > modulus { return Err(()); }

	// From https://www.rfc-editor.org/rfc/rfc5702#section-3.1
	const SHA256_PFX: [u8; 20] = unhex("003031300d060960864801650304020105000420");
	const SHA512_PFX: [u8; 20] = unhex("003051300d060960864801650304020305000440");
	let pfx = if hash_input.len() == 512 / 8 { &SHA512_PFX } else { &SHA256_PFX };

	if 512 - 2 - SHA256_PFX.len() <= hash_input.len() { return Err(()); }
	let mut hash_bytes = [0; 512];
	let mut hash_write_pos = 512 - hash_input.len();
	hash_bytes[hash_write_pos..].copy_from_slice(&hash_input);
	hash_write_pos -= pfx.len();
	hash_bytes[hash_write_pos..hash_write_pos + pfx.len()].copy_from_slice(pfx);
	while 512 + 1 - hash_write_pos < modulus_byte_len {
		hash_write_pos -= 1;
		hash_bytes[hash_write_pos] = 0xff;
	}
	hash_bytes[hash_write_pos] = 1;
	let hash = U4096::from_be_bytes(&hash_bytes)?;

	if hash > modulus { return Err(()); }

	// While modulus could be even, if it were we'd have already factored the modulus (one of the
	// primes is two!), so we don't particularly care if we fail spuriously for such spurious keys.
	let res = sig.expmod_odd_mod(exponent, &modulus)?;
	if res == hash {
		Ok(())
	} else {
		Err(())
	}
}
