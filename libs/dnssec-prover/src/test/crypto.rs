use crate::crypto::secp256r1::validate_ecdsa as validate_256r1;
use crate::crypto::secp384r1::validate_ecdsa as validate_384r1;
use crate::crypto::rsa::validate_rsa;
use crate::crypto::hash::{Hasher, HashResult};

use hex_conservative::FromHex;
use serde_json::Value;
use std::fs::File;

fn open_file(name: &str) -> File {
	if let Ok(f) = File::open(name) { return f; }
	if let Ok(f) = File::open("../".to_owned() + name) { return f; }
	if let Ok(f) = File::open("src/test/".to_owned() + name) { return f; }
	if let Ok(f) = File::open("../src/test/".to_owned() + name) { return f; }
	if let Ok(f) = File::open("../../src/test/".to_owned() + name) { return f; }
	panic!("Failed to find file {}", name);
}

fn decode_asn(sig: &str, int_len: usize) -> Result<Vec<u8>, ()> {
	// Signature is in ASN, so decode the garbage excess headers
	// Note that some tests are specifically for the ASN parser, so we have to carefully
	// reject invalid crap here.
	if sig.len() < 12 { return Err(()); }

	if &sig[..2] != "30" { return Err(()); }
	let total_len = (<[u8; 2]>::from_hex(&sig[..4]).unwrap())[1] as usize;
	if total_len + 2 != sig.len() / 2 { return Err(()); }

	if &sig[4..6] != "02" { return Err(()); }
	let r_len = (<[u8; 2]>::from_hex(&sig[4..8]).unwrap())[1] as usize;
	if sig.len() < r_len * 2 + 8 { return Err(()); }
	if r_len == 0 { return Err(()); }
	let r = Vec::from_hex(&sig[8..r_len * 2 + 8]).unwrap();
	if r.len() > int_len {
		// If the MSB is 1, an extra byte is required to avoid the sign flag
		if r.len() > int_len + 1 { return Err(()); }
		if r[0] != 0 { return Err(()); }
		if r[1] & 0b1000_0000 == 0 { return Err(()); }
	} else if r[0] & 0b1000_0000 != 0 { return Err(()); }

	if sig.len() < r_len * 2 + 12 { return Err(()); }
	if &sig[r_len * 2 + 8..r_len * 2 + 10] != "02" { return Err(()); }
	let s_len = (<[u8; 2]>::from_hex(&sig[r_len * 2 + 8..r_len * 2 + 12]).unwrap())[1] as usize;
	if sig.len() != r_len * 2 + s_len * 2 + 12 { return Err(()); }
	if s_len == 0 { return Err(()); }
	let s = Vec::from_hex(&sig[r_len * 2 + 12..]).unwrap();
	if s.len() > int_len {
		// If the MSB is 1, an extra byte is required to avoid the sign flag
		if s.len() > int_len + 1 { return Err(()); }
		if s[0] != 0 { return Err(()); }
		if s[1] & 0b1000_0000 == 0 { return Err(()); }
	} else if s[0] & 0b1000_0000 != 0 { return Err(()); }

	let mut sig_bytes = vec![0; int_len * 2];
	sig_bytes[int_len.saturating_sub(r.len())..int_len]
		.copy_from_slice(&r[r.len().saturating_sub(int_len)..]);
	sig_bytes[int_len + int_len.saturating_sub(s.len())..int_len * 2]
		.copy_from_slice(&s[s.len().saturating_sub(int_len)..]);

	Ok(sig_bytes)
}

fn test_ecdsa<
	Validate: Fn(&[u8], &[u8], &[u8]) -> Result<(), ()> + Clone,
	Hash: Fn(&[u8]) -> HashResult,
>(v: Value, int_len: usize, validate_fn: Validate, hash_fn: Hash) {
	for (group_idx, group) in v["testGroups"].as_array().unwrap().into_iter().enumerate() {
		let pk_str = group["publicKey"]["uncompressed"].as_str().unwrap();
		assert_eq!(&pk_str[..2], "04"); // OpenSSL uncompressed encoding flag
		let pk = Vec::from_hex(&pk_str[2..]).unwrap();
		for test in group["tests"].as_array().unwrap() {
			let msg = Vec::from_hex(test["msg"].as_str().unwrap()).unwrap();

			let expected_result = match test["result"].as_str().unwrap() {
				"valid" => Ok(()),
				"invalid" => Err(()),
				r => panic!("Unknown result type {}", r),
			};

			let sig = decode_asn(test["sig"].as_str().unwrap(), int_len);
			if sig.is_err() {
				assert_eq!(expected_result, Err(()));
				continue;
			}

			let hash = hash_fn(&msg);
			let pk = &pk[..];
			let validate_fn = validate_fn.clone();
			let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
				let result = validate_fn(&pk, &sig.unwrap(), hash.as_ref());
				assert_eq!(result, expected_result);
			}));
			if panicked.is_err() {
				panic!("Test case group {}, test id {}, comment {} panicked!", group_idx, test["tcId"], test["comment"]);
			}
		}
	}
}

#[test]
fn test_ecdsa_256r1() {
	let f = open_file("ecdsa_secp256r1_sha256_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_ecdsa(v, 32, validate_256r1, |msg| {
		let mut hasher = Hasher::sha256();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_ecdsa_384r1_sha256() {
	let f = open_file("ecdsa_secp384r1_sha256_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_ecdsa(v, 48, validate_384r1, |msg| {
		let mut hasher = Hasher::sha256();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_ecdsa_384r1_sha384() {
	let f = open_file("ecdsa_secp384r1_sha384_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_ecdsa(v, 48, validate_384r1, |msg| {
		let mut hasher = Hasher::sha384();
		hasher.update(msg);
		hasher.finish()
	});
}

fn test_rsa<Hash: Fn(&[u8]) -> HashResult>(v: Value, pk_len: usize, hash_fn: Hash) {
	for (group_idx, group) in v["testGroups"].as_array().unwrap().into_iter().enumerate() {
		let pk_str = group["publicKey"]["modulus"].as_str().unwrap();
		assert_eq!(&pk_str[..2], "00"); // No idea why this is here
		let pk = Vec::from_hex(&pk_str[2..]).unwrap();
		assert_eq!(pk.len(), pk_len);
		let exp_vec = Vec::from_hex(group["publicKey"]["publicExponent"].as_str().unwrap()).unwrap();
		if exp_vec.len() > 4 { panic!(); }
		let mut exp_bytes = [0; 4];
		exp_bytes[4 - exp_vec.len()..].copy_from_slice(&exp_vec);
		let exp = u32::from_be_bytes(exp_bytes);

		let mut pk_dns_encoded = Vec::new();
		pk_dns_encoded.push(4);
		pk_dns_encoded.extend_from_slice(&exp.to_be_bytes());
		pk_dns_encoded.extend_from_slice(&pk);

		for test in group["tests"].as_array().unwrap() {
			let msg = Vec::from_hex(test["msg"].as_str().unwrap()).unwrap();

			let result = match test["result"].as_str().unwrap() {
				"valid" => Ok(()),
				"invalid" => Err(()),
				"acceptable" => continue, // Why bother testing if the tests don't care?
				r => panic!("Unknown result type {}", r),
			};

			let sig = Vec::from_hex(test["sig"].as_str().unwrap()).unwrap();

			let hash = hash_fn(&msg);
			assert_eq!(result, validate_rsa(&pk_dns_encoded, &sig, hash.as_ref()),
				"Failed test case group {}, test id {}, comment {}", group_idx, test["tcId"], test["comment"]);
		}
	}
}

#[test]
fn test_rsa2048_sha256() {
	let f = open_file("rsa_signature_2048_sha256_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_rsa(v, 256, |msg| {
		let mut hasher = Hasher::sha256();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_rsa2048_sha512() {
	let f = open_file("rsa_signature_2048_sha512_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_rsa(v, 256, |msg| {
		let mut hasher = Hasher::sha512();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_rsa3072_sha256() {
	let f = open_file("rsa_signature_3072_sha256_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_rsa(v, 384, |msg| {
		let mut hasher = Hasher::sha256();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_rsa3072_sha512() {
	let f = open_file("rsa_signature_3072_sha512_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_rsa(v, 384, |msg| {
		let mut hasher = Hasher::sha512();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_rsa4096_sha256() {
	let f = open_file("rsa_signature_4096_sha256_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_rsa(v, 512, |msg| {
		let mut hasher = Hasher::sha256();
		hasher.update(msg);
		hasher.finish()
	});
}

#[test]
fn test_rsa4096_sha512() {
	let f = open_file("rsa_signature_4096_sha512_test.json");
	let v: Value = serde_json::from_reader(f).unwrap();
	test_rsa(v, 512, |msg| {
		let mut hasher = Hasher::sha512();
		hasher.update(msg);
		hasher.finish()
	});
}
