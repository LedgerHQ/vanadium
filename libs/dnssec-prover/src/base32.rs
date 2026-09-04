// This is a modification of base32 from https://crates.io/crates/base32(v0.4.0),
// copied from rust-lightning.
// The original portions of this software are Copyright (c) 2015 The base32 Developers
// The remainder is copyright rust-lightning developers, as viewable in version control at
// https://github.com/lightningdevkit/rust-lightning/

// This file is licensed under either of
// Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0) or
// MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT) at your option.

use alloc::vec::Vec;

/// RFC4648 "extended hex" encoding table
#[cfg(test)]
const RFC4648_ALPHABET: &'static [u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// RFC4648 "extended hex" decoding table
const RFC4648_INV_ALPHABET: [i8; 39] = [
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13,
	14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

/// Encode bytes into a base32 string.
#[cfg(test)]
pub fn encode(data: &[u8]) -> alloc::string::String {
	// output_length is calculated as follows:
	// / 5 divides the data length by the number of bits per chunk (5),
	// * 8 multiplies the result by the number of characters per chunk (8).
	// + 4 rounds up to the nearest character.
	let output_length = (data.len() * 8 + 4) / 5;
	let mut ret = encode_data(data, RFC4648_ALPHABET);
	ret.truncate(output_length);

	#[cfg(fuzzing)]
	assert_eq!(ret.capacity(), (data.len() + 4) / 5 * 8);

	alloc::string::String::from_utf8(ret).expect("Invalid UTF-8")
}

/// Decode a base32 string into a byte vector.
pub fn decode(data: &str) -> Result<Vec<u8>, ()> {
	let data = data.as_bytes();
	// If the string has more characters than are required to alphabet_encode the number of bytes
	// decodable, treat the string as invalid.
	match data.len() % 8 { 1|3|6 => return Err(()), _ => {} }
	decode_data(data, RFC4648_INV_ALPHABET)
}

/// Encode a byte slice into a base32 string.
#[cfg(test)]
fn encode_data(data: &[u8], alphabet: &'static [u8]) -> Vec<u8> {
	// cap is calculated as follows:
	// / 5 divides the data length by the number of bits per chunk (5),
	// * 8 multiplies the result by the number of characters per chunk (8).
	// + 4 rounds up to the nearest character.
	let cap = (data.len() + 4) / 5 * 8;
	let mut ret = Vec::with_capacity(cap);
	for chunk in data.chunks(5) {
		let mut buf = [0u8; 5];
		for (i, &b) in chunk.iter().enumerate() {
			buf[i] = b;
		}
		ret.push(alphabet[((buf[0] & 0xF8) >> 3) as usize]);
		ret.push(alphabet[(((buf[0] & 0x07) << 2) | ((buf[1] & 0xC0) >> 6)) as usize]);
		ret.push(alphabet[((buf[1] & 0x3E) >> 1) as usize]);
		ret.push(alphabet[(((buf[1] & 0x01) << 4) | ((buf[2] & 0xF0) >> 4)) as usize]);
		ret.push(alphabet[(((buf[2] & 0x0F) << 1) | (buf[3] >> 7)) as usize]);
		ret.push(alphabet[((buf[3] & 0x7C) >> 2) as usize]);
		ret.push(alphabet[(((buf[3] & 0x03) << 3) | ((buf[4] & 0xE0) >> 5)) as usize]);
		ret.push(alphabet[(buf[4] & 0x1F) as usize]);
	}
	#[cfg(fuzzing)]
	assert_eq!(ret.capacity(), cap);

	ret
}

fn decode_data(data: &[u8], alphabet: [i8; 39]) -> Result<Vec<u8>, ()> {
	// cap is calculated as follows:
	// / 8 divides the data length by the number of characters per chunk (8),
	// * 5 multiplies the result by the number of bits per chunk (5),
	// + 7 rounds up to the nearest byte.
	let cap = (data.len() + 7) / 8 * 5;
	let mut ret = Vec::with_capacity(cap);
	for chunk in data.chunks(8) {
		let mut buf = [0u8; 8];
		for (i, &c) in chunk.iter().enumerate() {
			match alphabet.get(c.to_ascii_uppercase().wrapping_sub(b'0') as usize) {
				Some(&-1) | None => return Err(()),
				Some(&value) => buf[i] = value as u8,
			};
		}
		ret.push((buf[0] << 3) | (buf[1] >> 2));
		ret.push((buf[1] << 6) | (buf[2] << 1) | (buf[3] >> 4));
		ret.push((buf[3] << 4) | (buf[4] >> 1));
		ret.push((buf[4] << 7) | (buf[5] << 2) | (buf[6] >> 3));
		ret.push((buf[6] << 5) | buf[7]);
	}
	let output_length = data.len() * 5 / 8;
	for c in ret.drain(output_length..) {
		if c != 0 {
			// If the original string had any bits set at positions outside of the encoded data,
			// treat the string as invalid.
			return Err(());
		}
	}

	// Check that our capacity calculation doesn't under-shoot in fuzzing
	#[cfg(fuzzing)]
	assert_eq!(ret.capacity(), cap);
	Ok(ret)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_encode_decode() {
		let mut bytes = [0u8; 256 * 5];
		for i in 0..=255 {
			bytes[i as usize + 256*0] = i;
			bytes[i as usize + 256*1] = i.wrapping_add(1);
			bytes[i as usize + 256*2] = i.wrapping_add(2);
			bytes[i as usize + 256*3] = i.wrapping_add(3);
			bytes[i as usize + 256*4] = i.wrapping_add(4);
		}
		assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
	}
}
