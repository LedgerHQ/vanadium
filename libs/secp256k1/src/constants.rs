// SPDX-License-Identifier: CC0-1.0

//! Constants related to the API and the underlying curve.
//!

/// The size (in bytes) of a message.
pub const MESSAGE_SIZE: usize = 32;

/// The size (in bytes) of a secret key.
pub const SECRET_KEY_SIZE: usize = 32;

/// The size (in bytes) of a serialized public key.
pub const PUBLIC_KEY_SIZE: usize = 33;

/// The size (in bytes) of an serialized uncompressed public key.
pub const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 65;

/// The maximum size of a signature.
pub const MAX_SIGNATURE_SIZE: usize = 72;

/// The maximum size of a compact signature.
pub const COMPACT_SIGNATURE_SIZE: usize = 64;

/// The size of a schnorr signature.
pub const SCHNORR_SIGNATURE_SIZE: usize = 64;

/// The size of a schnorr public key.
pub const SCHNORR_PUBLIC_KEY_SIZE: usize = 32;

/// The size of a key pair.
pub const KEY_PAIR_SIZE: usize = 96;

/// The Prime for the secp256k1 field element.
#[rustfmt::skip]
pub const FIELD_SIZE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
];

/// The order of the secp256k1 curve.
#[rustfmt::skip]
pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
];

/// The X coordinate of the generator.
#[rustfmt::skip]
pub const GENERATOR_X: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
];

/// The Y coordinate of the generator.
#[rustfmt::skip]
pub const GENERATOR_Y: [u8; 32] = [
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
    0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
];

/// The value of (p + 1) / 4, where p is the curve Prime.
#[rustfmt::skip]
pub(crate) const SQR_EXPONENT: [u8; 32] = [
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c
];

/// The value zero as an array of bytes.
pub const ZERO: [u8; 32] = [0; 32];

/// The value one as big-endian array of bytes.
pub const ONE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

/// The curve Prime, represented as a ModulusProvider from Vanadium's app-sdk
#[derive(Debug, Clone, Copy)]
pub struct P;
impl sdk::bignum::ModulusProvider<32> for P {
    const M: [u8; 32] = FIELD_SIZE;
}

/// The curve order, represented as a ModulusProvider from Vanadium's app-sdk
#[derive(Debug, Clone, Copy)]
pub struct N;
impl sdk::bignum::ModulusProvider<32> for N {
    const M: [u8; 32] = CURVE_ORDER;
}

/// The curve generator, represented as a Secp256k1Point from Vanadium's app-sdk
pub const G: sdk::curve::Secp256k1Point = sdk::curve::Secp256k1::get_generator();
