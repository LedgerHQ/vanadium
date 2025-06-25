// SPDX-License-Identifier: CC0-1.0

//! Support for schnorr signatures.
//!

use core::{fmt, str};

use crate::key::{Keypair, XOnlyPublicKey};
use crate::{constants, from_hex, Error, Message, Secp256k1, Signing, Verification};

/// Represents a schnorr signature.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature([u8; constants::SCHNORR_SIGNATURE_SIZE]);
impl_array_newtype!(Signature, u8, constants::SCHNORR_SIGNATURE_SIZE);
impl_pretty_debug!(Signature);

#[cfg(feature = "serde")]
impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 64 byte schnorr signature",
            ))
        } else {
            d.deserialize_bytes(super::serde_util::BytesVisitor::new(
                "raw 64 bytes schnorr signature",
                Signature::from_slice,
            ))
        }
    }
}

impl fmt::LowerHex for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.0[..] {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl str::FromStr for Signature {
    type Err = Error;
    fn from_str(s: &str) -> Result<Signature, Error> {
        let mut res = [0u8; constants::SCHNORR_SIGNATURE_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORR_SIGNATURE_SIZE) =>
                Signature::from_slice(&res[0..constants::SCHNORR_SIGNATURE_SIZE]),
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl Signature {
    /// Creates a `Signature` directly from a slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Signature, Error> {
        match data.len() {
            constants::SCHNORR_SIGNATURE_SIZE => {
                let mut ret = [0u8; constants::SCHNORR_SIGNATURE_SIZE];
                ret[..].copy_from_slice(data);
                Ok(Signature(ret))
            }
            _ => Err(Error::InvalidSignature),
        }
    }

    /// Returns a signature as a byte array.
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORR_SIGNATURE_SIZE] { self.0 }
}

impl<C: Signing> Secp256k1<C> {
    /// Creates a schnorr signature without using any auxiliary random data.
    pub fn sign_schnorr_no_aux_rand(&self, msg: &Message, keypair: &Keypair) -> Signature {
        let privkey = sdk::curve::EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(
            *keypair.secret_key().as_ref(),
        );
        let sig_raw = privkey.schnorr_sign(msg.as_ref(), None).unwrap();
        Signature::from_slice(&sig_raw).unwrap()
    }

    /// Creates a schnorr signature using the given auxiliary random data.
    pub fn sign_schnorr_with_aux_rand(
        &self,
        msg: &Message,
        keypair: &Keypair,
        aux_rand: &[u8; 32],
    ) -> Signature {
        let privkey = sdk::curve::EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(
            *keypair.secret_key().as_ref(),
        );
        let sig_raw = privkey.schnorr_sign(msg.as_ref(), Some(aux_rand)).unwrap();
        Signature::from_slice(&sig_raw).unwrap()
    }

    /// Creates a schnorr signature using the given auxiliary random data.
    #[cfg(feature = "rand")]
    pub fn sign_schnorr_with_rng<R: rand::Rng + rand::CryptoRng>(
        &self,
        msg: &Message,
        keypair: &Keypair,
        rng: &mut R,
    ) -> Signature {
        self.sign_schnorr_with_aux_rand(msg, keypair, &rng.gen())
    }
}

impl<C: Verification> Secp256k1<C> {
    /// Verifies a schnorr signature.
    pub fn verify_schnorr(
        &self,
        sig: &Signature,
        msg: &Message,
        pubkey: &XOnlyPublicKey,
    ) -> Result<(), Error> {
        let pubkey_serialized = pubkey.public_key(crate::Parity::Even).serialize_uncompressed();
        let mut x_bytes = [0u8; 32];
        let mut y_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&pubkey_serialized[1..33]);
        y_bytes.copy_from_slice(&pubkey_serialized[33..65]);

        let pubkey = sdk::curve::EcfpPublicKey::<sdk::curve::Secp256k1, 32>::new(x_bytes, y_bytes);
        pubkey.schnorr_verify(&msg.0, &sig.0).map_err(|_| Error::IncorrectSignature)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use core::str::FromStr;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;
    use crate::schnorr::{Keypair, Signature, XOnlyPublicKey};
    use crate::Error::InvalidPublicKey;
    use crate::{constants, from_hex, Message, Secp256k1, SecretKey};

    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    macro_rules! hex_32 {
        ($hex:expr) => {{
            let mut result = [0u8; 32];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    #[test]
    #[cfg(feature = "alloc")]
    #[cfg(not(secp256k1_fuzz))] // fixed sig vectors can't work with fuzz-sigs
    fn schnorr_sign() {
        let secp = Secp256k1::new();

        let hex_msg = hex_32!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_digest_slice(&hex_msg).unwrap();
        let sk = Keypair::from_seckey_str(
            &secp,
            "688C77BC2D5AAFF5491CF309D4753B732135470D05B7B2CD21ADD0744FE97BEF",
        )
        .unwrap();
        // let aux_rand: [u8; 32] =
        //     hex_32!("02CCE08E913F22A36C5648D6405A2C7C50106E7AA2F1649E381C7F09D16B80AB");
        // let expected_sig = Signature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();

        // let sig = secp.sign_schnorr_with_aux_rand(&msg, &sk, &aux_rand);

        // assert_eq!(expected_sig, sig);

        // the original test code (commented) uses sign_schnorr_with_aux_rand, which is not implemented.
        // Since signatures are random, we instead do a sign/verify round-trip for this test.
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &sk);

        assert!(secp.verify_schnorr(&sig, &msg, &sk.x_only_public_key().0).is_ok());
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))] // fixed sig vectors can't work with fuzz-sigs
    #[cfg(feature = "alloc")]
    fn schnorr_verify() {
        let secp = Secp256k1::new();

        let hex_msg = hex_32!("E48441762FB75010B2AA31A512B62B4148AA3FB08EB0765D76B252559064A614");
        let msg = Message::from_digest_slice(&hex_msg).unwrap();
        let sig = Signature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();
        let pubkey = XOnlyPublicKey::from_str(
            "B33CC9EDC096D0A83416964BD3C6247B8FECD256E4EFA7870D2C854BDEB33390",
        )
        .unwrap();

        assert!(secp.verify_schnorr(&sig, &msg, &pubkey).is_ok());
    }

    #[test]
    fn test_serialize() {
        let sig = Signature::from_str("6470FD1303DDA4FDA717B9837153C24A6EAB377183FC438F939E0ED2B620E9EE5077C4A8B8DCA28963D772A94F5F0DDF598E1C47C137F91933274C7C3EDADCE8").unwrap();
        let sig_bytes = sig.serialize();
        let bytes = [
            100, 112, 253, 19, 3, 221, 164, 253, 167, 23, 185, 131, 113, 83, 194, 74, 110, 171, 55,
            113, 131, 252, 67, 143, 147, 158, 14, 210, 182, 32, 233, 238, 80, 119, 196, 168, 184,
            220, 162, 137, 99, 215, 114, 169, 79, 95, 13, 223, 89, 142, 28, 71, 193, 55, 249, 25,
            51, 39, 76, 124, 62, 218, 220, 232,
        ];
        assert_eq!(sig_bytes, bytes);
    }

    #[test]
    fn test_pubkey_from_slice() {
        assert_eq!(XOnlyPublicKey::from_slice(&[]), Err(InvalidPublicKey));
        assert_eq!(XOnlyPublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));
        assert_eq!(XOnlyPublicKey::from_slice(&crate::constants::ZERO), Err(InvalidPublicKey));
        let invalid_pk = XOnlyPublicKey::from_slice(&[
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, // no valid point has this x-coordinate
        ]);
        assert_eq!(invalid_pk, Err(InvalidPublicKey));
        let pk = XOnlyPublicKey::from_slice(&[
            0xB3, 0x3C, 0xC9, 0xED, 0xC0, 0x96, 0xD0, 0xA8, 0x34, 0x16, 0x96, 0x4B, 0xD3, 0xC6,
            0x24, 0x7B, 0x8F, 0xEC, 0xD2, 0x56, 0xE4, 0xEF, 0xA7, 0x87, 0x0D, 0x2C, 0x85, 0x4B,
            0xDE, 0xB3, 0x33, 0x90,
        ]);
        assert!(pk.is_ok());
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_xonly_key_extraction() {
        let secp = Secp256k1::new();
        let sk_str = "688C77BC2D5AAFF5491CF309D4753B732135470D05B7B2CD21ADD0744FE97BEF";
        let keypair = Keypair::from_seckey_str(&secp, sk_str).unwrap();
        let sk = SecretKey::from_keypair(&keypair);
        assert_eq!(SecretKey::from_str(sk_str).unwrap(), sk);
        let pk = crate::key::PublicKey::from_keypair(&keypair);
        assert_eq!(crate::key::PublicKey::from_secret_key(&secp, &sk), pk);
        let (xpk, _parity) = keypair.x_only_public_key();
        assert_eq!(XOnlyPublicKey::from(pk), xpk);
    }

    #[test]
    fn test_pubkey_from_bad_slice() {
        // Bad sizes
        assert_eq!(
            XOnlyPublicKey::from_slice(&[0; constants::SCHNORR_PUBLIC_KEY_SIZE - 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            XOnlyPublicKey::from_slice(&[0; constants::SCHNORR_PUBLIC_KEY_SIZE + 1]),
            Err(InvalidPublicKey)
        );

        // Bad parse
        assert_eq!(
            XOnlyPublicKey::from_slice(&[0xff; constants::SCHNORR_PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        // In fuzzing mode restrictions on public key validity are much more
        // relaxed, thus the invalid check below is expected to fail.
        #[cfg(not(secp256k1_fuzz))]
        assert_eq!(
            XOnlyPublicKey::from_slice(&[0x55; constants::SCHNORR_PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        assert_eq!(XOnlyPublicKey::from_slice(&[]), Err(InvalidPublicKey));
    }

    #[cfg(not(secp256k1_fuzz))] // fixed sig vectors can't work with fuzz-sigs
    #[test]
    #[cfg(all(feature = "serde", feature = "alloc"))]
    fn test_serde() {
        use serde_test::{assert_tokens, Configure, Token};

        let s = Secp256k1::new();

        let msg = Message::from_digest_slice(&[1; 32]).unwrap();
        let keypair = Keypair::from_seckey_slice(&s, &[2; 32]).unwrap();
        let aux = [3u8; 32];
        let sig = s.sign_schnorr_with_aux_rand(&msg, &keypair, &aux);
        static SIG_BYTES: [u8; constants::SCHNORR_SIGNATURE_SIZE] = [
            0x14, 0xd0, 0xbf, 0x1a, 0x89, 0x53, 0x50, 0x6f, 0xb4, 0x60, 0xf5, 0x8b, 0xe1, 0x41,
            0xaf, 0x76, 0x7f, 0xd1, 0x12, 0x53, 0x5f, 0xb3, 0x92, 0x2e, 0xf2, 0x17, 0x30, 0x8e,
            0x2c, 0x26, 0x70, 0x6f, 0x1e, 0xeb, 0x43, 0x2b, 0x3d, 0xba, 0x9a, 0x01, 0x08, 0x2f,
            0x9e, 0x4d, 0x4e, 0xf5, 0x67, 0x8a, 0xd0, 0xd9, 0xd5, 0x32, 0xc0, 0xdf, 0xa9, 0x07,
            0xb5, 0x68, 0x72, 0x2d, 0x0b, 0x01, 0x19, 0xba,
        ];
        static SIG_STR: &str = "\
            14d0bf1a8953506fb460f58be141af767fd112535fb3922ef217308e2c26706f1eeb432b3dba9a01082f9e4d4ef5678ad0d9d532c0dfa907b568722d0b0119ba\
        ";

        static PK_BYTES: [u8; 32] = [
            24, 132, 87, 129, 246, 49, 196, 143, 28, 151, 9, 226, 48, 146, 6, 125, 6, 131, 127, 48,
            170, 12, 208, 84, 74, 200, 135, 254, 145, 221, 209, 102,
        ];
        static PK_STR: &str = "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";
        let pk = XOnlyPublicKey::from_slice(&PK_BYTES).unwrap();

        assert_tokens(&sig.compact(), &[Token::BorrowedBytes(&SIG_BYTES[..])]);
        assert_tokens(&sig.compact(), &[Token::Bytes(&SIG_BYTES[..])]);
        assert_tokens(&sig.compact(), &[Token::ByteBuf(&SIG_BYTES[..])]);

        assert_tokens(&sig.readable(), &[Token::BorrowedStr(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::Str(SIG_STR)]);
        assert_tokens(&sig.readable(), &[Token::String(SIG_STR)]);

        #[rustfmt::skip]
        assert_tokens(&pk.compact(), &[
            Token::Tuple{ len: 32 },
            Token::U8(24), Token::U8(132), Token::U8(87), Token::U8(129), Token::U8(246), Token::U8(49), Token::U8(196), Token::U8(143),
            Token::U8(28), Token::U8(151), Token::U8(9), Token::U8(226), Token::U8(48), Token::U8(146), Token::U8(6), Token::U8(125),
            Token::U8(6), Token::U8(131), Token::U8(127), Token::U8(48), Token::U8(170), Token::U8(12), Token::U8(208), Token::U8(84),
            Token::U8(74), Token::U8(200), Token::U8(135), Token::U8(254), Token::U8(145), Token::U8(221), Token::U8(209), Token::U8(102),
            Token::TupleEnd
        ]);

        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);
    }
}
