use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Add, Deref, Mul},
};

use hex_literal::hex;
use zeroize::Zeroizing;

use common::ecall_constants::{CurveKind, EcdsaSignMode, HashId, SchnorrSignMode};

use crate::ecalls::{Ecall, EcallsInterface};

/// A trait representing a cryptographic curve with hierarchical deterministic (HD) key derivation capabilities.
///
/// # Constants
/// - `SCALAR_LENGTH`: The length of the scalar in bytes.
///
/// # Required Methods
///
/// ## `derive_hd_node`
/// Derives an HD node (a pair of private and public keys) from a given path.
///
/// - `path`: A slice of `u32` values representing the derivation path.
/// - Returns: A `Result` containing a tuple with a 32-byte array (private key) and an array of `SCALAR_LENGTH` bytes (public key) on success, or a static string slice error message on failure.
///
/// ## `get_master_fingerprint`
/// Retrieves the fingerprint of the master key.
///
/// - Returns: A `u32` value representing the fingerprint of the master key.
pub trait Curve<const SCALAR_LENGTH: usize>: Sized {
    fn derive_hd_node(path: &[u32]) -> Result<HDPrivNode<Self, SCALAR_LENGTH>, &'static str>;
    fn get_master_fingerprint() -> u32;
}

/// A struct representing a Hierarchical Deterministic (HD) node composed of a private key, and a 32-byte chaincode.
///
/// # Type Parameters
///
/// * `SCALAR_LENGTH` - The length of the private key scalar.
///
/// # Fields
///
/// * `chaincode` - A 32-byte array representing the chain code.
/// * `privkey` - An array of bytes representing the private key, with a length defined by `SCALAR_LENGTH`.
pub struct HDPrivNode<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    curve_marker: PhantomData<C>,
    pub chaincode: [u8; 32],
    pub privkey: Zeroizing<[u8; SCALAR_LENGTH]>,
}

impl<C, const SCALAR_LENGTH: usize> Default for HDPrivNode<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn default() -> Self {
        Self {
            curve_marker: PhantomData,
            chaincode: [0u8; 32],
            privkey: Zeroizing::new([0u8; SCALAR_LENGTH]),
        }
    }
}

impl<C, const SCALAR_LENGTH: usize> core::fmt::Debug for HDPrivNode<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "HDPrivNode {{ chaincode: {:?}, privkey: [REDACTED] }}",
            self.chaincode
        )
    }
}

// A trait to simplify the implementation of `Curve` for different curves.
trait HasCurveKind<const SCALAR_LENGTH: usize> {
    // Returns the value that represents this curve in ECALLs.
    fn get_curve_kind() -> CurveKind;
}

impl<C, const SCALAR_LENGTH: usize> Curve<SCALAR_LENGTH> for C
where
    C: HasCurveKind<SCALAR_LENGTH>,
{
    fn derive_hd_node(path: &[u32]) -> Result<HDPrivNode<C, SCALAR_LENGTH>, &'static str> {
        let curve_kind = C::get_curve_kind();
        let mut result = HDPrivNode::default();

        if 1 != Ecall::derive_hd_node(
            curve_kind as u32,
            path.as_ptr(),
            path.len(),
            result.privkey.as_mut_ptr(),
            result.chaincode.as_mut_ptr(),
        ) {
            return Err("Failed to derive HD node");
        }

        Ok(result)
    }

    fn get_master_fingerprint() -> u32 {
        let curve_kind = C::get_curve_kind();
        Ecall::get_master_fingerprint(curve_kind as u32)
    }
}

/// A representation of an elliptic curve point in uncompressed form.
///
/// The format is:
///
/// `prefix | X-coordinate | Y-coordinate`
///
/// Where `prefix` is always `0x04` for uncompressed points, and `X` and `Y` are `SCALAR_LENGTH`
/// byte arrays representing the coordinates.
///
/// # Type Parameters
/// * `C` - The curve type implementing `Curve<SCALAR_LENGTH>`.
/// * `SCALAR_LENGTH` - The byte length of the scalar and coordinate elements.
#[repr(C)]
pub struct Point<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    curve_marker: PhantomData<C>,
    prefix: u8,
    x: [u8; SCALAR_LENGTH],
    y: [u8; SCALAR_LENGTH],
}

impl<C, const SCALAR_LENGTH: usize> Default for Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn default() -> Self {
        Self {
            curve_marker: PhantomData,
            prefix: 0x04,
            x: [0u8; SCALAR_LENGTH],
            y: [0u8; SCALAR_LENGTH],
        }
    }
}

impl<C, const SCALAR_LENGTH: usize> Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    /// Returns a mutable pointer to the beginning of the point's data.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        &mut self.prefix as *mut u8
    }
    /// Returns a pointer to the beginning of the point's data.
    pub fn as_ptr(&self) -> *const u8 {
        &self.prefix as *const u8
    }

    /// Creates a new Point with the given coordinates.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the point.
    /// * `y` - The y-coordinate of the point.
    ///
    /// # Returns
    ///
    /// A new `Point` instance.
    pub fn new(x: [u8; SCALAR_LENGTH], y: [u8; SCALAR_LENGTH]) -> Self {
        Self {
            curve_marker: PhantomData,
            prefix: 0x04,
            x,
            y,
        }
    }
}

pub struct EcfpPublicKey<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    public_key: Point<C, SCALAR_LENGTH>,
}

impl<C, const SCALAR_LENGTH: usize> EcfpPublicKey<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    /// Creates a new EcfpPublicKey from the given coordinates.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the public key.
    /// * `y` - The y-coordinate of the public key.
    ///
    /// # Returns
    ///
    /// A new `EcfpPublicKey` instance.
    pub fn new(x: [u8; SCALAR_LENGTH], y: [u8; SCALAR_LENGTH]) -> Self {
        Self {
            public_key: Point::new(x, y),
        }
    }
}

impl<C, const SCALAR_LENGTH: usize> From<Point<C, SCALAR_LENGTH>>
    for EcfpPublicKey<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn from(point: Point<C, SCALAR_LENGTH>) -> Self {
        Self { public_key: point }
    }
}

impl<C, const SCALAR_LENGTH: usize> From<EcfpPublicKey<C, SCALAR_LENGTH>>
    for Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn from(public_key: EcfpPublicKey<C, SCALAR_LENGTH>) -> Self {
        public_key.public_key
    }
}

impl<C, const SCALAR_LENGTH: usize> AsRef<Point<C, SCALAR_LENGTH>>
    for EcfpPublicKey<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn as_ref(&self) -> &Point<C, SCALAR_LENGTH> {
        &self.public_key
    }
}

pub struct EcfpPrivateKey<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    curve_marker: PhantomData<C>,
    private_key: Zeroizing<[u8; SCALAR_LENGTH]>,
}

impl<C, const SCALAR_LENGTH: usize> EcfpPrivateKey<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    pub fn new(private_key: [u8; SCALAR_LENGTH]) -> Self {
        Self {
            curve_marker: PhantomData,
            private_key: Zeroizing::new(private_key),
        }
    }
}

pub trait ToPublicKey<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn to_public_key(&self) -> EcfpPublicKey<C, SCALAR_LENGTH>;
}

// We could implement this for any SCALAR_LENGTH, but this currently requires
// the #![feature(generic_const_exprs)], as the byte size is 1 + 2*SCALAR_LENGTH.
impl<C: Curve<32>> Point<C, 32> {
    /// Converts the point to a byte array.
    ///
    /// # Returns
    ///
    /// A byte array of length `1 + 2 * 32` representing the point.
    pub fn to_bytes(&self) -> &[u8; 65] {
        // SAFETY: `Point` is `#[repr(C)]` with a known layout:
        // prefix (1 byte), x (32 bytes), y (32 bytes) = 65 bytes total.
        // Therefore, we can safely reinterpret the memory as a [u8; 65].
        unsafe { &*(self as *const Self as *const [u8; 65]) }
    }

    /// Creates a point from a byte array.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte array of length `1 + 2 * 32` representing the point.
    ///
    /// # Returns
    ///
    /// A new instance of `Self`.
    pub fn from_bytes(bytes: &[u8; 65]) -> &Self {
        if bytes[0] != 0x04 {
            panic!("Invalid point prefix. Expected 0x04");
        }
        // SAFETY: The input slice has exactly 65 bytes and must match
        // the memory layout of `Point`. The prefix is validated.
        unsafe { &*(bytes as *const [u8; 65] as *const Self) }
    }
}

impl<C, const SCALAR_LENGTH: usize> Add for &Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH> + HasCurveKind<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn add(self, other: Self) -> Self::Output {
        let mut result = Point::default();

        if 1 != Ecall::ecfp_add_point(
            C::get_curve_kind() as u32,
            result.as_mut_ptr(),
            self.as_ptr(),
            other.as_ptr(),
        ) {
            panic!("Failed to add points");
        }

        result
    }
}

impl<C, const SCALAR_LENGTH: usize> Mul<&[u8; SCALAR_LENGTH]> for &Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH> + HasCurveKind<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn mul(self, scalar: &[u8; SCALAR_LENGTH]) -> Self::Output {
        let mut result = Point::default();

        if 1 != Ecall::ecfp_scalar_mult(
            C::get_curve_kind() as u32,
            result.as_mut_ptr(),
            self.as_ptr(),
            scalar.as_ptr(),
            SCALAR_LENGTH,
        ) {
            panic!("Failed to multiply point by scalar");
        }

        result
    }
}

pub struct Secp256k1;

impl HasCurveKind<32> for Secp256k1 {
    fn get_curve_kind() -> CurveKind {
        CurveKind::Secp256k1
    }
}

pub type Secp256k1Point = Point<Secp256k1, 32>;

impl Secp256k1 {
    pub fn get_generator() -> Secp256k1Point {
        Point::new(
            hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            hex!("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        )
    }
}

impl EcfpPrivateKey<Secp256k1, 32> {
    /// Signs a 32-byte message hash using the ECDSA algorithm, with deterministic signing
    /// per RFC 6979.
    ///
    /// # Arguments
    ///
    /// * `msg_hash` - A reference to a 32-byte array containing the message hash to be signed.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector containing the ECDSA signature if the signing is successful.
    /// The signature is DER-encoded as per the bitcoin standard, and up to 71 bytes long.
    /// * `Err(&'static str)` - An error message if the signing fails.
    pub fn ecdsa_sign_hash(&self, msg_hash: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let mut result = [0u8; 71];
        let sig_size = Ecall::ecdsa_sign(
            Secp256k1::get_curve_kind() as u32,
            EcdsaSignMode::RFC6979 as u32,
            HashId::Sha256 as u32,
            self.private_key.as_ptr(),
            msg_hash.as_ptr(),
            result.as_mut_ptr(),
        );
        if sig_size == 0 {
            return Err("Failed to sign hash with ecdsa");
        }
        Ok(result[0..sig_size].to_vec())
    }

    /// Signs a message using the Schnorr signature algorithm, as defined in BIP-0340.
    ///
    /// # Arguments
    ///
    /// * `msg` - A reference to a byte slice containing the message to be signed.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector containing the Schnorr signature if the signing is successful.
    /// The length of the signature is always 64 bytes.
    ///
    /// * `Err(&'static str)` - An error message if the signing fails.
    pub fn schnorr_sign(&self, msg: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut result = [0u8; 64];
        let sig_size = Ecall::schnorr_sign(
            Secp256k1::get_curve_kind() as u32,
            SchnorrSignMode::BIP340 as u32,
            HashId::Sha256 as u32,
            self.private_key.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            result.as_mut_ptr(),
        );
        if sig_size != 64 {
            panic!("Schnorr signatures per BIP-340 must be exactly 64 bytes");
        }
        Ok(result.to_vec())
    }
}

impl EcfpPublicKey<Secp256k1, 32> {
    pub fn ecdsa_verify_hash(
        &self,
        msg_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        if 1 != Ecall::ecdsa_verify(
            Secp256k1::get_curve_kind() as u32,
            self.public_key.as_ptr(),
            msg_hash.as_ptr(),
            signature.as_ptr(),
            signature.len(),
        ) {
            return Err("Failed to verify hash with ecdsa");
        }
        Ok(())
    }

    pub fn schnorr_verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        if 1 != Ecall::schnorr_verify(
            Secp256k1::get_curve_kind() as u32,
            SchnorrSignMode::BIP340 as u32,
            HashId::Sha256 as u32,
            self.public_key.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            signature.as_ptr(),
            signature.len(),
        ) {
            return Err("Failed to verify schnorr signature");
        }
        Ok(())
    }
}

// TODO: can we generalize this to all curves?
impl ToPublicKey<Secp256k1, 32> for EcfpPrivateKey<Secp256k1, 32> {
    fn to_public_key(&self) -> EcfpPublicKey<Secp256k1, 32> {
        (&Secp256k1::get_generator() * self.private_key.deref()).into()
    }
}

#[cfg(test)]
mod tests {
    use crate::hash::Hasher;

    use super::*;

    #[test]
    fn test_secp256k1_get_master_fingerprint() {
        assert_eq!(Secp256k1::get_master_fingerprint(), 0xf5acc2fdu32);
    }

    #[test]
    fn test_derive_hd_node_secp256k1() {
        let node = Secp256k1::derive_hd_node(&[]).unwrap();
        assert_eq!(
            node.chaincode,
            hex!("eb473a0fa0af5031f14db9fe7c37bb8416a4ff01bb69dae9966dc83b5e5bf921")
        );
        assert_eq!(
            node.privkey[..],
            hex!("34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938")
        );

        let path = [0x8000002c, 0x80000000, 0x80000001, 0, 3];
        let node = Secp256k1::derive_hd_node(&path).unwrap();
        assert_eq!(
            node.chaincode,
            hex!("6da5f32f47232b3b9b2d6b59b802e2b313afa7cbda242f73da607139d8e04989")
        );
        assert_eq!(
            node.privkey[..],
            hex!("239841e64103fd024b01283e752a213fee1a8969f6825204ee3617a45c5e4a91")
        );
    }

    #[test]
    fn test_secp256k1_point_addition() {
        let point1 = Secp256k1Point::new(
            hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
        );
        let point2 = Secp256k1Point::new(
            hex!("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            hex!("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
        );

        let result = &point1 + &point2;

        assert_eq!(
            result.x,
            hex!("2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4")
        );
        assert_eq!(
            result.y,
            hex!("d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6")
        );
    }

    #[test]
    fn test_secp256k1_point_scalarmul() {
        let point1 = Secp256k1Point::new(
            hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            hex!("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        );
        let scalar = hex!("22445566778899aabbccddeeff0011223344556677889900aabbccddeeff0011");

        let result = &point1 * &scalar;

        assert_eq!(
            result.x,
            hex!("2748bce8ffc3f815e69e594ae974be5e9a3be69a233d5557ea9c92b71d69367b")
        );
        assert_eq!(
            result.y,
            hex!("747206115143153c85f3e8bb94d392bd955d36f1f0204921e6dd7684e81bdaab")
        );
    }

    #[test]
    fn test_secp256k1_ecdsa_sign_verify() {
        let privkey = EcfpPrivateKey::<Secp256k1, 32> {
            curve_marker: PhantomData,
            private_key: Zeroizing::new(hex!(
                "4242424242424242424242424242424242424242424242424242424242424242"
            )),
        };
        let msg = "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";
        let msg_hash = crate::hash::Sha256::hash(msg.as_bytes());

        let signature = privkey.ecdsa_sign_hash(&msg_hash).unwrap();

        let pubkey = privkey.to_public_key();
        pubkey.ecdsa_verify_hash(&msg_hash, &signature).unwrap();
    }

    #[test]
    fn test_secp256k1_schnorr_sign_verify() {
        let privkey = EcfpPrivateKey::<Secp256k1, 32> {
            curve_marker: PhantomData,
            private_key: Zeroizing::new(hex!(
                "4242424242424242424242424242424242424242424242424242424242424242"
            )),
        };
        let msg = "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";

        let signature = privkey.schnorr_sign(msg.as_bytes()).unwrap();

        let pubkey = privkey.to_public_key();
        pubkey.schnorr_verify(msg.as_bytes(), &signature).unwrap();
    }
}
