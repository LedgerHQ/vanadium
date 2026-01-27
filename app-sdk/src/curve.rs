use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Add, Deref, Mul},
};

use hex_literal::hex;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use common::ecall_constants::{CurveKind, EcdsaSignMode, HashId, SchnorrSignMode};

use crate::ecalls;

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
    fn curve_kind() -> CurveKind;
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

/// A representation of an elliptic curve point in uncompressed form.
///
/// # Point Encoding
///
/// Regular points use the SEC1 uncompressed format:
///
/// `prefix | X-coordinate | Y-coordinate`
///
/// Where `prefix` is `0x04` for valid curve points, and `X` and `Y` are `SCALAR_LENGTH`
/// byte arrays representing the coordinates.
///
/// # Point at Infinity (Identity Element)
///
/// The point at infinity is represented as 65 bytes of `0x00` (when `SCALAR_LENGTH = 32`).
/// This special encoding uses prefix `0x00` with zero coordinates:
///
/// `0x00 | 0x00...00 (32 bytes) | 0x00...00 (32 bytes)`
///
/// The point at infinity serves as the identity element for elliptic curve operations:
/// - **Addition**: `P + O = P` and `O + P = P` for any point `P`
/// - **Scalar multiplication**: `k * O = O` for any scalar `k`, and `0 * P = O` for any point `P`
///
/// # Type Parameters
/// * `C` - The curve type implementing `Curve<SCALAR_LENGTH>`.
/// * `SCALAR_LENGTH` - The byte length of the scalar and coordinate elements.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Point<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    curve_marker: PhantomData<C>,
    prefix: u8,
    pub x: [u8; SCALAR_LENGTH],
    pub y: [u8; SCALAR_LENGTH],
}

impl<C, const SCALAR_LENGTH: usize> Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    const ZERO: [u8; SCALAR_LENGTH] = [0u8; SCALAR_LENGTH];

    /// Checks if the point corresponds to the identity element (point at infinity)
    /// by verifying whether both x and y coordinates are zero.
    ///
    /// The point at infinity is represented with prefix `0x00` and zero coordinates.
    ///
    /// Guaranteed to run in constant time.
    ///
    /// # Returns
    /// `true` if this is the point at infinity, `false` otherwise.
    pub fn is_zero(&self) -> bool {
        (self.x.ct_eq(&Self::ZERO) & self.y.ct_eq(&Self::ZERO)).unwrap_u8() == 1
    }
}

impl<C, const SCALAR_LENGTH: usize> Default for Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    /// Creates the point at infinity (identity element).
    ///
    /// The point at infinity is represented with prefix `0x00` and zero coordinates,
    /// serving as the identity element for elliptic curve group operations.
    fn default() -> Self {
        Self {
            curve_marker: PhantomData,
            prefix: 0x00,
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
    /// This creates a regular curve point with prefix `0x04` (SEC1 uncompressed format).
    /// To create the point at infinity, use `Point::default()` instead.
    ///
    /// # Arguments
    ///
    /// * `x` - The x-coordinate of the point.
    /// * `y` - The y-coordinate of the point.
    ///
    /// # Returns
    ///
    /// A new `Point` instance with the specified coordinates.
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

impl<C, const SCALAR_LENGTH: usize> PartialEq for EcfpPrivateKey<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    fn eq(&self, other: &Self) -> bool {
        self.private_key
            .deref()
            .ct_eq(other.private_key.deref())
            .unwrap_u8()
            == 1
    }
}

impl<C, const SCALAR_LENGTH: usize> Eq for EcfpPrivateKey<C, SCALAR_LENGTH> where
    C: Curve<SCALAR_LENGTH>
{
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
    const SCALAR_ONE: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

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

    /// Creates a point from a byte array, validating that it lies on the curve.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte array of length `1 + 2 * 32` representing the point.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `Point` on success, or an error message if:
    /// - The prefix byte is not `0x04` (uncompressed point format) or `0x00` (point at infinity)
    /// - For `0x04` prefix, the point does not lie on the curve
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, &'static str> {
        if bytes[0] == 0x00 {
            return Ok(Point::default());
        }

        if bytes[0] != 0x04 {
            return Err("Invalid point prefix. Expected 0x04 or 0x00");
        }

        let point: Self = Self {
            curve_marker: PhantomData,
            prefix: bytes[0],
            x: bytes[1..33].try_into().unwrap(),
            y: bytes[33..65].try_into().unwrap(),
        };

        // Validate point is on curve by attempting scalar multiplication by 1.
        // If the point is not on the curve, the underlying ecall will fail.
        let mut result: Point<C, 32> = Point::default();
        if 1 != ecalls::ecfp_scalar_mult(
            C::curve_kind() as u32,
            result.as_mut_ptr(),
            point.as_ptr(),
            Self::SCALAR_ONE.as_ptr(),
            32,
        ) {
            return Err("Point is not on the curve");
        }

        Ok(point)
    }
}

impl<C, const SCALAR_LENGTH: usize> Add for &Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn add(self, other: Self) -> Self::Output {
        let mut result = Point::default();

        if 1 != ecalls::ecfp_add_point(
            C::curve_kind() as u32,
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
    C: Curve<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn mul(self, scalar: &[u8; SCALAR_LENGTH]) -> Self::Output {
        let mut result = Point::default();

        if 1 != ecalls::ecfp_scalar_mult(
            C::curve_kind() as u32,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secp256k1;

impl Curve<32> for Secp256k1 {
    fn derive_hd_node(path: &[u32]) -> Result<HDPrivNode<Self, 32>, &'static str> {
        let mut result = HDPrivNode::default();

        if 1 != ecalls::derive_hd_node(
            Self::curve_kind() as u32,
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
        ecalls::get_master_fingerprint(Self::curve_kind() as u32)
    }

    fn curve_kind() -> CurveKind {
        CurveKind::Secp256k1
    }
}

pub type Secp256k1Point = Point<Secp256k1, 32>;

impl Secp256k1 {
    pub const fn get_generator() -> Secp256k1Point {
        Point {
            curve_marker: PhantomData,
            prefix: 0x04,
            x: hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            y: hex!("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        }
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
        let sig_size = ecalls::ecdsa_sign(
            Secp256k1::curve_kind() as u32,
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
    pub fn schnorr_sign(
        &self,
        msg: &[u8],
        entropy: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>, &'static str> {
        let mut result = [0u8; 64];
        let sig_size = ecalls::schnorr_sign(
            Secp256k1::curve_kind() as u32,
            SchnorrSignMode::BIP340 as u32,
            HashId::Sha256 as u32,
            self.private_key.as_ptr(),
            msg.as_ptr(),
            msg.len(),
            result.as_mut_ptr(),
            entropy
                .map(|entropy| entropy as *const _)
                .unwrap_or(core::ptr::null()),
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
        if 1 != ecalls::ecdsa_verify(
            Secp256k1::curve_kind() as u32,
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
        if 1 != ecalls::schnorr_verify(
            Secp256k1::curve_kind() as u32,
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
    fn test_secp256k1_ecdsa_sign_verify_rfc_6979() {
        // Test vectors in format: (private_key_decimal, message, expected_signature)
        let test_vectors = [
            (
                hex!("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
                "Absence makes the heart grow fonder.",
                hex!("3045022100996D79FBA54B24E9394FC5FAB6BF94D173F3752645075DE6E32574FE08625F770220345E638B373DCB0CE0C09E5799695EF64FFC5E01DD8367B9A205CE25F28870F6").to_vec(),
            ),
            (
                hex!("dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986"),
                "Actions speak louder than words.",
                hex!("304502210088164430985A4437471417C2386FAA536E1FE8EC91BD0F1F642BC22A776891530220090DC83D6E3B54A1A54DC2E79C693144179A512D9C9E686A6C25E7641A2101A8").to_vec(),
            ),
            (
                hex!("084fed08b978af4d7d196a7446a86b58009e636b611db16211b65a9aadff29c5"),
                "All for one and one for all.",
                hex!("30450221009F1073C9C09B664498D4B216983330B01C29A0FB55DD61AA145B4EBD0579905502204592FB6626F672D4F3AD4BB2D0A1ED6C2A161CC35C6BB77E6F0FD3B63FEAB36F").to_vec(),
            ),
            (
                hex!("e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71"),
                "All's fair in love and war.",
                hex!("304502210080EABF24117B492635043886E7229B9705B970CBB6828C4E03A39DAE7AC34BDA022070E8A32CA1DF82ADD53FACBD58B4F2D3984D0A17B6B13C44460238D9FF74E41F").to_vec(),
            ),
            (
                hex!("e77b9a9ae9e30b0dbdb6f510a264ef9de781501d7b6b92ae89eb059c5ab743db"),
                "All work and no play makes Jack a dull boy.",
                hex!("3045022100A43FF5EDEA7EA0B9716D4359574E990A6859CDAEB9D7D6B4964AFD40BE11BD35022067F9D82E22FC447A122997335525F117F37B141C3EFA9F8C6D77B586753F962F").to_vec(),
            ),
            (
                hex!("67586e98fad27da0b9968bc039a1ef34c939b9b8e523a8bef89d478608c5ecf6"),
                "All's well that ends well.",
                hex!("3044022053CE16251F4FAE7EB87E2AB040A6F334E08687FB445566256CD217ECE389E0440220576506A168CBC9EE0DD485D6C418961E7A0861B0F05D22A93401812978D0B215").to_vec(),
            ),
            (
                hex!("ca358758f6d27e6cf45272937977a748fd88391db679ceda7dc7bf1f005ee879"),
                "An apple a day keeps the doctor away.",
                hex!("3045022100DF8744CC06A304B041E88149ACFD84A68D8F4A2A4047056644E1EC8357E11EBE02204BA2D5499A26D072C797A86C7851533F287CEB8B818CAE2C5D4483C37C62750C").to_vec(),
            ),
            (
                hex!("beead77994cf573341ec17b58bbf7eb34d2711c993c1d976b128b3188dc1829a"),
                "An apple never falls far from the tree.",
                hex!("3045022100878372D211ED0DBDE1273AE3DD85AEC577C08A06A55960F2E274F97CC9F2F38F02203F992CAA66F472A64F6CCDD8076C0A12202C674155A6A61B8CD23C1DED08AAB7").to_vec(),
            ),
            (
                hex!("2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9"),
                "An ounce of prevention is worth a pound of cure.",
                hex!("3045022100D5CB4E148C0A29CE37F1542BE416E8EF575DA522666B19B541960D726C99662B022045C951C1CA938C90DAD6C3EEDE7C5DF67FCF0D14F90FAF201E8D215F215C5C18").to_vec(),
            ),
            (
                hex!("01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"),
                "Appearances can be deceiving.",
                hex!("304402203E2F0118062306E2239C873828A7275DD35545A143797E224148C5BBBD59DD08022073A8C9E17BE75C66362913B5E05D81FD619B434EDDA766FAE6C352E86987809D").to_vec(),
            ),
        ];

        for (private_key, message, expected_sig) in test_vectors {
            let privkey = EcfpPrivateKey::<Secp256k1, 32>::new(private_key);
            let msg_hash = crate::hash::Sha256::hash(message.as_bytes());
            let pubkey = privkey.to_public_key();

            let signature = privkey.ecdsa_sign_hash(&msg_hash).unwrap();
            pubkey
                .ecdsa_verify_hash(&msg_hash, &signature)
                .expect("Signature should pass verification");

            assert_eq!(
                signature, expected_sig,
                "Signature does not match expected value"
            );
        }
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

        let signature = privkey.schnorr_sign(msg.as_bytes(), None).unwrap();

        let pubkey = privkey.to_public_key();
        pubkey.schnorr_verify(msg.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn test_point_from_bytes_invalid_point() {
        // A point with valid format (0x04 prefix) but coordinates not on the secp256k1 curve
        let invalid_point = hex!(
            "04"
            "0000000000000000000000000000000000000000000000000000000000000001"
            "0000000000000000000000000000000000000000000000000000000000000002"
        );

        let result = Secp256k1Point::from_bytes(&invalid_point);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Point is not on the curve");
    }

    #[test]
    fn test_point_from_bytes_invalid_prefix() {
        // A point with invalid prefix
        let invalid_prefix = hex!(
            "03"
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );

        let result = Secp256k1Point::from_bytes(&invalid_prefix);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid point prefix. Expected 0x04 or 0x00"
        );
    }

    #[test]
    fn test_point_from_bytes_valid_generator() {
        // The secp256k1 generator point - should succeed
        let generator_bytes = hex!(
            "04"
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );

        let result = Secp256k1Point::from_bytes(&generator_bytes);
        assert!(result.is_ok());
        let point = result.unwrap();
        assert_eq!(
            point.x,
            hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        assert_eq!(
            point.y,
            hex!("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
        );
    }

    #[test]
    fn test_point_from_bytes_point_at_infinity() {
        // Point at infinity: 0x00 prefix with zero coordinates
        let infinity_bytes = [0u8; 65];

        let result = Secp256k1Point::from_bytes(&infinity_bytes);
        assert!(result.is_ok());
        let point = result.unwrap();
        assert!(point.is_zero());
        assert_eq!(point.prefix, 0x00);
        assert_eq!(point.x, [0u8; 32]);
        assert_eq!(point.y, [0u8; 32]);
    }
}
