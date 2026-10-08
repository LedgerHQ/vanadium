use alloc::vec::Vec;
use core::{
    marker::PhantomData,
    ops::{Add, Deref, Mul, Neg, Sub},
};

use hex_literal::hex;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use common::ecall_constants::{CurveKind, EcdsaSignMode, HashId, SchnorrSignMode};

use crate::ecalls;

/// The maximum number of steps of a path for [`Curve::derive_hd_node`].
pub const MAX_BIP32_PATH_LEN: usize = common::ecall_validation::MAX_BIP32_PATH_LEN;

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
    /// Derives the node at `path` from the device's seed. Fails if the path has more than
    /// [`MAX_BIP32_PATH_LEN`] steps.
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
/// # Invariant
///
/// A `Point` is always either the point at infinity or a point of the curve: it can only be built
/// by the validating constructors ([`Point::from_bytes`], [`Point::from_coordinates`],
/// [`Point::lift_x`], [`Point::from_compressed`]), as the generator or infinity, or as the result
/// of the group operations. So the operations never fail.
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
    x: [u8; SCALAR_LENGTH],
    y: [u8; SCALAR_LENGTH],
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

    /// The x-coordinate; all zeros for the point at infinity.
    pub fn x(&self) -> &[u8; SCALAR_LENGTH] {
        &self.x
    }

    /// The y-coordinate; all zeros for the point at infinity.
    pub fn y(&self) -> &[u8; SCALAR_LENGTH] {
        &self.y
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
    /// Returns a mutable pointer to the beginning of the point's data. Only the ECALLs may write
    /// through it, since they only ever produce valid points.
    fn as_mut_ptr(&mut self) -> *mut u8 {
        &mut self.prefix as *mut u8
    }
    /// Returns a pointer to the beginning of the point's data.
    pub fn as_ptr(&self) -> *const u8 {
        &self.prefix as *const u8
    }
}

pub struct EcfpPublicKey<C, const SCALAR_LENGTH: usize>
where
    C: Curve<SCALAR_LENGTH>,
{
    public_key: Point<C, SCALAR_LENGTH>,
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

    /// Converts this private key into an `HDPrivNode` by pairing it with the given chaincode.
    pub fn into_hd_node(self, chaincode: &[u8; 32]) -> HDPrivNode<C, SCALAR_LENGTH> {
        let mut node = HDPrivNode::default();
        node.chaincode = *chaincode;
        node.privkey = self.private_key;
        node
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

    /// Creates a point from its 65-byte encoding: either 65 zero bytes for the point at infinity,
    /// or the uncompressed SEC1 encoding `0x04 || x || y` of a point of the curve.
    ///
    /// Returns an error for any other input.
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self, &'static str> {
        // The ECALLs reject any invalid encoding, so adding the point at infinity validates the
        // input, and returns it unchanged.
        let mut result = Self::default();
        let infinity = Self::default();
        // SAFETY: all buffers are 65 bytes; the ECALL writes `result` only if `bytes` is valid.
        if 1 != unsafe {
            ecalls::ecfp_add_point(
                C::curve_kind() as u32,
                result.as_mut_ptr(),
                bytes.as_ptr(),
                infinity.as_ptr(),
            )
        } {
            return Err("Invalid point");
        }
        Ok(result)
    }

    /// Creates the point with the given coordinates, or returns an error if it is not a point of
    /// the curve.
    pub fn from_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Result<Self, &'static str> {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        bytes[1..33].copy_from_slice(x);
        bytes[33..65].copy_from_slice(y);
        Self::from_bytes(&bytes)
    }
}

impl<C, const SCALAR_LENGTH: usize> Add for &Point<C, SCALAR_LENGTH>
where
    C: Curve<SCALAR_LENGTH>,
{
    type Output = Point<C, SCALAR_LENGTH>;

    fn add(self, other: Self) -> Self::Output {
        let mut result = Point::default();
        // SAFETY: result, self, and other are 65-byte point buffers; result does not alias the
        // inputs. Both inputs are valid points, so the ECALL cannot fail.
        let status = unsafe {
            ecalls::ecfp_add_point(
                C::curve_kind() as u32,
                result.as_mut_ptr(),
                self.as_ptr(),
                other.as_ptr(),
            )
        };
        if status != 1 {
            panic!("adding valid points cannot fail");
        }
        result
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secp256k1;

impl Curve<32> for Secp256k1 {
    fn derive_hd_node(path: &[u32]) -> Result<HDPrivNode<Self, 32>, &'static str> {
        let mut result = HDPrivNode::default();
        // SAFETY: path is a valid slice; privkey and chaincode are valid 32-byte output arrays.
        if 1 != unsafe {
            ecalls::derive_hd_node(
                Self::curve_kind() as u32,
                path.as_ptr(),
                path.len(),
                result.privkey.as_mut_ptr(),
                result.chaincode.as_mut_ptr(),
            )
        } {
            return Err("Failed to derive HD node");
        }

        Ok(result)
    }

    fn get_master_fingerprint() -> u32 {
        let mut fingerprint = 0u32;
        // SAFETY: fingerprint is a valid, writable u32.
        if 1 != unsafe {
            ecalls::get_master_fingerprint(Self::curve_kind() as u32, &mut fingerprint)
        } {
            panic!("Failed to get the master fingerprint");
        }
        fingerprint
    }

    fn curve_kind() -> CurveKind {
        CurveKind::Secp256k1
    }
}

pub type Secp256k1Point = Point<Secp256k1, 32>;

impl Secp256k1 {
    // secp256k1 field prime p
    const P: [u8; 32] = hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    // (p + 1) / 4  (used for modular square root since p ≡ 3 mod 4)
    const SQUAREROOT_EXP: [u8; 32] =
        hex!("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C");
    const SEVEN: [u8; 32] =
        hex!("0000000000000000000000000000000000000000000000000000000000000007");

    /// `p - y`, for `0 < y < p`.
    fn negate_field_element(y: &[u8; 32]) -> [u8; 32] {
        let mut res = [0u8; 32];
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let diff = Self::P[i] as i16 - y[i] as i16 - borrow;
            if diff < 0 {
                res[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                res[i] = diff as u8;
                borrow = 0;
            }
        }
        res
    }

    pub const fn get_generator() -> Secp256k1Point {
        Point {
            curve_marker: PhantomData,
            prefix: 0x04,
            x: hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            y: hex!("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        }
    }
}

/// An integer modulo the order n of the secp256k1 group, always smaller than n.
///
/// Scalars are often secret (private keys, nonces, tweaks), so they are zeroized when dropped
/// and compared in constant time. The arithmetic uses the big number ECALLs.
#[derive(Clone)]
pub struct Secp256k1Scalar([u8; 32]);

impl Secp256k1Scalar {
    /// The order n of the secp256k1 group.
    pub const ORDER: [u8; 32] = common::ecall_validation::SECP256K1_N;

    /// The scalar 0.
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// The scalar 1.
    pub fn one() -> Self {
        Self::from_u32(1)
    }

    /// The scalar `value`.
    pub fn from_u32(value: u32) -> Self {
        let mut res = Self::zero();
        res.0[28..].copy_from_slice(&value.to_be_bytes());
        res
    }

    /// The scalar encoded by the big-endian `bytes`, or `None` if they encode a value that is not
    /// smaller than n.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Option<Self> {
        common::ecall_validation::is_reduced(bytes, &Self::ORDER)
            .then(|| Self(*bytes))
    }

    /// The big-endian `bytes`, reduced modulo n.
    pub fn from_be_bytes_reduced(bytes: &[u8; 32]) -> Self {
        Self(common::ecall_validation::reduce_secp256k1_scalar(bytes))
    }

    /// The big-endian encoding of the scalar.
    pub fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether the scalar is 0. Runs in constant time.
    pub fn is_zero(&self) -> bool {
        self.0[..].ct_eq(&[0u8; 32][..]).unwrap_u8() == 1
    }

    /// The multiplicative inverse, or `None` for 0.
    pub fn inv(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let mut res = Self::zero();
        // SAFETY: all buffers are 32 bytes; 0 < self < n, and n is an odd prime.
        let status = unsafe {
            ecalls::bn_modinv_prime(res.0.as_mut_ptr(), self.0.as_ptr(), Self::ORDER.as_ptr(), 32)
        };
        if status != 1 {
            panic!("inversion of a canonical non-zero scalar cannot fail");
        }
        Some(res)
    }

    /// Applies one of the modular ECALLs `bn_addm`, `bn_subm` and `bn_multm` to two scalars.
    ///
    /// Not inlined: a scalar expression would otherwise repeat the whole ECALL sequence at every
    /// operator.
    #[inline(never)]
    fn binop(
        f: unsafe fn(*mut u8, *const u8, *const u8, *const u8, usize) -> u32,
        a: &Self,
        b: &Self,
    ) -> Self {
        let mut res = Self::zero();
        // SAFETY: all buffers are 32 bytes; both operands are smaller than n, which is odd.
        let status = unsafe {
            f(
                res.0.as_mut_ptr(),
                a.0.as_ptr(),
                b.0.as_ptr(),
                Self::ORDER.as_ptr(),
                32,
            )
        };
        if status != 1 {
            panic!("arithmetic on canonical scalars cannot fail");
        }
        res
    }
}

impl Add for &Secp256k1Scalar {
    type Output = Secp256k1Scalar;

    fn add(self, other: Self) -> Secp256k1Scalar {
        Secp256k1Scalar::binop(ecalls::bn_addm, self, other)
    }
}

impl Sub for &Secp256k1Scalar {
    type Output = Secp256k1Scalar;

    fn sub(self, other: Self) -> Secp256k1Scalar {
        Secp256k1Scalar::binop(ecalls::bn_subm, self, other)
    }
}

impl Mul for &Secp256k1Scalar {
    type Output = Secp256k1Scalar;

    fn mul(self, other: Self) -> Secp256k1Scalar {
        Secp256k1Scalar::binop(ecalls::bn_multm, self, other)
    }
}

impl Neg for &Secp256k1Scalar {
    type Output = Secp256k1Scalar;

    fn neg(self) -> Secp256k1Scalar {
        &Secp256k1Scalar::zero() - self
    }
}

impl Drop for Secp256k1Scalar {
    // Not inlined: scalar expressions create many temporaries, and each would otherwise repeat
    // the zeroization code.
    #[inline(never)]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ConstantTimeEq for Secp256k1Scalar {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0[..].ct_eq(&other.0[..])
    }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl Eq for Secp256k1Scalar {}

impl core::fmt::Debug for Secp256k1Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secp256k1Scalar([REDACTED])")
    }
}

impl Secp256k1Point {
    /// The point with x-coordinate `x` and an even y-coordinate (`lift_x` in BIP-340), or an error
    /// if `x` is not the x-coordinate of a point of the curve.
    pub fn lift_x(x: &[u8; 32]) -> Result<Self, &'static str> {
        let mut x2 = [0u8; 32];
        let mut x3 = [0u8; 32];
        let mut rhs = [0u8; 32]; // x^3 + 7 mod p
        let mut y = [0u8; 32];
        let mut y2 = [0u8; 32];
        let p = Secp256k1::P.as_ptr();

        // SAFETY: all buffers are 32 bytes. The ECALLs return 0 if x is not smaller than p.
        let ok = unsafe {
            ecalls::bn_multm(x2.as_mut_ptr(), x.as_ptr(), x.as_ptr(), p, 32) == 1
                && ecalls::bn_multm(x3.as_mut_ptr(), x2.as_ptr(), x.as_ptr(), p, 32) == 1
                && ecalls::bn_addm(rhs.as_mut_ptr(), x3.as_ptr(), Secp256k1::SEVEN.as_ptr(), p, 32)
                    == 1
                // since p = 3 mod 4, rhs^((p + 1) / 4) is a square root of rhs, if it has one
                && ecalls::bn_powm(
                    y.as_mut_ptr(),
                    rhs.as_ptr(),
                    Secp256k1::SQUAREROOT_EXP.as_ptr(),
                    32,
                    p,
                    32,
                ) == 1
                && ecalls::bn_multm(y2.as_mut_ptr(), y.as_ptr(), y.as_ptr(), p, 32) == 1
        };
        if !ok || y2 != rhs {
            return Err("Not the x-coordinate of a point of the curve");
        }
        if y[31] & 1 == 1 {
            y = Secp256k1::negate_field_element(&y);
        }

        Ok(Self {
            curve_marker: PhantomData,
            prefix: 0x04,
            x: *x,
            y,
        })
    }

    /// Decodes a 33-byte compressed SEC1 point, or returns an error if it is not one.
    pub fn from_compressed(compressed: &[u8; 33]) -> Result<Self, &'static str> {
        if compressed[0] != 0x02 && compressed[0] != 0x03 {
            return Err("Invalid compressed key prefix");
        }
        let point = Self::lift_x(compressed[1..33].try_into().unwrap())?;
        Ok(if compressed[0] == 0x03 {
            -&point
        } else {
            point
        })
    }

    /// The 33-byte compressed SEC1 encoding, or `None` for the point at infinity.
    pub fn to_compressed(&self) -> Option<[u8; 33]> {
        if self.is_zero() {
            return None;
        }
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02 + (self.y[31] & 1);
        compressed[1..33].copy_from_slice(&self.x);
        Some(compressed)
    }

    /// Whether the y-coordinate is even; it is, for the point at infinity.
    pub fn has_even_y(&self) -> bool {
        self.y[31] & 1 == 0
    }
}

impl Mul<&Secp256k1Scalar> for &Secp256k1Point {
    type Output = Secp256k1Point;

    fn mul(self, scalar: &Secp256k1Scalar) -> Secp256k1Point {
        let mut result = Point::default();
        // SAFETY: result is a 65-byte output buffer; self is a valid point, and the scalar is
        // 32 bytes and smaller than n, so the ECALL cannot fail.
        let status = unsafe {
            ecalls::ecfp_scalar_mult(
                Secp256k1::curve_kind() as u32,
                result.as_mut_ptr(),
                self.as_ptr(),
                scalar.as_be_bytes().as_ptr(),
                32,
            )
        };
        if status != 1 {
            panic!("multiplying a valid point by a canonical scalar cannot fail");
        }
        result
    }
}

impl Neg for &Secp256k1Point {
    type Output = Secp256k1Point;

    /// The opposite point, (x, p - y); the point at infinity is its own opposite.
    fn neg(self) -> Secp256k1Point {
        if self.is_zero() {
            return *self;
        }
        Point {
            curve_marker: PhantomData,
            prefix: 0x04,
            x: self.x,
            y: Secp256k1::negate_field_element(&self.y),
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
    /// The signature is DER-encoded as per the bitcoin standard, and up to 72 bytes long.
    /// * `Err(&'static str)` - An error message if the signing fails.
    pub fn ecdsa_sign_hash(&self, msg_hash: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
        let mut result = [0u8; 72];
        // SAFETY: privkey is 32 bytes; msg_hash is 32 bytes; result is a 72-byte output buffer.
        let sig_size = unsafe {
            ecalls::ecdsa_sign(
                Secp256k1::curve_kind() as u32,
                EcdsaSignMode::RFC6979 as u32,
                HashId::Sha256 as u32,
                self.private_key.as_ptr(),
                msg_hash.as_ptr(),
                result.as_mut_ptr(),
            )
        };
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
    /// * `entropy` - An optional reference to a 32-byte array providing additional entropy for signing, or null.
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
        // SAFETY: privkey is 32 bytes; msg is a valid slice; result is a 64-byte output buffer;
        // entropy is either null or a valid pointer to 32 bytes.
        let sig_size = unsafe {
            ecalls::schnorr_sign(
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
            )
        };
        if sig_size != 64 {
            return Err("Failed to produce a schnorr signature");
        }
        Ok(result.to_vec())
    }
}

impl EcfpPublicKey<Secp256k1, 32> {
    /// Creates an `EcfpPublicKey` from a 33-byte compressed SEC1 public key.
    ///
    /// Returns `Err` if `compressed` does not represent a valid secp256k1 point.
    pub fn from_compressed(compressed: &[u8; 33]) -> Result<Self, &'static str> {
        Secp256k1Point::from_compressed(compressed).map(Self::from)
    }

    /// Encodes this public key as a 33-byte compressed SEC1 point.
    ///
    /// Panics if the public key is the point at infinity.
    pub fn to_compressed(&self) -> [u8; 33] {
        self.public_key
            .to_compressed()
            .expect("a public key is not the point at infinity")
    }

    pub fn ecdsa_verify_hash(
        &self,
        msg_hash: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), &'static str> {
        // SAFETY: pubkey is a 65-byte uncompressed SEC1 key; msg_hash is 32 bytes;
        // signature is a valid slice.
        if 1 != unsafe {
            ecalls::ecdsa_verify(
                Secp256k1::curve_kind() as u32,
                self.public_key.as_ptr(),
                msg_hash.as_ptr(),
                signature.as_ptr(),
                signature.len(),
            )
        } {
            return Err("Failed to verify hash with ecdsa");
        }
        Ok(())
    }

    pub fn schnorr_verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        // SAFETY: the x-coordinate is the 32-byte x-only BIP-340 key; msg and signature are valid
        // slices.
        if 1 != unsafe {
            ecalls::schnorr_verify(
                Secp256k1::curve_kind() as u32,
                SchnorrSignMode::BIP340 as u32,
                HashId::Sha256 as u32,
                self.public_key.x().as_ptr(),
                msg.as_ptr(),
                msg.len(),
                signature.as_ptr(),
                signature.len(),
            )
        } {
            return Err("Failed to verify schnorr signature");
        }
        Ok(())
    }

    /// BIP-32 fingerprint: first 4 bytes of RIPEMD160(SHA256(compressed_pubkey)).
    pub fn fingerprint(&self) -> u32 {
        use crate::hash::{Hasher, Ripemd160, Sha256};
        let pk_bytes = self.public_key.to_bytes();
        let mut sha256_hasher = Sha256::new();
        sha256_hasher.update(&[pk_bytes[64] % 2 + 0x02]);
        sha256_hasher.update(&pk_bytes[1..33]);
        let mut sha256 = [0u8; 32];
        sha256_hasher.digest(&mut sha256);
        let hash = Ripemd160::hash(&sha256);
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    }
}

// TODO: can we generalize this to all curves?
impl ToPublicKey<Secp256k1, 32> for EcfpPrivateKey<Secp256k1, 32> {
    /// Panics if the private key is not smaller than n.
    fn to_public_key(&self) -> EcfpPublicKey<Secp256k1, 32> {
        let d = Secp256k1Scalar::from_be_bytes(&self.private_key).expect("invalid private key");
        (&Secp256k1::get_generator() * &d).into()
    }
}

/// Computes HMAC-SHA512(key, data1 || data2).
///
/// Key must be at most 128 bytes (the SHA-512 block size); if shorter it is
/// zero-padded to the block size.
fn hmac_sha512(key: &[u8; 32], data1: &[u8], data2: &[u8]) -> [u8; 64] {
    use crate::hash::{Hasher, Sha512};

    // SHA-512 block size is 128 bytes. Key (32 bytes) < block size, so pad with zeros.
    let mut ipad_key = [0x36u8; 128];
    let mut opad_key = [0x5cu8; 128];
    for i in 0..32 {
        ipad_key[i] ^= key[i];
        opad_key[i] ^= key[i];
    }

    // Inner hash: SHA-512(ipad_key || data1 || data2)
    let mut inner = Sha512::new();
    inner.update(&ipad_key);
    inner.update(data1);
    inner.update(data2);
    let mut inner_digest = [0u8; 64];
    inner.digest(&mut inner_digest);

    // Outer hash: SHA-512(opad_key || inner_digest)
    let mut outer = Sha512::new();
    outer.update(&opad_key);
    outer.update(&inner_digest);
    let mut result = [0u8; 64];
    outer.digest(&mut result);
    result
}

impl HDPrivNode<Secp256k1, 32> {
    /// Performs BIP32 child key derivation (CKDpriv).
    ///
    /// `child` is a raw BIP32 child index. Values `>= 0x80000000` are hardened.
    ///
    /// Algorithm (per BIP32):
    /// 1. Build the HMAC data:
    ///    - non-hardened: `compressed_pubkey || child_be`
    ///    - hardened:     `0x00 || privkey || child_be`
    /// 2. HMAC-SHA512(key = chaincode, data).
    /// 3. Split output: left 32 bytes = tweak, right 32 bytes = new chaincode.
    /// 4. New private key = parent_key + tweak (mod secp256k1 order).
    pub fn ckd_priv(&self, child: u32) -> Result<HDPrivNode<Secp256k1, 32>, &'static str> {
        let hardened = child >= 0x80000000;
        let parent = Secp256k1Scalar::from_be_bytes(&self.privkey).ok_or("invalid private key")?;

        // 1. Build the HMAC data prefix.
        let mut data_prefix = Zeroizing::new([0u8; 33]);
        if hardened {
            data_prefix[0] = 0x00;
            data_prefix[1..33].copy_from_slice(&*self.privkey);
        } else {
            let pubkey = &Secp256k1::get_generator() * &parent;
            data_prefix.copy_from_slice(&pubkey.to_compressed().ok_or("invalid private key")?);
        }

        // 2. HMAC-SHA512(key = chaincode, data = data_prefix || child_index_be).
        let hmac_result = Zeroizing::new(hmac_sha512(
            &self.chaincode,
            &data_prefix[..],
            &child.to_be_bytes(),
        ));

        // 3. Split: left 32 bytes = tweak, right 32 bytes = new chaincode.
        // BIP-32 rejects a tweak that is not smaller than the curve order (this happens with
        // negligible probability)
        let tweak = Secp256k1Scalar::from_be_bytes(hmac_result[0..32].try_into().unwrap())
            .ok_or("invalid tweak")?;
        let mut new_chaincode = [0u8; 32];
        new_chaincode.copy_from_slice(&hmac_result[32..64]);

        // 4. new_privkey = (parent_privkey + tweak) mod n, which BIP-32 rejects if it is 0
        let child_privkey = &parent + &tweak;
        if child_privkey.is_zero() {
            return Err("derived child key is the zero scalar");
        }

        let mut result = HDPrivNode::<Secp256k1, 32>::default();
        result.chaincode = new_chaincode;
        *result.privkey = *child_privkey.as_be_bytes();
        Ok(result)
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
        let point1 = Secp256k1Point::from_coordinates(
            &hex!("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            &hex!("1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
        )
        .unwrap();
        let point2 = Secp256k1Point::from_coordinates(
            &hex!("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            &hex!("388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
        )
        .unwrap();

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
        let point1 = Secp256k1::get_generator();
        let scalar = Secp256k1Scalar::from_be_bytes(&hex!(
            "22445566778899aabbccddeeff0011223344556677889900aabbccddeeff0011"
        ))
        .unwrap();

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

    fn n_minus(d: u32) -> [u8; 32] {
        let n = Secp256k1Scalar::from_be_bytes_reduced(&Secp256k1Scalar::ORDER);
        *(&n - &Secp256k1Scalar::from_u32(d)).as_be_bytes()
    }

    #[test]
    fn test_scalar_construction() {
        assert!(Secp256k1Scalar::from_be_bytes(&Secp256k1Scalar::ORDER).is_none());
        assert!(Secp256k1Scalar::from_be_bytes(&[0xff; 32]).is_none());
        assert!(Secp256k1Scalar::from_be_bytes(&n_minus(1)).is_some());
        assert!(Secp256k1Scalar::zero().is_zero());
        assert!(!Secp256k1Scalar::one().is_zero());

        let mut n_plus_5 = Secp256k1Scalar::ORDER;
        n_plus_5[31] += 5;
        assert_eq!(
            Secp256k1Scalar::from_be_bytes_reduced(&n_plus_5),
            Secp256k1Scalar::from_u32(5)
        );
        assert!(Secp256k1Scalar::from_be_bytes_reduced(&Secp256k1Scalar::ORDER).is_zero());
    }

    #[test]
    fn test_scalar_arithmetic() {
        let one = Secp256k1Scalar::one();
        let two = Secp256k1Scalar::from_u32(2);
        let three = Secp256k1Scalar::from_u32(3);
        let n_minus_1 = Secp256k1Scalar::from_be_bytes(&n_minus(1)).unwrap();

        assert_eq!(&n_minus_1 + &two, one);
        assert_eq!(&one - &two, n_minus_1);
        assert_eq!(-&one, n_minus_1);
        assert!((-&Secp256k1Scalar::zero()).is_zero());
        assert_eq!(&two * &three, Secp256k1Scalar::from_u32(6));
        assert_eq!(&n_minus_1 * &n_minus_1, one);

        assert_eq!(&three.inv().unwrap() * &three, one);
        assert_eq!(n_minus_1.inv().unwrap(), n_minus_1);
        assert!(Secp256k1Scalar::zero().inv().is_none());
    }

    #[test]
    fn test_point_negation() {
        let g = Secp256k1::get_generator();
        let neg_g = -&g;
        assert_eq!(neg_g.x(), g.x());
        assert!(!neg_g.has_even_y());
        assert!((&g + &neg_g).is_zero());
        assert_eq!(-&neg_g, g);
        assert!((-&Secp256k1Point::default()).is_zero());

        // (n - 1) * G = -G
        let n_minus_1 = Secp256k1Scalar::from_be_bytes(&n_minus(1)).unwrap();
        assert_eq!(&g * &n_minus_1, neg_g);
        assert!((&g * &Secp256k1Scalar::zero()).is_zero());
    }

    #[test]
    fn test_lift_x_and_compressed() {
        let g = Secp256k1::get_generator();
        assert!(g.has_even_y());
        assert_eq!(Secp256k1Point::lift_x(g.x()).unwrap(), g);

        let mut compressed = g.to_compressed().unwrap();
        assert_eq!(compressed[0], 0x02);
        assert_eq!(Secp256k1Point::from_compressed(&compressed).unwrap(), g);
        compressed[0] = 0x03;
        assert_eq!(Secp256k1Point::from_compressed(&compressed).unwrap(), -&g);
        assert_eq!((-&g).to_compressed().unwrap(), compressed);
        assert!(Secp256k1Point::default().to_compressed().is_none());

        // x = p is not a field element, and x = 5 is not the x-coordinate of a point of the curve
        assert!(Secp256k1Point::lift_x(&Secp256k1::P).is_err());
        let mut five = [0u8; 32];
        five[31] = 5;
        assert!(Secp256k1Point::lift_x(&five).is_err());
    }

    #[test]
    fn test_from_coordinates_rejects_points_off_the_curve() {
        let g = Secp256k1::get_generator();
        let mut y = *g.y();
        y[31] ^= 1;
        assert!(Secp256k1Point::from_coordinates(g.x(), &y).is_err());
        assert_eq!(Secp256k1Point::from_coordinates(g.x(), g.y()).unwrap(), g);
        // a coordinate that is not smaller than p
        assert!(Secp256k1Point::from_coordinates(&Secp256k1::P, g.y()).is_err());
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

    // BIP-32 test vector 1 (seed 000102030405060708090a0b0c0d0e0f).

    /// m/0h  →  m/0h/1  (child index 1, non-hardened)
    #[test]
    fn test_ckd_priv_bip32_tv1_m0h_to_m0h1() {
        // BIP-32 test vector 1, node m/0h
        let parent = HDPrivNode::<Secp256k1, 32> {
            curve_marker: PhantomData,
            privkey: Zeroizing::new(hex!(
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
            )),
            chaincode: hex!("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"),
        };

        let child = parent
            .ckd_priv(1)
            .expect("non-hardened derivation should succeed");

        // Expected: m/0h/1
        assert_eq!(
            child.privkey[..],
            hex!("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
        );
        assert_eq!(
            child.chaincode,
            hex!("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")
        );
    }

    /// m/0h/1/2h  →  m/0h/1/2h/2  (child index 2, non-hardened)
    #[test]
    fn test_ckd_priv_bip32_tv1_m0h12h_to_m0h12h2() {
        // BIP-32 test vector 1, node m/0h/1/2h
        let parent = HDPrivNode::<Secp256k1, 32> {
            curve_marker: PhantomData,
            privkey: Zeroizing::new(hex!(
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"
            )),
            chaincode: hex!("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"),
        };

        let child = parent
            .ckd_priv(2)
            .expect("non-hardened derivation should succeed");

        // Expected: m/0h/1/2h/2
        assert_eq!(
            child.privkey[..],
            hex!("0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4")
        );
        assert_eq!(
            child.chaincode,
            hex!("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd")
        );
    }

    /// m/0h/1/2h/2  →  m/0h/1/2h/2/1000000000  (child index 1_000_000_000, non-hardened)
    #[test]
    fn test_ckd_priv_bip32_tv1_m0h12h2_to_m0h12h2_1e9() {
        // BIP-32 test vector 1, node m/0h/1/2h/2
        let parent = HDPrivNode::<Secp256k1, 32> {
            curve_marker: PhantomData,
            privkey: Zeroizing::new(hex!(
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"
            )),
            chaincode: hex!("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"),
        };

        let child = parent
            .ckd_priv(1_000_000_000)
            .expect("non-hardened derivation should succeed");

        // Expected: m/0h/1/2h/2/1000000000
        assert_eq!(
            child.privkey[..],
            hex!("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8")
        );
        assert_eq!(
            child.chaincode,
            hex!("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e")
        );
    }

    #[test]
    fn test_from_compressed_generator_even_y() {
        // Generator point: y is even → 0x02 prefix
        let compressed = hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let pubkey = EcfpPublicKey::<Secp256k1, 32>::from_compressed(&compressed).unwrap();
        assert_eq!(
            pubkey.as_ref().x,
            hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        assert_eq!(
            pubkey.as_ref().y,
            hex!("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
        );
        assert_eq!(pubkey.as_ref().y[31] & 1, 0, "y should be even");
    }

    #[test]
    fn test_from_compressed_generator_odd_y() {
        // Generator point negation: same x, 0x03 prefix → y = p - y_G
        let compressed = hex!("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let pubkey = EcfpPublicKey::<Secp256k1, 32>::from_compressed(&compressed).unwrap();
        assert_eq!(
            pubkey.as_ref().x,
            hex!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        );
        // y = p - y_G = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        //             - 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        //             = B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777
        assert_eq!(
            pubkey.as_ref().y,
            hex!("b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777")
        );
        assert_eq!(pubkey.as_ref().y[31] & 1, 1, "y should be odd");
    }

    #[test]
    fn test_from_compressed_invalid_prefix() {
        // 0x04 is an uncompressed prefix, not a valid compressed prefix
        let compressed = hex!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert!(EcfpPublicKey::<Secp256k1, 32>::from_compressed(&compressed).is_err());

        // 0x00 is also invalid
        let compressed = hex!("0079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        assert!(EcfpPublicKey::<Secp256k1, 32>::from_compressed(&compressed).is_err());
    }

    /// BIP-32 test vector 1, m → m/0h (hardened, child index 0x80000000)
    #[test]
    fn test_ckd_priv_bip32_tv1_m_to_m0h_hardened() {
        // Master node m for seed 000102030405060708090a0b0c0d0e0f
        let parent = HDPrivNode::<Secp256k1, 32> {
            curve_marker: PhantomData,
            privkey: Zeroizing::new(hex!(
                "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
            )),
            chaincode: hex!("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"),
        };

        let child = parent
            .ckd_priv(0x80000000)
            .expect("hardened derivation should succeed");

        // Expected: m/0h
        assert_eq!(
            child.privkey[..],
            hex!("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
        );
        assert_eq!(
            child.chaincode,
            hex!("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")
        );
    }

    /// BIP-32 test vector 1: fingerprint of the master public key (seed 000102030405060708090a0b0c0d0e0f).
    /// The expected value 0x3442193e is the parent_fingerprint recorded in the m/0h serialization
    /// in the BIP-32 specification.
    #[test]
    fn test_fingerprint_bip32_tv1_master() {
        let privkey = EcfpPrivateKey::<Secp256k1, 32>::new(hex!(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        ));
        assert_eq!(privkey.to_public_key().fingerprint(), 0x3442193e);
    }
}
