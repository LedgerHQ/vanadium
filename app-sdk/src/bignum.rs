//! Module providing arbitrary-sized big number arithmetic and modular operations, built
//! using the ECALLs provided in the Vanadium app sdk.
//!
//! This module defines the `BigNum`, `Modulus`, and `BigNumMod` structs, which allow for
//! arithmetic operations on big numbers of a specified size, including modular addition,
//! subtraction, multiplication, and exponentiation.

use core::{
    marker::PhantomData,
    ops::{Add, AddAssign, MulAssign, Sub, SubAssign},
    panic,
};

use crate::ecalls;

use common::ecall_constants::MAX_BIGNUMBER_SIZE;
use subtle::ConstantTimeEq;

/// Represents an arbitrary-sized big number, up to the maximum supported size `MAX_BIGNUMBER_SIZE`.
/// Numbers are contained in a byte array of size `N`.
///
/// The `BigNum<N>` struct holds a big number in a byte array of size `N`.
///
/// Additions and subtractions are implemented only for operators of the same size, and are wrapping
/// in case of overflow or underflow.
#[derive(Debug, Clone)]
pub struct BigNum<const N: usize> {
    buffer: [u8; N],
}

impl<const N: usize> PartialEq for BigNum<N> {
    fn eq(&self, other: &Self) -> bool {
        self.buffer.ct_eq(&other.buffer).into()
    }
}

impl<const N: usize> Eq for BigNum<N> {}

impl<const N: usize> BigNum<N> {
    /// Creates a new `BigNum` from a big-endian byte array.
    ///
    /// # Panics
    ///
    /// Panics if the size `N` is larger than `MAX_BIGNUMBER_SIZE`.
    pub fn from_be_bytes(bytes: [u8; N]) -> Self {
        if N > MAX_BIGNUMBER_SIZE {
            panic!("Buffer too large");
        }
        Self { buffer: bytes }
    }

    /// Creates a `BigNum` from a `u32` value.
    ///
    /// # Panics
    ///
    /// Panics if the buffer size `N` is smaller than 4 bytes.
    pub fn from_u32(value: u32) -> Self {
        if N < 4 {
            panic!("Buffer too small to hold u32");
        }
        let mut buffer = [0u8; N];
        buffer[N - 4..N].copy_from_slice(&value.to_be_bytes());
        Self { buffer }
    }

    /// Returns the big number as a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; N] {
        self.buffer
    }
}

// Implementations for addition and subtraction on `BigNum`

impl<const N: usize> Add<&BigNum<N>> for &BigNum<N> {
    type Output = BigNum<N>;

    fn add(self, other: &BigNum<N>) -> BigNum<N> {
        let mut result = [0u8; N];
        let mut carry = 0u16;
        for i in (0..N).rev() {
            let s = self.buffer[i] as u16 + other.buffer[i] as u16 + carry;
            result[i] = s as u8;
            carry = s >> 8;
        }
        BigNum { buffer: result }
    }
}

impl<const N: usize> Add<&BigNum<N>> for BigNum<N> {
    type Output = BigNum<N>;

    fn add(self, other: &BigNum<N>) -> BigNum<N> {
        &self + other
    }
}

impl<const N: usize> Add<BigNum<N>> for &BigNum<N> {
    type Output = BigNum<N>;

    fn add(self, other: BigNum<N>) -> BigNum<N> {
        self + &other
    }
}

impl<const N: usize> Add<BigNum<N>> for BigNum<N> {
    type Output = BigNum<N>;

    fn add(self, other: BigNum<N>) -> BigNum<N> {
        &self + &other
    }
}

impl<const N: usize> AddAssign<&Self> for BigNum<N> {
    fn add_assign(&mut self, other: &Self) {
        let mut carry = 0u16;

        for i in (0..N).rev() {
            let sum = self.buffer[i] as u16 + other.buffer[i] as u16 + carry;
            self.buffer[i] = sum as u8;
            carry = sum >> 8;
        }
    }
}

impl<const N: usize> Sub for &BigNum<N> {
    type Output = BigNum<N>;

    fn sub(self, other: Self) -> BigNum<N> {
        let mut result = [0u8; N];
        let mut borrow = 0i16;

        for i in (0..N).rev() {
            let diff = self.buffer[i] as i16 - other.buffer[i] as i16 - borrow;
            if diff >= 0 {
                result[i] = diff as u8;
                borrow = 0;
            } else {
                result[i] = (diff + 256) as u8;
                borrow = 1;
            }
        }

        BigNum { buffer: result }
    }
}

impl<const N: usize> Sub<&BigNum<N>> for BigNum<N> {
    type Output = BigNum<N>;

    fn sub(self, other: &BigNum<N>) -> BigNum<N> {
        &self - other
    }
}

impl<const N: usize> Sub<BigNum<N>> for &BigNum<N> {
    type Output = BigNum<N>;

    fn sub(self, other: BigNum<N>) -> BigNum<N> {
        self - &other
    }
}

impl<const N: usize> Sub<BigNum<N>> for BigNum<N> {
    type Output = BigNum<N>;

    fn sub(self, other: BigNum<N>) -> BigNum<N> {
        &self - &other
    }
}

impl<const N: usize> SubAssign<&Self> for BigNum<N> {
    fn sub_assign(&mut self, other: &Self) {
        let mut borrow = 0i16;

        for i in (0..N).rev() {
            let diff = self.buffer[i] as i16 - other.buffer[i] as i16 - borrow;
            if diff >= 0 {
                self.buffer[i] = diff as u8;
                borrow = 0;
            } else {
                self.buffer[i] = (diff + 256) as u8;
                borrow = 1;
            }
        }
    }
}

pub trait ModulusProvider<const N: usize>: Sized {
    const M: [u8; N];

    fn new_big_num_mod(&self, buffer: [u8; N]) -> BigNumMod<N, Self> {
        BigNumMod::from_be_bytes(buffer)
    }
}

/// Represents a big number under a given modulus.
///
/// The `BigNumMod` struct provides arithmetic operations for big numbers under a specified modulus.
/// Operations between `BigNumMod` instances will panic if their moduli differ.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct BigNumMod<const N: usize, M: ModulusProvider<N>> {
    buffer: [u8; N],
    // use PhantomData for M
    _marker: PhantomData<M>,
}

impl<const N: usize, M: ModulusProvider<N>> BigNumMod<N, M> {
    /// Creates a new `BigNumMod` from a big-endian byte array and a modulus.
    ///
    /// The value is reduced modulo the modulus during creation, therefore the
    /// value in the buffer is guaranteed to be strictly smaller than the modulus.
    ///
    /// # Panics
    ///
    /// Panics if the size `N` is larger than `MAX_BIGNUMBER_SIZE`, or if the modulus is zero.
    pub fn from_be_bytes(buffer: [u8; N]) -> Self {
        if N > MAX_BIGNUMBER_SIZE {
            panic!("Buffer too large");
        }
        // reduce the buffer by the modulus
        let mut buffer = buffer;
        if 1 != ecalls::bn_modm(buffer.as_mut_ptr(), buffer.as_ptr(), N, M::M.as_ptr(), N) {
            panic!("bn_modm failed")
        }

        Self {
            buffer,
            _marker: PhantomData,
        }
    }

    /// Creates a new `BigNumMod` from a big-endian byte array without reducing it modulo the modulus.
    /// It is responsibility of the caller to guarantee that the buffer is indeed smaller than the modulus.
    ///
    /// # Panics
    ///
    /// Panics if the size `N` is larger than `MAX_BIGNUMBER_SIZE`.
    pub const fn from_be_bytes_noreduce(buffer: [u8; N]) -> Self {
        if N > MAX_BIGNUMBER_SIZE {
            panic!("Buffer too large");
        }
        Self {
            buffer,
            _marker: PhantomData,
        }
    }

    /// Creates a `BigNumMod` from a `u32` value and a modulus.
    ///
    /// The value is reduced modulo the modulus during creation.
    ///
    /// # Panics
    ///
    /// Panics if the size `N` is larger than `MAX_BIGNUMBER_SIZE`, if `N` is too small to hold a u32,
    /// or if the modulus is zero.
    #[inline]
    pub fn from_u32(value: u32) -> Self {
        if N > MAX_BIGNUMBER_SIZE {
            panic!("Buffer too large");
        }
        if N <= 4 {
            panic!("Buffer too small");
        }
        let mut buffer = [0u8; N];
        buffer[N - 4..N].copy_from_slice(&value.to_be_bytes());

        if 1 != ecalls::bn_modm(buffer.as_mut_ptr(), buffer.as_ptr(), N, M::M.as_ptr(), N) {
            panic!("bn_modm failed");
        }

        Self {
            buffer,
            _marker: PhantomData,
        }
    }

    /// Returns the value, in big-endian, expressed as a &[u8; N].
    pub fn as_be_bytes(&self) -> &[u8; N] {
        &self.buffer
    }

    /// Converts to a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; N] {
        self.buffer
    }

    /// Computes the modular exponentiation of the value raised to the given exponent.
    ///
    /// Returns a new `BigNumMod` representing `(self ^ exponent) mod modulus`.
    pub fn pow<const N_EXP: usize>(&self, exponent: &BigNum<N_EXP>) -> Self {
        let mut result = [0u8; N];
        let res = ecalls::bn_powm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            exponent.buffer.as_ptr(),
            N_EXP,
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Exponentiation failed");
        }
        Self::from_be_bytes_noreduce(result)
    }

    /// This function is used in the tests to compare two BigNumMod instances when
    /// side channel attacks are not a concern. This avoids the overhead of the constant-time comparison.
    pub fn unsafe_eq(&self, other: &Self) -> bool {
        self.buffer == other.buffer
    }
}

/// Checks if two `BigNumMod` instances are equal.
/// Two BigModNum instances are equal if and only if their buffers are equal.
impl<const N: usize, M: ModulusProvider<N>> PartialEq for BigNumMod<N, M> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.buffer.ct_eq(&other.buffer).into()
    }
}

impl<const N: usize, M: ModulusProvider<N>> Eq for BigNumMod<N, M> {}

impl<const N: usize, M: ModulusProvider<N>> Add for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn add(self, other: Self) -> BigNumMod<N, M> {
        let mut result = [0u8; N];
        let res = ecalls::bn_addm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Addition failed");
        }
        BigNumMod::from_be_bytes_noreduce(result)
    }
}

impl<const N: usize, M: ModulusProvider<N>> Add<&BigNumMod<N, M>> for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn add(self, other: &BigNumMod<N, M>) -> BigNumMod<N, M> {
        &self + other
    }
}

impl<const N: usize, M: ModulusProvider<N>> Add<BigNumMod<N, M>> for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn add(self, other: BigNumMod<N, M>) -> BigNumMod<N, M> {
        self + &other
    }
}

impl<const N: usize, M: ModulusProvider<N>> Add<BigNumMod<N, M>> for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn add(self, other: BigNumMod<N, M>) -> BigNumMod<N, M> {
        &self + &other
    }
}

impl<const N: usize, M: ModulusProvider<N>> AddAssign for BigNumMod<N, M> {
    #[inline]
    fn add_assign(&mut self, other: Self) {
        let res = ecalls::bn_addm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Addition failed");
        }
    }
}

impl<const N: usize, M: ModulusProvider<N>> AddAssign<&BigNumMod<N, M>> for BigNumMod<N, M> {
    #[inline]
    fn add_assign(&mut self, other: &BigNumMod<N, M>) {
        let res = ecalls::bn_addm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Addition failed");
        }
    }
}

impl<const N: usize, M: ModulusProvider<N>> Add<u32> for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn add(self, other: u32) -> BigNumMod<N, M> {
        &self + other
    }
}

impl<const N: usize, M: ModulusProvider<N>> Add<u32> for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn add(self, other: u32) -> BigNumMod<N, M> {
        self + &BigNumMod::from_u32(other)
    }
}

impl<const N: usize, M: ModulusProvider<N>> Add<&BigNumMod<N, M>> for u32 {
    type Output = BigNumMod<N, M>;

    fn add(self, other: &BigNumMod<N, M>) -> BigNumMod<N, M> {
        &BigNumMod::from_u32(self) + other
    }
}

impl<const N: usize, M: ModulusProvider<N>> AddAssign<u32> for BigNumMod<N, M> {
    fn add_assign(&mut self, other: u32) {
        *self += Self::from_u32(other);
    }
}

impl<const N: usize, M: ModulusProvider<N>> Sub for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn sub(self, other: Self) -> BigNumMod<N, M> {
        let mut result = [0u8; N];
        let res = ecalls::bn_subm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Subtraction failed");
        }
        BigNumMod::from_be_bytes_noreduce(result)
    }
}

impl<const N: usize, M: ModulusProvider<N>> Sub<&BigNumMod<N, M>> for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn sub(self, other: &BigNumMod<N, M>) -> BigNumMod<N, M> {
        &self - other
    }
}

impl<const N: usize, M: ModulusProvider<N>> Sub<BigNumMod<N, M>> for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn sub(self, other: BigNumMod<N, M>) -> BigNumMod<N, M> {
        self - &other
    }
}

impl<const N: usize, M: ModulusProvider<N>> Sub<BigNumMod<N, M>> for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn sub(self, other: BigNumMod<N, M>) -> BigNumMod<N, M> {
        &self - &other
    }
}

impl<const N: usize, M: ModulusProvider<N>> SubAssign for BigNumMod<N, M> {
    fn sub_assign(&mut self, other: Self) {
        let res = ecalls::bn_subm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Subtraction failed");
        }
    }
}

impl<const N: usize, M: ModulusProvider<N>> SubAssign<&BigNumMod<N, M>> for BigNumMod<N, M> {
    fn sub_assign(&mut self, other: &BigNumMod<N, M>) {
        let res = ecalls::bn_subm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Subtraction failed");
        }
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Sub<u32> for BigNumMod<N, M> {
    type Output = Self;

    fn sub(self, other: u32) -> Self {
        &self - &Self::from_u32(other)
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Sub<u32> for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn sub(self, other: u32) -> BigNumMod<N, M> {
        self - &BigNumMod::from_u32(other)
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Sub<&BigNumMod<N, M>> for u32 {
    type Output = BigNumMod<N, M>;

    fn sub(self, rhs: &BigNumMod<N, M>) -> BigNumMod<N, M> {
        BigNumMod::from_u32(self) - rhs
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Sub<BigNumMod<N, M>> for u32 {
    type Output = BigNumMod<N, M>;

    fn sub(self, rhs: BigNumMod<N, M>) -> BigNumMod<N, M> {
        BigNumMod::from_u32(self) - &rhs
    }
}

impl<const N: usize, M: ModulusProvider<N>> SubAssign<u32> for BigNumMod<N, M> {
    fn sub_assign(&mut self, other: u32) {
        *self -= Self::from_u32(other);
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Mul for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn mul(self, other: Self) -> BigNumMod<N, M> {
        let mut result = [0u8; N];
        let res = ecalls::bn_multm(
            result.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Multiplication failed");
        }
        BigNumMod::from_be_bytes_noreduce(result)
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Mul<&BigNumMod<N, M>> for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn mul(self, other: &BigNumMod<N, M>) -> Self::Output {
        &self * other
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Mul<BigNumMod<N, M>> for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn mul(self, other: BigNumMod<N, M>) -> Self::Output {
        self * &other
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Mul for BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    fn mul(self, other: Self) -> Self::Output {
        &self * &other
    }
}

impl<const N: usize, M: ModulusProvider<N>> MulAssign<&Self> for BigNumMod<N, M> {
    fn mul_assign(&mut self, other: &Self) {
        let res = ecalls::bn_multm(
            self.buffer.as_mut_ptr(),
            self.buffer.as_ptr(),
            other.buffer.as_ptr(),
            M::M.as_ptr(),
            N,
        );
        if res != 1 {
            panic!("Multiplication failed");
        }
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Mul<u32> for BigNumMod<N, M> {
    type Output = Self;

    fn mul(self, other: u32) -> Self {
        &self * &BigNumMod::from_u32(other)
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::MulAssign<u32> for BigNumMod<N, M> {
    fn mul_assign(&mut self, other: u32) {
        *self *= &BigNumMod::from_u32(other);
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Mul<&BigNumMod<N, M>> for u32 {
    type Output = BigNumMod<N, M>;

    fn mul(self, other: &BigNumMod<N, M>) -> BigNumMod<N, M> {
        &BigNumMod::from_u32(self) * other
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Neg for BigNumMod<N, M> {
    type Output = Self;

    #[inline]
    fn neg(self) -> Self {
        Self::from_u32(0) - self
    }
}

impl<const N: usize, M: ModulusProvider<N>> core::ops::Neg for &BigNumMod<N, M> {
    type Output = BigNumMod<N, M>;

    #[inline]
    fn neg(self) -> BigNumMod<N, M> {
        BigNumMod::<N, M>::from_u32(0) - self
    }
}

/// Converts a byte array to a `BigNum` reference.
///
/// # Safety
/// It is the responsibility of the caller to make sure that the byte array represents a
/// number smaller than the modulus.
pub unsafe fn as_big_num_mod_ref<'a, const N: usize, M: ModulusProvider<N>>(
    buf: &'a [u8; N],
) -> &'a BigNumMod<N, M> {
    unsafe { &*(buf as *const [u8; N] as *const BigNumMod<N, M>) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[derive(Debug, Clone, Copy)]
    struct M;
    impl ModulusProvider<32> for M {
        const M: [u8; 32] =
            hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    }

    #[derive(Debug, Clone, Copy)]
    struct M2;
    impl ModulusProvider<32> for M2 {
        const M: [u8; 32] =
            hex!("3d4b0f9e4e4d5b6e5e5d6e7e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9d");
    }

    #[test]
    fn test_big_num_addition() {
        assert_eq!(
            &BigNum::<4>::from_u32(0x77989873) + &BigNum::<4>::from_u32(0xa4589234),
            BigNum::<4>::from_u32(0x1bf12aa7)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0x47989873) + &BigNum::<4>::from_u32(0xa4589234),
            BigNum::<4>::from_u32(0xebf12aa7)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0xffffffff) + &BigNum::<4>::from_u32(1),
            BigNum::<4>::from_u32(0)
        );

        let zero_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(0);
        let minus_one_large = BigNum::from_be_bytes([0xff; MAX_BIGNUMBER_SIZE]);
        let one_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(1);
        assert_eq!(&minus_one_large + &one_large, zero_large);
    }

    #[test]
    fn test_big_num_subtraction() {
        assert_eq!(
            &BigNum::<4>::from_u32(0xa4589234) - &BigNum::<4>::from_u32(0x77989873),
            BigNum::<4>::from_u32(0x2cbff9c1)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0x77989873) - &BigNum::<4>::from_u32(0xa4589234),
            BigNum::<4>::from_u32(0xd340063f)
        );
        assert_eq!(
            &BigNum::<4>::from_u32(0) - &BigNum::<4>::from_u32(1),
            BigNum::<4>::from_u32(0xffffffff)
        );

        let minus_one_large = BigNum::from_be_bytes([0xff; MAX_BIGNUMBER_SIZE]);
        let one_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(1);
        let zero_large = BigNum::<MAX_BIGNUMBER_SIZE>::from_u32(0);
        assert_eq!(&zero_large - &one_large, minus_one_large);
    }

    #[test]
    fn test_big_num_mod_equality() {
        let a: BigNumMod<32, M> = BigNumMod::from_be_bytes([0x01; 32]);

        // same modulus and buffer
        let b: BigNumMod<32, M> = BigNumMod::from_be_bytes([0x01; 32]);

        // different buffer
        let c: BigNumMod<32, M> = BigNumMod::from_be_bytes([0x02; 32]);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_big_num_mod_from_u32() {
        let a: BigNumMod<32, M> = BigNumMod::from_u32(2);
        assert_eq!(
            a.buffer,
            hex!("0000000000000000000000000000000000000000000000000000000000000002")
        );
    }

    #[test]
    fn test_big_num_mod_add() {
        let a: BigNumMod<32, M> = BigNumMod::from_u32(2);
        let b: BigNumMod<32, M> = BigNumMod::from_u32(3);
        assert_eq!(&a + &b, BigNumMod::<32, M>::from_u32(5));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            &a + &b,
            M.new_big_num_mod(hex!(
                "15d7f1c4cab897b32c12c8a1b638879e023d5a9d8ca0da88d89bdb53a7b61679"
            ))
        );

        // add with u32
        assert_eq!(
            &BigNumMod::<32, M>::from_u32(2) + 3u32,
            BigNumMod::<32, M>::from_u32(5)
        );
        assert_eq!(
            3u32 + &BigNumMod::<32, M>::from_u32(2),
            BigNumMod::<32, M>::from_u32(5)
        );

        // tests with AddAssign
        let mut a_copy = a.clone();
        a_copy += &b;
        assert_eq!(a_copy, &a + &b);

        let mut a = BigNumMod::<32, M>::from_u32(13);
        a += 7u32;
        assert_eq!(a, BigNumMod::<32, M>::from_u32(20));
    }

    #[test]
    fn test_big_num_mod_sub() {
        let a = BigNumMod::<32, M>::from_u32(5);
        let b = BigNumMod::<32, M>::from_u32(3);
        assert_eq!(&a - &b, BigNumMod::<32, M>::from_u32(2));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            &a - &b,
            M.new_big_num_mod(hex!(
                "2eb6c1439a7770b1fc00388eb1d77f8afdd55575799fb6185776d4c060ae0062"
            ))
        );
        assert_eq!(
            &b - &a,
            M.new_big_num_mod(hex!(
                "d1493ebc65888f4e03ffc7714e288075022aaa8a866049e7a8892b3e9f51fbcd"
            ))
        );

        // sub with u32
        assert_eq!(
            BigNumMod::<32, M>::from_u32(5) - 3u32,
            BigNumMod::<32, M>::from_u32(2)
        );

        // tests with SubAssign
        let mut a_copy = a.clone();
        a_copy -= &b;
        assert_eq!(a_copy, &a - &b);
        let mut a = BigNumMod::<32, M>::from_u32(13);
        a -= 7u32;
        assert_eq!(a, BigNumMod::<32, M>::from_u32(6));
    }

    #[test]
    fn test_big_num_mod_mul() {
        let a = BigNumMod::<32, M>::from_u32(2);
        let b = BigNumMod::<32, M>::from_u32(3);
        assert_eq!(&a * &b, BigNumMod::<32, M>::from_u32(6));

        let a = M.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));
        let b = M.new_big_num_mod(hex!(
            "7390984098209380980948098230840982340294098092384092834923840923"
        ));
        assert_eq!(
            &a * &b,
            M.new_big_num_mod(hex!(
                "2d5daeb3ed823bef5a4480a2c5aa0708e8e37ed7302d2b21c9b442b244d48ce6"
            ))
        );

        // mul with u32
        assert_eq!(
            BigNumMod::<32, M>::from_u32(2) * 3u32,
            BigNumMod::<32, M>::from_u32(6)
        );
        assert_eq!(
            3u32 * &BigNumMod::<32, M>::from_u32(2),
            BigNumMod::<32, M>::from_u32(6)
        );

        // tests for MulAssign
        let mut a_copy = a.clone();
        a_copy *= &b;
        assert_eq!(a_copy, &a * &b);

        let mut a = BigNumMod::<32, M>::from_u32(7);
        a *= 13u32;
        assert_eq!(a, BigNumMod::from_u32(91));
    }

    #[test]
    fn test_big_num_mod_pow() {
        let a = M2.new_big_num_mod(hex!(
            "a247598432980432940980983408039480095809832048509809580984320985"
        ));

        // 0 always returns 1
        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("00"))).buffer,
            hex!("0000000000000000000000000000000000000000000000000000000000000001")
        );

        // 1 is the identity
        assert_eq!(a.pow(&BigNum::from_be_bytes(hex!("01"))), a);

        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("02"))).buffer,
            hex!("2378a937274b6304f12d26e7170d5d757087246a2db3d5c776faf10984d3331b")
        );
        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("00000002"))).buffer,
            hex!("2378a937274b6304f12d26e7170d5d757087246a2db3d5c776faf10984d3331b")
        );
        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!(
                "0000000000000000000000000000000000000000000000000000000000000002"
            )))
            .buffer,
            hex!("2378a937274b6304f12d26e7170d5d757087246a2db3d5c776faf10984d3331b")
        );

        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("23"))).buffer,
            hex!("2c341d219fc6fc7895e4de6a93d48ab77acfc2564beebb7c14a6aa57d3fd575a")
        );

        assert_eq!(
            a.pow(&BigNum::from_be_bytes(hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd722e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7"))).buffer,
            hex!("3c0baee8c4e2f7220615013d7402fa5e69e43bc10e55500a5af4f8b966658846")
        );
    }

    #[test]
    fn test_big_num_mod_neg_zero() {
        let zero = BigNumMod::<32, M>::from_u32(0);
        let neg_zero: BigNumMod<32, M> = -&zero;
        assert_eq!(neg_zero, zero);
    }

    #[test]
    fn test_big_num_mod_neg() {
        let a = BigNumMod::<32, M>::from_u32(5);
        let neg_a = -&a;
        // In modular arithmetic, a + (-a) should equal 0
        assert_eq!(&a + &neg_a, BigNumMod::<32, M>::from_u32(0));
    }
}
