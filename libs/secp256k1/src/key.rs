// SPDX-License-Identifier: CC0-1.0

//! Public and secret keys.
//!

use core::ops::{self, BitXor};
use core::{fmt, str};

use sdk::bignum::BigNumMod;
use sdk::curve::Secp256k1Point;
#[cfg(feature = "serde")]
use serde::ser::SerializeTuple;
use subtle::{Choice, ConstantTimeEq};

use crate::constants::{self, G, N, P};
use crate::sdk_helpers::{secp256k1_compute_y, secp256k1_compute_y_with_parity};
use crate::Error::{self, InvalidPublicKey, InvalidSecretKey, InvalidTweak};
#[cfg(feature = "hashes")]
#[allow(deprecated)]
use crate::ThirtyTwoByteHash;
use crate::{ecdsa, from_hex, schnorr, Message, Scalar, Secp256k1, Signing, Verification};

// subtle doesn't have implement ConstantTimeLess for [u8; 32]
#[inline]
fn ct_lt(a: &[u8; 32], b: &[u8; 32]) -> Choice {
    let mut less = 0u8; // Will be 1 if a < b, 0 otherwise
    let mut equal = 1u8; // Will be 1 if equal so far, 0 otherwise

    for i in 0..32 {
        // Update less: set to 1 if a[i] < a[i] and all previous bytes were equal
        less |= equal & (a[i] < b[i]) as u8;
        // Update equal: remains 1 only if a[i] == a[i] and equal was 1
        equal &= (a[i] == b[i]) as u8;
    }

    Choice::from(less & 1)
}

/// Secret key - a 256-bit key used to create ECDSA and Taproot signatures.
///
/// This value should be generated using a [cryptographically secure pseudorandom number generator].
///
/// # Side channel attacks
///
/// We have attempted to reduce the side channel attack surface by implementing a constant time `eq`
/// method. For similar reasons we explicitly do not implement `PartialOrd`, `Ord`, or `Hash` on
/// `SecretKey`. If you really want to order secrets keys then you can use `AsRef` to get at the
/// underlying bytes and compare them - however this is almost certainly a bad idea.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` feature enabled. We treat the byte value as a tuple
/// of 32 `u8`s for non-human-readable formats. This representation is optimal for for some formats
/// (e.g. [`bincode`]) however other formats may be less optimal (e.g. [`cbor`]).
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(feature =  "rand-std")] {
/// use secp256k1::{rand, Secp256k1, SecretKey};
///
/// let secp = Secp256k1::new();
/// let secret_key = SecretKey::new(&mut rand::thread_rng());
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
/// [cryptographically secure pseudorandom number generator]: https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator
#[derive(Copy, Clone)]
pub struct SecretKey([u8; constants::SECRET_KEY_SIZE]);
impl_display_secret!(SecretKey);

impl PartialEq for SecretKey {
    /// This implementation is designed to be constant time to help prevent side channel attacks.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let accum = self.0.iter().zip(&other.0).fold(0, |accum, (a, b)| accum | a ^ b);
        unsafe { core::ptr::read_volatile(&accum) == 0 }
    }
}

impl Eq for SecretKey {}

impl AsRef<[u8; constants::SECRET_KEY_SIZE]> for SecretKey {
    /// Gets a reference to the underlying array.
    ///
    /// # Side channel attacks
    ///
    /// Using ordering functions (`PartialOrd`/`Ord`) on a reference to secret keys leaks data
    /// because the implementations are not constant time. Doing so will make your code vulnerable
    /// to side channel attacks. [`SecretKey::eq`] is implemented using a constant time algorithm,
    /// please consider using it to do comparisons of secret keys.
    #[inline]
    fn as_ref(&self) -> &[u8; constants::SECRET_KEY_SIZE] {
        let SecretKey(dat) = self;
        dat
    }
}

impl<I> ops::Index<I> for SecretKey
where
    [u8]: ops::Index<I>,
{
    type Output = <[u8] as ops::Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl str::FromStr for SecretKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<SecretKey, Error> {
        let mut res = [0u8; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) => SecretKey::from_slice(&res),
            _ => Err(Error::InvalidSecretKey),
        }
    }
}

/// Public key - used to verify ECDSA signatures and to do Taproot tweaks.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` feature enabled. We treat the byte value as a tuple
/// of 33 `u8`s for non-human-readable formats. This representation is optimal for for some formats
/// (e.g. [`bincode`]) however other formats may be less optimal (e.g. [`cbor`]).
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(feature =  "alloc")] {
/// use vlib_secp256k1::{SecretKey, Secp256k1, PublicKey};
///
/// let secp = Secp256k1::new();
/// let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
/// let public_key = PublicKey::from_secret_key(&secp, &secret_key);
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct PublicKey(sdk::curve::Secp256k1Point);

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<PublicKey, Error> {
        let mut res = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::PUBLIC_KEY_SIZE) =>
                PublicKey::from_slice(&res[0..constants::PUBLIC_KEY_SIZE]),
            Ok(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE) => PublicKey::from_slice(&res),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl SecretKey {
    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key.
    ///
    /// # Examples
    ///
    /// ```
    /// use vlib_secp256k1::SecretKey;
    /// let sk = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    /// ```
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<SecretKey, Error> {
        match <[u8; constants::SECRET_KEY_SIZE]>::try_from(data) {
            Ok(data) => {
                // check if the key is valid, like in the original implementation
                // a key is valid if it is in the range [1, n - 1] where n is the order of the curve
                if bool::from(data.ct_eq(&crate::constants::ZERO))
                    || !bool::from(ct_lt(&data, &crate::constants::CURVE_ORDER))
                {
                    return Err(InvalidSecretKey);
                }

                Ok(SecretKey(data))
            }
            Err(_) => Err(InvalidSecretKey),
        }
    }

    /// Creates a new secret key using data from BIP-340 [`Keypair`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{rand, Secp256k1, SecretKey, Keypair};
    ///
    /// let secp = Secp256k1::new();
    /// let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    /// let secret_key = SecretKey::from_keypair(&keypair);
    /// # }
    /// ```
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let (sk, _) = keypair.0;
        sk
    }

    /// Returns the secret key as a byte value.
    #[inline]
    pub fn secret_bytes(&self) -> [u8; constants::SECRET_KEY_SIZE] { self.0 }

    /// Negates the secret key.
    #[inline]
    #[must_use = "you forgot to use the negated secret key"]
    pub fn negate(mut self) -> SecretKey {
        self.0 = *(-BigNumMod::<32, N>::from_be_bytes_noreduce(self.0)).as_be_bytes();

        self
    }

    /// Tweaks a [`SecretKey`] by adding `tweak` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn add_tweak(mut self, tweak: &Scalar) -> Result<SecretKey, Error> {
        let self_bn = BigNumMod::<32, N>::from_be_bytes_noreduce(self.0);
        let tweak_bn = BigNumMod::<32, N>::from_be_bytes_noreduce(*tweak.as_be_bytes());
        let result_bn = &self_bn + &tweak_bn;
        let result = result_bn.as_be_bytes();

        if bool::from(result.ct_eq(&crate::constants::ZERO)) {
            return Err(InvalidTweak);
        }
        self.0 = *result;
        Ok(self)
    }

    /// Tweaks a [`SecretKey`] by multiplying by `tweak` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn mul_tweak(mut self, tweak: &Scalar) -> Result<SecretKey, Error> { todo!() }

    /// Returns the [`Keypair`] for this [`SecretKey`].
    ///
    /// This is equivalent to using [`Keypair::from_secret_key`].
    #[inline]
    pub fn keypair<C: Signing>(&self, secp: &Secp256k1<C>) -> Keypair {
        Keypair::from_secret_key(secp, self)
    }

    /// Returns the [`PublicKey`] for this [`SecretKey`].
    ///
    /// This is equivalent to using [`PublicKey::from_secret_key`].
    #[inline]
    pub fn public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey::from_secret_key(secp, self)
    }

    /// Returns the [`XOnlyPublicKey`] (and it's [`Parity`]) for this [`SecretKey`].
    ///
    /// This is equivalent to `XOnlyPublicKey::from_keypair(self.keypair(secp))`.
    #[inline]
    pub fn x_only_public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> (XOnlyPublicKey, Parity) {
        let kp = self.keypair(secp);
        XOnlyPublicKey::from_keypair(&kp)
    }
}

#[cfg(feature = "hashes")]
#[allow(deprecated)]
impl<T: ThirtyTwoByteHash> From<T> for SecretKey {
    /// Converts a 32-byte hash directly to a secret key without error paths.
    fn from(t: T) -> SecretKey {
        SecretKey::from_slice(&t.into_32()).expect("failed to create secret key")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecretKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
            s.serialize_str(crate::to_hex(&self.0, &mut buf).expect("fixed-size hex serialization"))
        } else {
            let mut tuple = s.serialize_tuple(constants::SECRET_KEY_SIZE)?;
            for byte in self.0.iter() {
                tuple.serialize_element(byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecretKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte SecretKey",
            ))
        } else {
            let visitor = super::serde_util::Tuple32Visitor::new(
                "raw 32 bytes SecretKey",
                SecretKey::from_slice,
            );
            d.deserialize_tuple(constants::SECRET_KEY_SIZE, visitor)
        }
    }
}

impl PublicKey {
    /// Creates a new public key from a [`SecretKey`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
    ///
    /// let secp = Secp256k1::new();
    /// let secret_key = SecretKey::new(&mut rand::thread_rng());
    /// let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    /// # }
    /// ```
    #[inline]
    pub fn from_secret_key<C: Signing>(_secp: &Secp256k1<C>, sk: &SecretKey) -> PublicKey {
        PublicKey(&G * &sk.secret_bytes())
    }

    /// Creates a public key directly from a slice.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, Error> {
        if data.is_empty() {
            return Err(Error::InvalidPublicKey);
        }

        let header = data[0];
        match header {
            0x02 | 0x03 => {
                if data.len() != 33 {
                    return Err(Error::InvalidPublicKey);
                }
                let x: &[u8; 32] = data[1..33].try_into().unwrap();

                // check if x is a valid coordinate
                if x == &crate::constants::ZERO || x >= &crate::constants::CURVE_ORDER {
                    return Err(Error::InvalidPublicKey);
                }

                // compute the y coordinate
                let x_bn = unsafe { sdk::bignum::as_big_num_mod_ref::<32, P>(x) };
                let y_bn = secp256k1_compute_y_with_parity(x_bn, header & 1)?;
                let y = y_bn.to_be_bytes();
                Ok(PublicKey(Secp256k1Point::new(*x, y)))
            }
            0x04 => {
                if data.len() != 65 {
                    return Err(Error::InvalidPublicKey);
                }
                let x: &[u8; 32] = data[1..33].try_into().unwrap();
                let y: &[u8; 32] = data[33..65].try_into().unwrap();

                // check if x is a valid coordinate
                if x == &crate::constants::ZERO || x >= &crate::constants::CURVE_ORDER {
                    return Err(Error::InvalidPublicKey);
                }
                // check if y is a valid coordinate
                if y == &crate::constants::ZERO || y >= &crate::constants::CURVE_ORDER {
                    return Err(Error::InvalidPublicKey);
                }

                let point = sdk::curve::Secp256k1Point::new(*x, *y);

                let x_bn = unsafe { sdk::bignum::as_big_num_mod_ref::<32, P>(x) };
                let y_bn = unsafe { sdk::bignum::as_big_num_mod_ref::<32, P>(y) };
                let lhs = y_bn * y_bn;
                let rhs = x_bn * x_bn * x_bn + crate::sdk_helpers::SEVEN;
                if !lhs.unsafe_eq(&rhs) {
                    return Err(Error::InvalidPublicKey);
                }

                Ok(PublicKey(point))
            }
            0x06 | 0x07 => panic!("Hybrid keys are not implemented"),
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// Creates a new compressed public key using data from BIP-340 [`Keypair`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{rand, Secp256k1, PublicKey, Keypair};
    ///
    /// let secp = Secp256k1::new();
    /// let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    /// let public_key = PublicKey::from_keypair(&keypair);
    /// # }
    /// ```
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let (_, pk) = keypair.0;
        pk
    }

    /// Creates a [`PublicKey`] using the key material from `pk` combined with the `parity`.
    pub fn from_x_only_public_key(pk: XOnlyPublicKey, parity: Parity) -> PublicKey {
        let mut buf = [0u8; 33];

        // First byte of a compressed key should be `0x02 AND parity`.
        buf[0] = match parity {
            Parity::Even => 0x02,
            Parity::Odd => 0x03,
        };
        buf[1..].clone_from_slice(&pk.serialize());

        PublicKey::from_slice(&buf).expect("we know the buffer is valid")
    }

    #[inline]
    /// Serializes the key as a byte-encoded pair of values. In compressed form the y-coordinate is
    /// represented by only a single bit, as x determines it up to one bit.
    pub fn serialize(&self) -> [u8; constants::PUBLIC_KEY_SIZE] {
        let mut res = [0u8; constants::PUBLIC_KEY_SIZE];
        res[0] = 0x02 + (self.0.y[31] & 0x01);
        res[1..33].copy_from_slice(&self.0.x);
        res
    }

    #[inline]
    /// Serializes the key as a byte-encoded pair of values, in uncompressed form.
    pub fn serialize_uncompressed(&self) -> [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] {
        let mut res = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        res[0] = 0x04;
        res[1..33].copy_from_slice(&self.0.x);
        res[33..65].copy_from_slice(&self.0.y);
        res
    }

    /// Negates the public key.
    #[inline]
    #[must_use = "you forgot to use the negated public key"]
    pub fn negate<C: Verification>(mut self, secp: &Secp256k1<C>) -> PublicKey { todo!() }

    /// Tweaks a [`PublicKey`] by adding `tweak * G` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn add_exp_tweak<C: Verification>(
        mut self,
        _secp: &Secp256k1<C>,
        tweak: &Scalar,
    ) -> Result<PublicKey, Error> {
        let g = sdk::curve::Secp256k1::get_generator();

        let tweaked = &g * &tweak.as_be_bytes();
        let result = &self.0 + &tweaked;

        if result.is_zero() {
            return Err(Error::InvalidTweak);
        }

        self.0 = result;
        Ok(self)
    }

    /// Tweaks a [`PublicKey`] by multiplying by `tweak` modulo the curve order.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    #[inline]
    pub fn mul_tweak<C: Verification>(
        mut self,
        secp: &Secp256k1<C>,
        other: &Scalar,
    ) -> Result<PublicKey, Error> {
        todo!()
    }

    /// Adds a second key to this one, returning the sum.
    ///
    /// # Errors
    ///
    /// If the result would be the point at infinity, i.e. adding this point to its own negation.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "rand-std")] {
    /// use secp256k1::{rand, Secp256k1};
    ///
    /// let secp = Secp256k1::new();
    /// let mut rng = rand::thread_rng();
    /// let (_, pk1) = secp.generate_keypair(&mut rng);
    /// let (_, pk2) = secp.generate_keypair(&mut rng);
    /// let sum = pk1.combine(&pk2).expect("It's improbable to fail for 2 random public keys");
    /// # }
    /// ```
    pub fn combine(&self, other: &PublicKey) -> Result<PublicKey, Error> {
        PublicKey::combine_keys(&[self, other])
    }

    /// Adds the keys in the provided slice together, returning the sum.
    ///
    /// # Errors
    ///
    /// Errors under any of the following conditions:
    /// - The result would be the point at infinity, i.e. adding a point to its own negation.
    /// - The provided slice is empty.
    /// - The number of elements in the provided slice is greater than `i32::MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{rand, Secp256k1, PublicKey};
    ///
    /// let secp = Secp256k1::new();
    /// let mut rng = rand::thread_rng();
    /// let (_, pk1) = secp.generate_keypair(&mut rng);
    /// let (_, pk2) = secp.generate_keypair(&mut rng);
    /// let (_, pk3) = secp.generate_keypair(&mut rng);
    /// let sum = PublicKey::combine_keys(&[&pk1, &pk2, &pk3]).expect("It's improbable to fail for 3 random public keys");
    /// # }
    /// ```
    pub fn combine_keys(keys: &[&PublicKey]) -> Result<PublicKey, Error> { todo!() }

    /// Returns the [`XOnlyPublicKey`] (and it's [`Parity`]) for this [`PublicKey`].
    #[inline]
    pub fn x_only_public_key(&self) -> (XOnlyPublicKey, Parity) {
        let x = self.0.x;
        let y = self.0.y;
        let parity = Parity::from_u8(y[31] & 1).expect("This can never fail");
        let x_only = XOnlyPublicKey::from_slice(&x).expect("We know the public key is valid");
        (x_only, parity)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: &Message,
        sig: &ecdsa::Signature,
    ) -> Result<(), Error> {
        secp.verify_ecdsa(msg, sig, self)
    }
}

impl From<Secp256k1Point> for PublicKey {
    #[inline]
    fn from(pk: Secp256k1Point) -> PublicKey { PublicKey(pk) }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            let mut tuple = s.serialize_tuple(constants::PUBLIC_KEY_SIZE)?;
            // Serialize in compressed form.
            for byte in self.serialize().iter() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "an ASCII hex string representing a public key",
            ))
        } else {
            let visitor = super::serde_util::Tuple33Visitor::new(
                "33 bytes compressed public key",
                PublicKey::from_slice,
            );
            d.deserialize_tuple(constants::PUBLIC_KEY_SIZE, visitor)
        }
    }
}

/// Opaque data structure that holds a keypair consisting of a secret and a public key.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` and_`global-context` features enabled. Serializes
/// the secret bytes only. We treat the byte value as a tuple of 32 `u8`s for non-human-readable
/// formats. This representation is optimal for for some formats (e.g. [`bincode`]) however other
/// formats may be less optimal (e.g. [`cbor`]). For human-readable formats we use a hex string.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(feature =  "rand-std")] {
/// use secp256k1::{rand, Keypair, Secp256k1};
///
/// let secp = Secp256k1::new();
/// let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
/// let keypair = Keypair::from_secret_key(&secp, &secret_key);
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Keypair((SecretKey, PublicKey));

// implement PartialOrd, Ord and Hash by only using the PublicKey part
impl PartialOrd for Keypair {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.public_key().partial_cmp(&other.public_key())
    }
}
impl Ord for Keypair {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.public_key().cmp(&other.public_key())
    }
}
impl core::hash::Hash for Keypair {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) { self.public_key().hash(state) }
}
impl_display_secret!(Keypair);

impl Keypair {
    /// Generates a new random secret key using the global [`SECP256K1`] context.
    #[cfg(all(feature = "rand", feature = "global-context"))]
    pub fn new_global<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Self {
        let key: [u8; 32] = rng.gen();
        Self::from_seckey_slice(crate::SECP256K1, &key).expect("cryptographically impossible")
    }

    /// Creates a [`Keypair`] directly from a Secp256k1 secret key.
    #[inline]
    pub fn from_secret_key<C: Signing>(secp: &Secp256k1<C>, sk: &SecretKey) -> Keypair {
        Keypair((sk.clone(), PublicKey::from_secret_key(secp, sk)))
    }

    /// Creates a [`Keypair`] directly from a secret key slice.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if the provided data has an incorrect length, exceeds Secp256k1
    /// field `p` value or the corresponding public key is not even.
    #[inline]
    pub fn from_seckey_slice<C: Signing>(
        secp: &Secp256k1<C>,
        data: &[u8],
    ) -> Result<Keypair, Error> {
        if data.is_empty() || data.len() != constants::SECRET_KEY_SIZE {
            return Err(Error::InvalidSecretKey);
        }

        let sk = SecretKey::from_slice(data)?;
        Ok(Keypair::from_secret_key(secp, &sk))
    }

    /// Creates a [`Keypair`] directly from a secret key string.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSecretKey`] if corresponding public key for the provided secret key is not even.
    #[inline]
    pub fn from_seckey_str<C: Signing>(secp: &Secp256k1<C>, s: &str) -> Result<Keypair, Error> {
        let mut res = [0u8; constants::SECRET_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SECRET_KEY_SIZE) =>
                Keypair::from_seckey_slice(secp, &res[0..constants::SECRET_KEY_SIZE]),
            _ => Err(Error::InvalidPublicKey),
        }
    }

    /// Returns the secret bytes for this key pair.
    #[inline]
    pub fn secret_bytes(&self) -> [u8; constants::SECRET_KEY_SIZE] {
        *SecretKey::from_keypair(self).as_ref()
    }

    /// Tweaks a keypair by first converting the public key to an xonly key and tweaking it.
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting key would be invalid.
    ///
    /// NB: Will not error if the tweaked public key has an odd value and can't be used for
    ///     BIP 340-342 purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{Secp256k1, Keypair, Scalar};
    ///
    /// let secp = Secp256k1::new();
    /// let tweak = Scalar::random();
    ///
    /// let mut keypair = Keypair::new(&secp, &mut rand::thread_rng());
    /// let tweaked = keypair.add_xonly_tweak(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    // TODO: Add checked implementation
    #[inline]
    pub fn add_xonly_tweak<C: Verification>(
        mut self,
        secp: &Secp256k1<C>,
        tweak: &Scalar,
    ) -> Result<Keypair, Error> {
        let y = self.0 .1 .0.y;
        let is_y_odd = y[31] & 1 == 1;

        self.0 .1 = self.0 .1.add_exp_tweak(secp, tweak)?;

        if is_y_odd {
            self.0 .0 = self.0 .0.negate();
        }
        self.0 .0 = self.0 .0.add_tweak(tweak)?;
        Ok(self)
    }

    /// Returns the [`SecretKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`SecretKey::from_keypair`].
    #[inline]
    pub fn secret_key(&self) -> SecretKey { SecretKey::from_keypair(self) }

    /// Returns the [`PublicKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`PublicKey::from_keypair`].
    #[inline]
    pub fn public_key(&self) -> PublicKey { PublicKey::from_keypair(self) }

    /// Returns the [`XOnlyPublicKey`] (and it's [`Parity`]) for this [`Keypair`].
    ///
    /// This is equivalent to using [`XOnlyPublicKey::from_keypair`].
    #[inline]
    pub fn x_only_public_key(&self) -> (XOnlyPublicKey, Parity) {
        XOnlyPublicKey::from_keypair(self)
    }
}

impl From<Keypair> for SecretKey {
    #[inline]
    fn from(pair: Keypair) -> Self { SecretKey::from_keypair(&pair) }
}

impl<'a> From<&'a Keypair> for SecretKey {
    #[inline]
    fn from(pair: &'a Keypair) -> Self { SecretKey::from_keypair(pair) }
}

impl From<Keypair> for PublicKey {
    #[inline]
    fn from(pair: Keypair) -> Self { PublicKey::from_keypair(&pair) }
}

impl<'a> From<&'a Keypair> for PublicKey {
    #[inline]
    fn from(pair: &'a Keypair) -> Self { PublicKey::from_keypair(pair) }
}

impl str::FromStr for Keypair {
    type Err = Error;

    #[allow(unused_variables, unreachable_code)] // When built with no default features.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ctx = Secp256k1::signing_only();

        #[allow(clippy::needless_borrow)]
        Keypair::from_seckey_str(&ctx, s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Keypair {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
            s.serialize_str(
                crate::to_hex(&self.secret_bytes(), &mut buf)
                    .expect("fixed-size hex serialization"),
            )
        } else {
            let mut tuple = s.serialize_tuple(constants::SECRET_KEY_SIZE)?;
            for byte in self.secret_bytes().iter() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
#[allow(unused_variables)] // For `data` under some feature combinations (the unconditional panic below).
#[allow(unreachable_code)] // For `Keypair::from_seckey_slice` after unconditional panic.
impl<'de> serde::Deserialize<'de> for Keypair {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte Keypair",
            ))
        } else {
            let visitor = super::serde_util::Tuple32Visitor::new("raw 32 bytes Keypair", |data| {
                #[cfg(feature = "alloc")]
                let ctx = Secp256k1::signing_only();

                #[cfg(not(feature = "alloc"))]
                let ctx: Secp256k1<crate::SignOnlyPreallocated> = panic!("cannot deserialize key pair without a context (please enable the alloc feature)");

                #[allow(clippy::needless_borrow)]
                Keypair::from_seckey_slice(&ctx, data)
            });
            d.deserialize_tuple(constants::SECRET_KEY_SIZE, visitor)
        }
    }
}

/// An x-only public key, used for verification of Taproot signatures and serialized according to BIP-340.
///
/// # Serde support
///
/// Implements de/serialization with the `serde` feature enabled. We treat the byte value as a tuple
/// of 32 `u8`s for non-human-readable formats. This representation is optimal for for some formats
/// (e.g. [`bincode`]) however other formats may be less optimal (e.g. [`cbor`]).
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # #[cfg(feature =  "rand-std")] {
/// use secp256k1::{rand, Secp256k1, Keypair, XOnlyPublicKey};
///
/// let secp = Secp256k1::new();
/// let keypair = Keypair::new(&secp, &mut rand::thread_rng());
/// let xonly = XOnlyPublicKey::from_keypair(&keypair);
/// # }
/// ```
/// [`bincode`]: https://docs.rs/bincode
/// [`cbor`]: https://docs.rs/cbor
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct XOnlyPublicKey([u8; 32]); // TODO: use a better type

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ser = self.serialize();
        for ch in &ser[..] {
            write!(f, "{:02x}", *ch)?;
        }
        Ok(())
    }
}

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(self, f) }
}

impl str::FromStr for XOnlyPublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<XOnlyPublicKey, Error> {
        let mut res = [0u8; constants::SCHNORR_PUBLIC_KEY_SIZE];
        match from_hex(s, &mut res) {
            Ok(constants::SCHNORR_PUBLIC_KEY_SIZE) =>
                XOnlyPublicKey::from_slice(&res[0..constants::SCHNORR_PUBLIC_KEY_SIZE]),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl XOnlyPublicKey {
    /// Returns the [`XOnlyPublicKey`] (and it's [`Parity`]) for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> (XOnlyPublicKey, Parity) {
        keypair.public_key().x_only_public_key()
    }

    /// Creates a schnorr public key directly from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the length of the data slice is not 32 bytes or the
    /// slice does not represent a valid Secp256k1 point x coordinate.
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<XOnlyPublicKey, Error> {
        if data.is_empty() || data.len() != constants::SCHNORR_PUBLIC_KEY_SIZE {
            return Err(Error::InvalidPublicKey);
        }

        match <[u8; constants::SCHNORR_PUBLIC_KEY_SIZE]>::try_from(data) {
            Ok(data) => {
                // check if the key is valid, like in the original implementation
                // a key is valid if it is in the range [1, n - 1] where n is the order of the curve
                if data == crate::constants::ZERO || !data.lt(&crate::constants::CURVE_ORDER) {
                    return Err(InvalidPublicKey);
                }

                // check if the x coordinate is on the curve
                let x_bn = BigNumMod::<32, P>::from_be_bytes_noreduce(data);
                let _ = secp256k1_compute_y(&x_bn)?;

                Ok(XOnlyPublicKey(data))
            }
            Err(_) => Err(InvalidPublicKey),
        }
    }

    #[inline]
    /// Serializes the key as a byte-encoded x coordinate value (32 bytes).
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] { self.0 }

    /// Tweaks an [`XOnlyPublicKey`] by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// The newly tweaked key plus an opaque type representing the parity of the tweaked key, this
    /// should be provided to `tweak_add_check` which can be used to verify a tweak more efficiently
    /// than regenerating it and checking equality.
    ///
    /// # Errors
    ///
    /// If the resulting key would be invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{Secp256k1, Keypair, Scalar, XOnlyPublicKey};
    ///
    /// let secp = Secp256k1::new();
    /// let tweak = Scalar::random();
    ///
    /// let mut keypair = Keypair::new(&secp, &mut rand::thread_rng());
    /// let (xonly, _parity) = keypair.x_only_public_key();
    /// let tweaked = xonly.add_tweak(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// # }
    /// ```
    // NOTE: due to a limitation of Vanadium SDK, this currently panics instead of returning an error if the
    //       tweak equals the negation of the secret key.
    pub fn add_tweak<V: Verification>(
        mut self,
        _secp: &Secp256k1<V>,
        tweak: &Scalar,
    ) -> Result<(XOnlyPublicKey, Parity), Error> {
        let tweak_point: sdk::curve::Point<sdk::curve::Secp256k1, 32> = &G * &tweak.as_be_bytes();

        let x_bn = BigNumMod::<32, P>::from_be_bytes_noreduce(self.0);
        let y = secp256k1_compute_y_with_parity(&x_bn, 0)?;
        let tweaked = &Secp256k1Point::new(x_bn.to_be_bytes(), y.to_be_bytes()) + &tweak_point;
        let parity = Parity::from_u8(tweaked.y[31] & 1).unwrap();

        self.0 = tweaked.x;

        Ok((self, parity))
    }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::add_tweak`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key and output parity from
    /// [`XOnlyPublicKey::add_tweak`] as input.
    ///
    /// Currently this is not much more efficient than just recomputing the tweak and checking
    /// equality. However, in future this API will support batch verification, which is
    /// significantly faster, so it is wise to design protocols with this in mind.
    ///
    /// # Returns
    ///
    /// True if tweak and check is successful, false otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature =  "rand-std")] {
    /// use secp256k1::{Secp256k1, Keypair, Scalar};
    ///
    /// let secp = Secp256k1::new();
    /// let tweak = Scalar::random();
    ///
    /// let mut keypair = Keypair::new(&secp, &mut rand::thread_rng());
    /// let (mut public_key, _) = keypair.x_only_public_key();
    /// let original = public_key;
    /// let (tweaked, parity) = public_key.add_tweak(&secp, &tweak).expect("Improbable to fail with a randomly generated tweak");
    /// assert!(original.tweak_add_check(&secp, &tweaked, parity, tweak));
    /// # }
    /// ```
    // NOTE: due to a limitation of Vanadium SDK, this currently panics instead of returning an error if the
    //       tweak equals the negation of the secret key.
    pub fn tweak_add_check<V: Verification>(
        &self,
        _secp: &Secp256k1<V>,
        tweaked_key: &Self,
        tweaked_parity: Parity,
        tweak: Scalar,
    ) -> bool {
        let Ok((tweaked_result, parity_result)) = self.add_tweak(_secp, &tweak) else {
            return false;
        };
        tweaked_result == *tweaked_key && parity_result == tweaked_parity
    }

    /// Returns the [`PublicKey`] for this [`XOnlyPublicKey`].
    ///
    /// This is equivalent to using [`PublicKey::from_xonly_and_parity(self, parity)`].
    #[inline]
    pub fn public_key(&self, parity: Parity) -> PublicKey {
        PublicKey::from_x_only_public_key(*self, parity)
    }

    /// Checks that `sig` is a valid schnorr signature for `msg` using this public key.
    pub fn verify<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: &Message,
        sig: &schnorr::Signature,
    ) -> Result<(), Error> {
        secp.verify_schnorr(sig, msg, self)
    }
}

/// Represents the parity passed between FFI function calls.
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Parity {
    /// Even parity.
    Even = 0,
    /// Odd parity.
    Odd = 1,
}

impl Parity {
    /// Converts parity into an integer (byte) value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_u8(self) -> u8 { self as u8 }

    /// Converts parity into an integer value.
    ///
    /// This returns `0` for even parity and `1` for odd parity.
    pub fn to_i32(self) -> i32 { self as i32 }

    /// Constructs a [`Parity`] from a byte.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_u8(parity: u8) -> Result<Parity, InvalidParityValue> {
        Parity::from_i32(parity.into())
    }

    /// Constructs a [`Parity`] from a signed integer.
    ///
    /// The only allowed values are `0` meaning even parity and `1` meaning odd.
    /// Other values result in error being returned.
    pub fn from_i32(parity: i32) -> Result<Parity, InvalidParityValue> {
        match parity {
            0 => Ok(Parity::Even),
            1 => Ok(Parity::Odd),
            _ => Err(InvalidParityValue(parity)),
        }
    }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<i32> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: i32) -> Result<Self, Self::Error> { Self::from_i32(parity) }
}

/// `Even` for `0`, `Odd` for `1`, error for anything else
impl TryFrom<u8> for Parity {
    type Error = InvalidParityValue;

    fn try_from(parity: u8) -> Result<Self, Self::Error> { Self::from_u8(parity) }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for i32 {
    fn from(parity: Parity) -> i32 { parity.to_i32() }
}

/// The conversion returns `0` for even parity and `1` for odd.
impl From<Parity> for u8 {
    fn from(parity: Parity) -> u8 { parity.to_u8() }
}

/// Returns even parity if the operands are equal, odd otherwise.
impl BitXor for Parity {
    type Output = Parity;

    fn bitxor(self, rhs: Parity) -> Self::Output {
        // This works because Parity has only two values (i.e. only 1 bit of information).
        if self == rhs {
            Parity::Even // 1^1==0 and 0^0==0
        } else {
            Parity::Odd // 1^0==1 and 0^1==1
        }
    }
}

/// Error returned when conversion from an integer to `Parity` fails.
//
// Note that we don't allow inspecting the value because we may change the type.
// Yes, this comment is intentionally NOT doc comment.
// Too many derives for compatibility with current Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct InvalidParityValue(i32);

impl fmt::Display for InvalidParityValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value {} for Parity - must be 0 or 1", self.0)
    }
}

impl From<InvalidParityValue> for Error {
    fn from(error: InvalidParityValue) -> Self { Error::InvalidParityValue(error) }
}

/// The parity is serialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl serde::Serialize for Parity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(self.to_u8())
    }
}

/// The parity is deserialized as `u8` - `0` for even, `1` for odd.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Parity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Parity;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("8-bit integer (byte) with value 0 or 1")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use serde::de::Unexpected;

                Parity::from_u8(v)
                    .map_err(|_| E::invalid_value(Unexpected::Unsigned(v.into()), &"0 or 1"))
            }
        }

        d.deserialize_u8(Visitor)
    }
}

impl From<PublicKey> for XOnlyPublicKey {
    fn from(src: PublicKey) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&src.0.x).expect("This should never fail")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for XOnlyPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            let mut tuple = s.serialize_tuple(constants::SCHNORR_PUBLIC_KEY_SIZE)?;
            for byte in self.serialize().iter() {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for XOnlyPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(super::serde_util::FromStrVisitor::new(
                "a hex string representing 32 byte schnorr public key",
            ))
        } else {
            let visitor = super::serde_util::Tuple32Visitor::new(
                "raw 32 bytes schnorr public key",
                XOnlyPublicKey::from_slice,
            );
            d.deserialize_tuple(constants::SCHNORR_PUBLIC_KEY_SIZE, visitor)
        }
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod test {
    use core::str::FromStr;

    use serde_test::{Configure, Token};
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::{Keypair, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey, *};
    use crate::Error::{InvalidPublicKey, InvalidSecretKey};
    use crate::{constants, from_hex, to_hex, Scalar};

    #[cfg(not(secp256k1_fuzz))]
    macro_rules! hex {
        ($hex:expr) => {{
            let mut result = vec![0; $hex.len() / 2];
            from_hex($hex, &mut result).expect("valid hex string");
            result
        }};
    }

    #[test]
    fn skey_from_slice() {
        let sk = SecretKey::from_slice(&[1; 31]);
        assert_eq!(sk, Err(InvalidSecretKey));

        let sk = SecretKey::from_slice(&[1; 32]);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&[1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed = PublicKey::from_slice(&[
            4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85,
            220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124,
            149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195,
            155, 51, 247, 123, 113, 60, 228, 188,
        ]);
        assert!(uncompressed.is_ok());

        let compressed = PublicKey::from_slice(&[
            3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41,
            111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78,
        ]);
        assert!(compressed.is_ok());
    }

    #[test]
    #[rustfmt::skip]
    fn invalid_secret_key() {
        // Zero
        assert_eq!(SecretKey::from_slice(&[0; 32]), Err(InvalidSecretKey));
        assert_eq!(
            SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000000"),
            Err(InvalidSecretKey)
        );
        // -1
        assert_eq!(SecretKey::from_slice(&[0xff; 32]), Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40,
        ]).is_ok());
        // One past top of range
        assert!(SecretKey::from_slice(&[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ]).is_err());
    }

    #[test]
    fn test_pubkey_from_bad_slice() {
        // Bad sizes
        assert_eq!(
            PublicKey::from_slice(&[0; constants::PUBLIC_KEY_SIZE - 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::PUBLIC_KEY_SIZE + 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE - 1]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 1]),
            Err(InvalidPublicKey)
        );

        // Bad parse
        assert_eq!(
            PublicKey::from_slice(&[0xff; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        assert_eq!(
            PublicKey::from_slice(&[0x55; constants::PUBLIC_KEY_SIZE]),
            Err(InvalidPublicKey)
        );
        assert_eq!(PublicKey::from_slice(&[]), Err(InvalidPublicKey));
    }

    #[test]
    fn test_seckey_from_bad_slice() {
        // Bad sizes
        assert_eq!(
            SecretKey::from_slice(&[0; constants::SECRET_KEY_SIZE - 1]),
            Err(InvalidSecretKey)
        );
        assert_eq!(
            SecretKey::from_slice(&[0; constants::SECRET_KEY_SIZE + 1]),
            Err(InvalidSecretKey)
        );
        // Bad parse
        assert_eq!(
            SecretKey::from_slice(&[0xff; constants::SECRET_KEY_SIZE]),
            Err(InvalidSecretKey)
        );
        assert_eq!(
            SecretKey::from_slice(&[0x00; constants::SECRET_KEY_SIZE]),
            Err(InvalidSecretKey)
        );
        assert_eq!(SecretKey::from_slice(&[]), Err(InvalidSecretKey));
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_display_output() {
        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
        ];

        #[cfg(not(secp256k1_fuzz))]
        let s = Secp256k1::signing_only();
        let sk = SecretKey::from_slice(&SK_BYTES).expect("sk");

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the expected result.
        #[cfg(not(secp256k1_fuzz))]
        let pk = PublicKey::from_secret_key(&s, &sk);
        #[cfg(secp256k1_fuzz)]
        let pk = PublicKey::from_slice(&[
            0x02, 0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f, 0x1c, 0x97, 0x09, 0xe2, 0x30,
            0x92, 0x06, 0x7d, 0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54, 0x4a, 0xc8, 0x87,
            0xfe, 0x91, 0xdd, 0xd1, 0x66,
        ])
        .expect("pk");

        assert_eq!(
            sk.display_secret().to_string(),
            "01010101010101010001020304050607ffff0000ffff00006363636363636363"
        );
        assert_eq!(
            SecretKey::from_str("01010101010101010001020304050607ffff0000ffff00006363636363636363")
                .unwrap(),
            sk
        );
        assert_eq!(
            pk.to_string(),
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
        );
        assert_eq!(
            PublicKey::from_str(
                "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166"
            )
            .unwrap(),
            pk
        );
        assert_eq!(
            PublicKey::from_str(
                "04\
                18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166\
                84B84DB303A340CD7D6823EE88174747D12A67D2F8F2F9BA40846EE5EE7A44F6"
            )
            .unwrap(),
            pk
        );

        assert!(SecretKey::from_str(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff0000636363636363636363"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff0000636363636363636"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff000063636363636363"
        )
        .is_err());
        assert!(SecretKey::from_str(
            "01010101010101010001020304050607ffff0000ffff000063636363636363xx"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0300000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16601"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd16"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1"
        )
        .is_err());
        assert!(PublicKey::from_str(
            "xx0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd1"
        )
        .is_err());

        let long_str = "a".repeat(1024 * 1024);
        assert!(SecretKey::from_str(&long_str).is_err());
        assert!(PublicKey::from_str(&long_str).is_err());
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn pubkey_combine() {
        let compressed1 = PublicKey::from_slice(&hex!(
            "0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"
        ))
        .unwrap();
        let compressed2 = PublicKey::from_slice(&hex!(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
        ))
        .unwrap();
        let exp_sum = PublicKey::from_slice(&hex!(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07"
        ))
        .unwrap();

        let sum1 = compressed1.combine(&compressed2);
        assert!(sum1.is_ok());
        let sum2 = compressed2.combine(&compressed1);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn pubkey_combine_keys() {
        let compressed1 = PublicKey::from_slice(&hex!(
            "0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"
        ))
        .unwrap();
        let compressed2 = PublicKey::from_slice(&hex!(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
        ))
        .unwrap();
        let compressed3 = PublicKey::from_slice(&hex!(
            "03e74897d8644eb3e5b391ca2ab257aec2080f4d1a95cad57e454e47f021168eb0"
        ))
        .unwrap();
        let exp_sum = PublicKey::from_slice(&hex!(
            "0252d73a47f66cf341e5651542f0348f452b7c793af62a6d8bff75ade703a451ad"
        ))
        .unwrap();

        let sum1 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
        assert!(sum1.is_ok());
        let sum2 = PublicKey::combine_keys(&[&compressed1, &compressed2, &compressed3]);
        assert!(sum2.is_ok());
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.unwrap(), exp_sum);
    }

    #[test]
    #[cfg(not(secp256k1_fuzz))]
    fn pubkey_combine_keys_empty_slice() {
        assert!(PublicKey::combine_keys(&[]).is_err());
    }

    #[cfg(not(secp256k1_fuzz))]
    #[test]
    #[allow(clippy::nonminimal_bool)]
    fn pubkey_equal() {
        let pk1 = PublicKey::from_slice(&hex!(
            "0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba"
        ))
        .unwrap();
        let pk2 = pk1;
        let pk3 = PublicKey::from_slice(&hex!(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443"
        ))
        .unwrap();

        assert_eq!(pk1, pk2);
        assert!(pk1 <= pk2);
        assert!(pk2 <= pk1);
        assert!(!(pk2 < pk1));
        assert!(!(pk1 < pk2));

        assert!(pk3 > pk1);
        assert!(pk1 < pk3);
        assert!(pk3 >= pk1);
        assert!(pk1 <= pk3);
    }

    #[test]
    #[cfg(all(feature = "serde", feature = "alloc"))]
    fn test_serde() {
        use serde_test::{assert_tokens, Configure, Token};
        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            1, 1, 1, 1, 1, 1, 1, 1,
            0, 1, 2, 3, 4, 5, 6, 7,
            0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
            99, 99, 99, 99, 99, 99, 99, 99
        ];
        static SK_STR: &str = "01010101010101010001020304050607ffff0000ffff00006363636363636363";

        #[cfg(secp256k1_fuzz)]
        #[rustfmt::skip]
        static PK_BYTES: [u8; 33] = [
            0x02,
            0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
            0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
            0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
            0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66,
        ];
        static PK_STR: &str = "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";

        #[cfg(not(secp256k1_fuzz))]
        let s = Secp256k1::new();
        let sk = SecretKey::from_slice(&SK_BYTES).unwrap();

        // In fuzzing mode secret->public key derivation is different, so
        // hard-code the expected result.
        #[cfg(not(secp256k1_fuzz))]
        let pk = PublicKey::from_secret_key(&s, &sk);
        #[cfg(secp256k1_fuzz)]
        let pk = PublicKey::from_slice(&PK_BYTES).expect("pk");

        #[rustfmt::skip]
        assert_tokens(&sk.compact(), &[
            Token::Tuple{ len: 32 },
            Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1), Token::U8(1),
            Token::U8(0), Token::U8(1), Token::U8(2), Token::U8(3), Token::U8(4), Token::U8(5), Token::U8(6), Token::U8(7),
            Token::U8(0xff), Token::U8(0xff), Token::U8(0), Token::U8(0), Token::U8(0xff), Token::U8(0xff), Token::U8(0), Token::U8(0),
            Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99), Token::U8(99),
            Token::TupleEnd
        ]);

        assert_tokens(&sk.readable(), &[Token::BorrowedStr(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::Str(SK_STR)]);
        assert_tokens(&sk.readable(), &[Token::String(SK_STR)]);

        #[rustfmt::skip]
        assert_tokens(&pk.compact(), &[
            Token::Tuple{ len: 33 },
            Token::U8(0x02),
            Token::U8(0x18), Token::U8(0x84), Token::U8(0x57), Token::U8(0x81), Token::U8(0xf6), Token::U8(0x31), Token::U8(0xc4), Token::U8(0x8f),
            Token::U8(0x1c), Token::U8(0x97), Token::U8(0x09), Token::U8(0xe2), Token::U8(0x30), Token::U8(0x92), Token::U8(0x06), Token::U8(0x7d),
            Token::U8(0x06), Token::U8(0x83), Token::U8(0x7f), Token::U8(0x30), Token::U8(0xaa), Token::U8(0x0c), Token::U8(0xd0), Token::U8(0x54),
            Token::U8(0x4a), Token::U8(0xc8), Token::U8(0x87), Token::U8(0xfe), Token::U8(0x91), Token::U8(0xdd), Token::U8(0xd1), Token::U8(0x66),
            Token::TupleEnd
        ]);

        assert_tokens(&pk.readable(), &[Token::BorrowedStr(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::Str(PK_STR)]);
        assert_tokens(&pk.readable(), &[Token::String(PK_STR)]);
    }

    #[test]
    fn test_from_key_pubkey() {
        let kpk1 = PublicKey::from_str(
            "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
        )
        .unwrap();
        let kpk2 = PublicKey::from_str(
            "0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07",
        )
        .unwrap();

        let pk1 = XOnlyPublicKey::from(kpk1);
        let pk2 = XOnlyPublicKey::from(kpk2);

        assert_eq!(pk1.serialize()[..], kpk1.serialize()[1..]);
        assert_eq!(pk2.serialize()[..], kpk2.serialize()[1..]);
    }

    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn keys() -> (SecretKey, PublicKey, Keypair, XOnlyPublicKey) {
        let secp = Secp256k1::new();

        #[rustfmt::skip]
        static SK_BYTES: [u8; 32] = [
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
            0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
        ];

        #[rustfmt::skip]
        static PK_BYTES: [u8; 32] = [
            0x18, 0x84, 0x57, 0x81, 0xf6, 0x31, 0xc4, 0x8f,
            0x1c, 0x97, 0x09, 0xe2, 0x30, 0x92, 0x06, 0x7d,
            0x06, 0x83, 0x7f, 0x30, 0xaa, 0x0c, 0xd0, 0x54,
            0x4a, 0xc8, 0x87, 0xfe, 0x91, 0xdd, 0xd1, 0x66
        ];

        let mut pk_bytes = [0u8; 33];
        pk_bytes[0] = 0x02; // Use positive Y co-ordinate.
        pk_bytes[1..].clone_from_slice(&PK_BYTES);

        let sk = SecretKey::from_slice(&SK_BYTES).expect("failed to parse sk bytes");
        let pk = PublicKey::from_slice(&pk_bytes).expect("failed to create pk from iterator");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let xonly = XOnlyPublicKey::from_slice(&PK_BYTES).expect("failed to get xonly from slice");

        (sk, pk, kp, xonly)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_public_key_to_xonly_public_key() {
        let (_sk, pk, _kp, want) = keys();
        let (got, parity) = pk.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_secret_key_to_public_key() {
        let secp = Secp256k1::new();

        let (sk, want, _kp, _xonly) = keys();
        let got = sk.public_key(&secp);

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_secret_key_to_x_only_public_key() {
        let secp = Secp256k1::new();

        let (sk, _pk, _kp, want) = keys();
        let (got, parity) = sk.x_only_public_key(&secp);

        assert_eq!(parity, Parity::Even);
        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_keypair_to_public_key() {
        let (_sk, want, kp, _xonly) = keys();
        let got = kp.public_key();

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn convert_keypair_to_x_only_public_key() {
        let (_sk, _pk, kp, want) = keys();
        let (got, parity) = kp.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(got, want)
    }

    // SecretKey -> Keypair -> SecretKey
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_secret_key_via_keypair() {
        let secp = Secp256k1::new();
        let (sk, _pk, _kp, _xonly) = keys();

        let kp = sk.keypair(&secp);
        let back = kp.secret_key();

        assert_eq!(back, sk)
    }

    // Keypair -> SecretKey -> Keypair
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_keypair_via_secret_key() {
        let secp = Secp256k1::new();
        let (_sk, _pk, kp, _xonly) = keys();

        let sk = kp.secret_key();
        let back = sk.keypair(&secp);

        assert_eq!(back, kp)
    }

    // XOnlyPublicKey -> PublicKey -> XOnlyPublicKey
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_x_only_public_key_via_public_key() {
        let (_sk, _pk, _kp, xonly) = keys();

        let pk = xonly.public_key(Parity::Even);
        let (back, parity) = pk.x_only_public_key();

        assert_eq!(parity, Parity::Even);
        assert_eq!(back, xonly)
    }

    // PublicKey -> XOnlyPublicKey -> PublicKey
    #[test]
    #[cfg(all(not(secp256k1_fuzz), feature = "alloc"))]
    fn roundtrip_public_key_via_x_only_public_key() {
        let (_sk, pk, _kp, _xonly) = keys();

        let (xonly, parity) = pk.x_only_public_key();
        let back = xonly.public_key(parity);

        assert_eq!(back, pk)
    }

    #[test]
    fn public_key_from_x_only_public_key_and_odd_parity() {
        let s = "18845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166";
        let mut want = String::from("03");
        want.push_str(s);

        let xonly = XOnlyPublicKey::from_str(s).expect("failed to parse xonly pubkey string");
        let pk = xonly.public_key(Parity::Odd);
        let got = format!("{}", pk);

        assert_eq!(got, want)
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "serde"))]
    fn test_keypair_deserialize_serde() {
        let ctx = crate::Secp256k1::new();
        let sec_key_str = "4242424242424242424242424242424242424242424242424242424242424242";
        let keypair = Keypair::from_seckey_str(&ctx, sec_key_str).unwrap();

        serde_test::assert_tokens(&keypair.readable(), &[Token::String(sec_key_str)]);

        let sec_key_bytes = keypair.secret_key().secret_bytes();
        let tokens = std::iter::once(Token::Tuple { len: 32 })
            .chain(sec_key_bytes.iter().copied().map(Token::U8))
            .chain(std::iter::once(Token::TupleEnd))
            .collect::<Vec<_>>();
        serde_test::assert_tokens(&keypair.compact(), &tokens);
    }
}

#[cfg(bench)]
mod benches {
    use std::collections::BTreeSet;

    use test::Bencher;

    use crate::constants::GENERATOR_X;
    use crate::PublicKey;

    #[bench]
    fn bench_pk_ordering(b: &mut Bencher) {
        let mut map = BTreeSet::new();
        let mut g_slice = [02u8; 33];
        g_slice[1..].copy_from_slice(&GENERATOR_X);
        let g = PublicKey::from_slice(&g_slice).unwrap();
        let mut pk = g;
        b.iter(|| {
            map.insert(pk);
            pk = pk.combine(&pk).unwrap();
        })
    }
}
