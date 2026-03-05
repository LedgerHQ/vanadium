use core::fmt;
use core::marker::PhantomData;

use bitcoin::hashes::{Hash, HashEngine, Hmac, HmacEngine};
use subtle::ConstantTimeEq;

// m/POR_MAGIC computed with SLIP21 is the hmac key for Proofs of Registration.
const POR_MAGIC: &[u8] = b"Proof of Registration";

/// A trait for types that can produce a typed registration ID and therefore
/// participate in proof-of-registration flows.
///
/// Each implementer carries an associated `Context` type that supplies any
/// additional data needed to derive the ID (e.g. a name for named accounts).
///
/// The blanket impl for all [`Account`](crate::account::Account) types provides
/// this automatically with `Context = str`.
pub trait Registerable: Sized {
    /// Additional context required to compute the registration ID.
    type Context: ?Sized;

    /// Compute the registration ID for this object, given the context.
    fn registration_id(&self, ctx: &Self::Context) -> RegistrationId<Self>;
}

/// A typed 32-byte identifier for an object of type `T`.
///
/// Two `RegistrationId`s are only comparable when they refer to the same type,
/// preventing accidental mix-ups at compile time.
pub struct RegistrationId<T: ?Sized> {
    bytes: [u8; 32],
    _marker: PhantomData<fn() -> T>,
}

impl<T: ?Sized> RegistrationId<T> {
    /// Wrap raw bytes into a typed ID.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl<T: ?Sized> Clone for RegistrationId<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for RegistrationId<T> {}

impl<T: ?Sized> fmt::Debug for RegistrationId<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RegistrationId").field(&self.bytes).finish()
    }
}

impl<T: ?Sized> PartialEq for RegistrationId<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T: ?Sized> Eq for RegistrationId<T> {}

/// A proof-of-registration for an object of type `T`.
///
/// Uses constant-time comparison to prevent timing attacks.
///
/// Two `ProofOfRegistration`s are only comparable when they refer to the
/// same type, making it impossible to accidentally compare proofs for
/// different kinds of objects.
#[repr(transparent)]
pub struct ProofOfRegistration<T: ?Sized> {
    bytes: [u8; 32],
    _marker: PhantomData<fn() -> T>,
}

impl<T: ?Sized> Clone for ProofOfRegistration<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for ProofOfRegistration<T> {}

impl<T: ?Sized> fmt::Debug for ProofOfRegistration<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProofOfRegistration")
            .field(&self.bytes)
            .finish()
    }
}

impl<T: ?Sized> PartialEq for ProofOfRegistration<T> {
    /// Uses constant-time comparison to prevent timing attacks.
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<T: ?Sized> Eq for ProofOfRegistration<T> {}

impl<T: ?Sized> ProofOfRegistration<T> {
    /// Compute the proof of registration for a given registration ID.
    ///
    /// The proof is an HMAC-SHA256 of the ID bytes, keyed with a
    /// SLIP-21-derived key at path `m/"Proof of Registration"`.
    #[cfg(any(feature = "target_native", feature = "target_vanadium_ledger"))]
    pub fn new(id: &RegistrationId<T>) -> Self {
        let por_key = sdk::slip21::derive_slip21_key(&[&POR_MAGIC]);

        let mut mac =
            HmacEngine::<bitcoin::hashes::sha256::Hash>::new(por_key.dangerous_as_raw_bytes());
        mac.input(id.as_bytes());
        Self {
            bytes: Hmac::<bitcoin::hashes::sha256::Hash>::from_engine(mac).to_byte_array(),
            _marker: PhantomData,
        }
    }

    /// Wrap raw bytes received over the wire into a typed proof.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Returns the raw bytes of the proof of registration.
    ///
    /// This is necessary for example to serialize and return the proof externally. However,
    /// it is generally dangerous to use the serialized form of proofs of registrations, as
    /// incorrect use might lead to side-channel attacks.
    ///
    /// In order to verify the proof, build a new instance using the `from_bytes` method
    /// before comparing it with the expected proof.
    pub fn dangerous_as_bytes(&self) -> [u8; 32] {
        self.bytes
    }
}
