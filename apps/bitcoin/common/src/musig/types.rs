//! Public types for the MuSig2 module.

use core::fmt;

use sdk::curve::Secp256k1Point;
use zeroize::Zeroize;

use super::MUSIG_PUBNONCE_SIZE;

/// A 33-byte SEC1 compressed public key.
pub type PlainPk = [u8; 33];
/// A 32-byte BIP-340 x-only public key.
pub type XOnlyPk = [u8; 32];

/// Output of the BIP-327 KeyAgg algorithm. Holds the aggregate point `Q`
/// together with the accumulators `gacc`, `tacc` that track sign-flips and
/// additive tweaks applied to it.
#[derive(Debug)]
pub struct KeyAggContext {
    pub(crate) q: Secp256k1Point,
    pub(crate) gacc: [u8; 32],
    pub(crate) tacc: [u8; 32],
}

impl KeyAggContext {
    /// Aggregate public key in uncompressed form.
    pub fn aggregate_point(&self) -> &Secp256k1Point {
        &self.q
    }
}

/// A 66-byte public nonce: two compressed points `R_s1 || R_s2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PubNonce(pub [u8; MUSIG_PUBNONCE_SIZE]);

impl PubNonce {
    pub fn as_bytes(&self) -> &[u8; MUSIG_PUBNONCE_SIZE] {
        &self.0
    }
}

/// A MuSig2 secret nonce: two scalars `k1`, `k2` plus the associated public key.
///
/// `SecNonce` is consumed by `sign()`; its contents are zeroized on drop so
/// that reuse is impossible.
pub struct SecNonce {
    k1: [u8; 32],
    k2: [u8; 32],
    pk: PlainPk,
}

impl SecNonce {
    pub(crate) fn new(k1: [u8; 32], k2: [u8; 32], pk: PlainPk) -> Self {
        Self { k1, k2, pk }
    }

    /// Moves the inner secret material out of `self`. The caller is responsible
    /// for zeroizing the returned `(k1, k2)` arrays once done; `pk` is public.
    pub(crate) fn into_parts(mut self) -> ([u8; 32], [u8; 32], PlainPk) {
        let k1 = core::mem::take(&mut self.k1);
        let k2 = core::mem::take(&mut self.k2);
        let pk = self.pk;
        // self will be dropped below; explicit zeroize is unnecessary because
        // we already moved-out via core::mem::take, which leaves zeros behind.
        (k1, k2, pk)
    }
}

impl Drop for SecNonce {
    fn drop(&mut self) {
        self.k1.zeroize();
        self.k2.zeroize();
        // pk is not secret; no need to scrub.
    }
}

impl fmt::Debug for SecNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecNonce")
            .field("k1", &"[REDACTED]")
            .field("k2", &"[REDACTED]")
            .field("pk", &self.pk)
            .finish()
    }
}

/// Session context for partial signing.
///
/// Borrows all of its inputs; the caller assembles them once per
/// (input, message) pair and passes them to [`crate::musig::sign`].
pub struct SessionContext<'a> {
    pub aggnonce: &'a PubNonce,
    pub pubkeys: &'a [PlainPk],
    pub tweaks: &'a [[u8; 32]],
    pub is_xonly: &'a [bool],
    pub msg: &'a [u8],
}

/// Errors produced by the BIP-327 primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MusigError {
    /// A 33-byte input was not a valid SEC1 compressed point on the curve.
    InvalidPoint,
    /// `key_agg` / `nonce_agg` was called with an empty list.
    EmptyPubkeyList,
    /// The KeyAgg sum collapsed to the point at infinity (vanishingly unlikely
    /// for honestly-chosen inputs).
    KeyAggInfinity,
    /// Two independent `H_nonce` outputs collapsed to zero (vanishingly unlikely).
    NonceGenFailed,
    /// `nonce_agg` got a malformed contribution from this signer index.
    InvalidContribution(usize),
    /// A tweak was >= n.
    TweakOutOfRange,
    /// Applying a tweak produced the point at infinity.
    TweakInfinity,
    /// `sign` was called for a pubkey not in the session's `pubkeys` list.
    PubkeyNotInList,
    /// A `k1` or `k2` from `secnonce` was zero or >= n.
    NonceOutOfRange,
    /// `sk` was zero or >= n.
    SecretKeyOutOfRange,
    /// The pubkey derived from `sk` doesn't match the one stored in `secnonce`.
    PubkeyMismatch,
    /// BIP-32 unhardened CKDpub failed (hardened index passed, or HMAC produced
    /// a tweak >= n, or the tweaked point was infinity).
    DerivationFailed,
}
