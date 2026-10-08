//! BIP-327 (MuSig2) primitives.
//!
//! Port of `src/musig/musig.c` from the C reference Ledger Bitcoin app,
//! adapted to the Vanadium app SDK. The module exposes four public functions
//! that mirror the C API one-to-one: [`key_agg`], [`nonce_gen`], [`nonce_agg`],
//! [`sign`]. Helpers are kept private.

mod types;

use bitcoin::bip32::{ChainCode, ChildNumber, Xpub};
use bitcoin::secp256k1;
use hashes::{sha256t_hash_newtype, Hash, HashEngine};
use sdk::curve::{EcfpPublicKey, Secp256k1, Secp256k1Point, Secp256k1Scalar};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use alloc::vec::Vec;

pub use types::{KeyAggContext, MusigError, PlainPk, PubNonce, SecNonce, SessionContext, XOnlyPk};

/// Size of a public nonce in bytes (two compressed points).
pub const MUSIG_PUBNONCE_SIZE: usize = 66;

/// The fixed chaincode used by BIP-388 when forming a synthetic xpub from a
/// MuSig2 aggregate public key. Defined in BIP-328.
pub const BIP_328_CHAINCODE: [u8; 32] = [
    0x86, 0x80, 0x87, 0xCA, 0x02, 0xA6, 0xF9, 0x74, 0xC4, 0x59, 0x89, 0x24, 0xC3, 0x6B, 0x57, 0x76,
    0x2D, 0x32, 0xCB, 0x45, 0x71, 0x71, 0x67, 0xE3, 0x00, 0x62, 0x2C, 0x71, 0x67, 0xE3, 0x89, 0x65,
];

// BIP-327 / BIP-340 tagged hashes. The `sha256t_hash_newtype!` macro lives in
// `bitcoin_hashes` and produces SHA-256 engines pre-fed with `H(tag) || H(tag)`.
sha256t_hash_newtype! {
    pub struct KeyAggListTag = hash_str("KeyAgg list");
    pub struct KeyAggListHash(_);

    pub struct KeyAggCoeffTag = hash_str("KeyAgg coefficient");
    pub struct KeyAggCoeffHash(_);

    pub struct MuSigNonceTag = hash_str("MuSig/nonce");
    pub struct MuSigNonceHash(_);

    pub struct MuSigNonceCoefTag = hash_str("MuSig/noncecoef");
    pub struct MuSigNonceCoefHash(_);

    pub struct Bip340ChallengeTag = hash_str("BIP0340/challenge");
    pub struct Bip340ChallengeHash(_);
}

// =============================================================================
// Low-level point helpers
// =============================================================================

/// Decompresses a 33-byte compressed point.
///
/// Returns an error if the prefix byte is not `0x02` or `0x03`, or if the point
/// is not on the curve.
fn cpoint(pk: &[u8; 33]) -> Result<Secp256k1Point, MusigError> {
    let p = EcfpPublicKey::<Secp256k1, 32>::from_compressed(pk)
        .map_err(|_| MusigError::InvalidPoint)?;
    Ok(p.into())
}

/// Decompresses a possibly-infinity 33-byte point.
/// Returns the point at infinity when all 33 bytes are zero.
fn cpoint_ext(pk: &[u8; 33]) -> Result<Secp256k1Point, MusigError> {
    if pk.iter().all(|&b| b == 0) {
        return Ok(Secp256k1Point::default());
    }
    cpoint(pk)
}

/// True iff `P`'s affine y-coordinate is even. Caller must ensure `P` is not
/// the point at infinity.
fn has_even_y(p: &Secp256k1Point) -> bool {
    debug_assert!(!p.is_zero(), "has_even_y called with point at infinity");
    p.has_even_y()
}

/// SEC1 compressed encoding of a non-infinity point. Thin wrapper that goes
/// through the SDK so we don't duplicate the parity logic.
fn compress(p: &Secp256k1Point) -> [u8; 33] {
    EcfpPublicKey::from(*p).to_compressed()
}

// =============================================================================
// musig_key_agg helpers
// =============================================================================

/// Finds the first pubkey distinct from `pubkeys[0]`, or all-zeros if none.
/// Mirrors `musig_get_second_key`.
fn second_key(pubkeys: &[PlainPk]) -> PlainPk {
    let first = &pubkeys[0];
    for pk in &pubkeys[1..] {
        if pk != first {
            return *pk;
        }
    }
    [0u8; 33]
}

/// Computes `H(KeyAgg list || pk_1 || ... || pk_n)`. Mirrors `musig_hash_keys`.
fn hash_keys(pubkeys: &[PlainPk]) -> [u8; 32] {
    let mut e = KeyAggListHash::engine();
    for pk in pubkeys {
        e.input(pk);
    }
    KeyAggListHash::from_engine(e).to_byte_array()
}

/// Computes the KeyAgg coefficient `a_i` for `pk_`, given precomputed `pk2`.
fn key_agg_coeff_internal(pubkeys: &[PlainPk], pk_: &PlainPk, pk2: &PlainPk) -> Secp256k1Scalar {
    if pk_ == pk2 {
        return Secp256k1Scalar::one();
    }
    let l = hash_keys(pubkeys);
    let mut e = KeyAggCoeffHash::engine();
    e.input(&l);
    e.input(pk_);
    let out = KeyAggCoeffHash::from_engine(e).to_byte_array();
    Secp256k1Scalar::from_be_bytes_reduced(&out)
}

fn key_agg_coeff(pubkeys: &[PlainPk], pk_: &PlainPk) -> Secp256k1Scalar {
    let pk2 = second_key(pubkeys);
    key_agg_coeff_internal(pubkeys, pk_, &pk2)
}

/// Computes the KeyAgg Context per BIP-0327. Mirrors `musig_key_agg`.
///
/// `pubkeys` must be sorted in ascending order (per KeySort); callers should
/// sort before invoking.
pub fn key_agg(pubkeys: &[PlainPk]) -> Result<KeyAggContext, MusigError> {
    if pubkeys.is_empty() {
        return Err(MusigError::EmptyPubkeyList);
    }
    let pk2 = second_key(pubkeys);

    let mut q = Secp256k1Point::default();
    for pk in pubkeys {
        let p = cpoint(pk)?;
        let a_i = key_agg_coeff_internal(pubkeys, pk, &pk2);
        let p_scaled = &p * &a_i;
        q = &q + &p_scaled;
    }

    if q.is_zero() {
        return Err(MusigError::KeyAggInfinity);
    }

    let mut gacc = [0u8; 32];
    gacc[31] = 1;
    Ok(KeyAggContext {
        q,
        gacc,
        tacc: [0u8; 32],
    })
}

// =============================================================================
// Nonce generation and aggregation
// =============================================================================

/// Computes the per-coefficient nonce hash (input to nonce_gen at index `i`).
fn nonce_hash(
    rand: &[u8],
    pk: &PlainPk,
    aggpk: &XOnlyPk,
    i: u8,
    msg_prefixed: &[u8],
    extra_in: &[u8],
) -> [u8; 32] {
    let mut e = MuSigNonceHash::engine();
    e.input(rand);
    e.input(&[33u8]);
    e.input(pk);
    e.input(&[32u8]);
    e.input(aggpk);
    e.input(msg_prefixed);
    e.input(&(extra_in.len() as u32).to_be_bytes());
    if !extra_in.is_empty() {
        e.input(extra_in);
    }
    e.input(&[i]);
    MuSigNonceHash::from_engine(e).to_byte_array()
}

/// Generates a fresh `(secnonce, pubnonce)` pair from external randomness.
///
/// Differences with the BIP-327 specs:
/// - optional `sk`, `msg`, `extra_in` arguments are dropped
/// - `aggpk` is mandatory.
pub fn nonce_gen(
    rand: &[u8],
    pk: &PlainPk,
    aggpk: &XOnlyPk,
) -> Result<(SecNonce, PubNonce), MusigError> {
    let msg = [0u8];
    let k1 = Secp256k1Scalar::from_be_bytes_reduced(&Zeroizing::new(nonce_hash(
        rand,
        pk,
        aggpk,
        0,
        &msg,
        &[],
    )));
    let k2 = Secp256k1Scalar::from_be_bytes_reduced(&Zeroizing::new(nonce_hash(
        rand,
        pk,
        aggpk,
        1,
        &msg,
        &[],
    )));
    if k1.is_zero() || k2.is_zero() {
        // Vanishingly unlikely; same handling as the C ref.
        return Err(MusigError::NonceGenFailed);
    }

    // neither nonce is 0, so neither point is infinity
    let g = Secp256k1::get_generator();
    let r_s1 = &g * &k1;
    let r_s2 = &g * &k2;

    let mut pubnonce_bytes = [0u8; 66];
    pubnonce_bytes[..33].copy_from_slice(&compress(&r_s1));
    pubnonce_bytes[33..].copy_from_slice(&compress(&r_s2));

    Ok((
        SecNonce::new(*k1.as_be_bytes(), *k2.as_be_bytes(), *pk),
        PubNonce(pubnonce_bytes),
    ))
}

/// Aggregates participants' public nonces into the round-2 aggregate nonce.
///
/// On error the inner `usize` is the index of the signer whose contribution was invalid, enabling the caller to blame.
pub fn nonce_agg(pubnonces: &[PubNonce]) -> Result<PubNonce, MusigError> {
    if pubnonces.is_empty() {
        return Err(MusigError::EmptyPubkeyList);
    }
    let mut out = [0u8; 66];
    for j in 0..2 {
        let mut acc = Secp256k1Point::default();
        for (i, pn) in pubnonces.iter().enumerate() {
            let chunk: &[u8; 33] = pn.0[j * 33..j * 33 + 33].try_into().unwrap();
            let r_ij = cpoint(chunk).map_err(|_| MusigError::InvalidContribution(i))?;
            acc = &acc + &r_ij;
        }
        if acc.is_zero() {
            // Infinity is encoded as 33 zero bytes.
        } else {
            out[j * 33..j * 33 + 33].copy_from_slice(&compress(&acc));
        }
    }
    Ok(PubNonce(out))
}

// =============================================================================
// Tweaking and session derivation
// =============================================================================

/// Applies a single tweak (BIP-32 or x-only) to a KeyAgg context, updating
/// `Q`, `gacc`, `tacc`. Mirrors `apply_tweak`.
fn apply_tweak(
    ctx: &mut KeyAggContext,
    tweak: &[u8; 32],
    is_xonly: bool,
) -> Result<(), MusigError> {
    // g = n - 1 if the tweak is x-only and Q has an odd y, 1 otherwise
    let g = if is_xonly && !has_even_y(&ctx.q) {
        -&Secp256k1Scalar::one()
    } else {
        Secp256k1Scalar::one()
    };

    // Reject tweak >= n (mirrors the cmp check in apply_tweak).
    let t = Secp256k1Scalar::from_be_bytes(tweak).ok_or(MusigError::TweakOutOfRange)?;

    // Q := g * Q + t * G
    ctx.q = &(&ctx.q * &g) + &(&Secp256k1::get_generator() * &t);
    if ctx.q.is_zero() {
        return Err(MusigError::TweakInfinity);
    }

    // gacc := g * gacc, tacc := g * tacc + t
    let gacc = Secp256k1Scalar::from_be_bytes_reduced(&ctx.gacc);
    let tacc = Secp256k1Scalar::from_be_bytes_reduced(&ctx.tacc);
    ctx.gacc = *(&g * &gacc).as_be_bytes();
    ctx.tacc = *(&(&g * &tacc) + &t).as_be_bytes();

    Ok(())
}

/// Output of `get_session_values`.
struct SessionValues {
    q: Secp256k1Point,
    gacc: Secp256k1Scalar,
    tacc: Secp256k1Scalar,
    b: Secp256k1Scalar,
    r: Secp256k1Point,
    e: Secp256k1Scalar,
}

/// Derives all session values from a session context. Mirrors `musig_get_session_values`.
// `noncecoef(aggnonce, q_x, msg)` -> 32-byte scalar (BIP-327 `b`).
pub(crate) fn noncecoef(aggnonce: &PubNonce, q_x: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut e = MuSigNonceCoefHash::engine();
    e.input(&aggnonce.0);
    e.input(q_x);
    e.input(msg);
    MuSigNonceCoefHash::from_engine(e).to_byte_array()
}

/// `R = R_1 + b * R_2`, falling back to `G` if the sum is infinity.
pub(crate) fn final_nonce(
    aggnonce: &PubNonce,
    b: &Secp256k1Scalar,
) -> Result<Secp256k1Point, MusigError> {
    let r1_bytes: &[u8; 33] = aggnonce.0[..33].try_into().unwrap();
    let r2_bytes: &[u8; 33] = aggnonce.0[33..].try_into().unwrap();
    let r1 = cpoint_ext(r1_bytes)?;
    let r2 = cpoint_ext(r2_bytes)?;
    let r = &r1 + &(&r2 * b);
    Ok(if r.is_zero() {
        Secp256k1::get_generator()
    } else {
        r
    })
}

fn get_session_values(ctx: &SessionContext) -> Result<SessionValues, MusigError> {
    let mut keyagg = key_agg(ctx.pubkeys)?;
    for (tweak, is_xonly) in ctx.tweaks.iter().zip(ctx.is_xonly.iter()) {
        apply_tweak(&mut keyagg, tweak, *is_xonly)?;
    }

    // BIP-327 reduces b and e modulo n
    let b = Secp256k1Scalar::from_be_bytes_reduced(&noncecoef(ctx.aggnonce, keyagg.q.x(), ctx.msg));
    let r = final_nonce(ctx.aggnonce, &b)?;

    // e = BIP-340_challenge(R.x || Q.x || msg)
    let mut eng = Bip340ChallengeHash::engine();
    eng.input(r.x());
    eng.input(keyagg.q.x());
    eng.input(ctx.msg);
    let e = Secp256k1Scalar::from_be_bytes_reduced(
        &Bip340ChallengeHash::from_engine(eng).to_byte_array(),
    );

    Ok(SessionValues {
        q: keyagg.q,
        gacc: Secp256k1Scalar::from_be_bytes_reduced(&keyagg.gacc),
        tacc: Secp256k1Scalar::from_be_bytes_reduced(&keyagg.tacc),
        b,
        r,
        e,
    })
}

/// Returns the KeyAgg coefficient of `pubkey` for the given session, or an
/// error if `pubkey` is not one of `ctx.pubkeys`.
fn get_session_key_agg_coeff(
    ctx: &SessionContext,
    pubkey: &PlainPk,
) -> Result<Secp256k1Scalar, MusigError> {
    // Constant-time-ish search; pubkey lookups in this context are not secret.
    let mut found = false;
    for pk in ctx.pubkeys {
        if pk.ct_eq(pubkey).unwrap_u8() == 1 {
            found = true;
            break;
        }
    }
    if !found {
        return Err(MusigError::PubkeyNotInList);
    }
    Ok(key_agg_coeff(ctx.pubkeys, pubkey))
}

// =============================================================================
// Partial signing (round 2)
// =============================================================================

/// Round 2 of the MuSig2 protocol: produces a partial signature.
///
/// Consumes `secnonce` so that nonce reuse is impossible at the type level
/// (it is dropped, zeroizing its contents, before the function returns).
pub fn sign(
    secnonce: SecNonce,
    sk: &[u8; 32],
    ctx: &SessionContext,
) -> Result<[u8; 32], MusigError> {
    // Move out of secnonce so the wrapper drops its remaining state, then we
    // operate on local copies of k1 / k2 that we'll zeroize ourselves.
    let (mut k1, mut k2, expected_pk) = secnonce.into_parts();

    let result = (|| -> Result<[u8; 32], MusigError> {
        let values = get_session_values(ctx)?;

        // Range checks on k1, k2: must be 0 < k_i < n.
        let nonce = |k: &[u8; 32]| {
            Secp256k1Scalar::from_be_bytes(k)
                .filter(|k| !k.is_zero())
                .ok_or(MusigError::NonceOutOfRange)
        };
        let (mut k1, mut k2) = (nonce(&k1)?, nonce(&k2)?);

        // Flip k1 / k2 to use -k if R has odd y.
        if !has_even_y(&values.r) {
            k1 = -&k1;
            k2 = -&k2;
        }

        // Range check on sk: 0 < sk < n.
        let sk = Secp256k1Scalar::from_be_bytes(sk)
            .filter(|sk| !sk.is_zero())
            .ok_or(MusigError::SecretKeyOutOfRange)?;

        // P = sk * G
        let pubkey_point = &Secp256k1::get_generator() * &sk;
        let computed_pk = compress(&pubkey_point);
        if computed_pk.ct_eq(&expected_pk).unwrap_u8() != 1 {
            return Err(MusigError::PubkeyMismatch);
        }

        let a = get_session_key_agg_coeff(ctx, &computed_pk)?;

        // g = 1 if has_even_y(Q) else n - 1.
        let g = if has_even_y(&values.q) {
            Secp256k1Scalar::one()
        } else {
            -&Secp256k1Scalar::one()
        };

        // d = g * gacc * sk (mod n)
        let d = &(&g * &values.gacc) * &sk;

        // s = k1 + b * k2 + e * a * d (mod n)
        let s = &(&k1 + &(&values.b * &k2)) + &(&(&values.e * &a) * &d);

        Ok(*s.as_be_bytes())
    })();

    // Always zeroize secrets, even on error.
    k1.zeroize();
    k2.zeroize();

    result
}

/// Combines a complete set of partial signatures into a single BIP-340 Schnorr
/// signature `R.x || s` (64 bytes), per BIP-327 §6.3 (`PartialSigAgg`).
///
/// `ctx` must be the *same* session context that every partial signer used
/// (same `aggnonce`, `pubkeys`, `tweaks`, `is_xonly`, `msg`). `psigs` must
/// contain one entry per participant. The returned signature verifies under
/// the final aggregate x-only key, which is `Q.x` after all tweaks (with `Q`
/// adjusted to have even y per BIP-340).
pub fn partial_sig_agg(
    ctx: &SessionContext,
    psigs: &[[u8; 32]],
) -> Result<[u8; 64], MusigError> {
    if psigs.len() != ctx.pubkeys.len() {
        return Err(MusigError::InvalidPartialSignature);
    }
    let values = get_session_values(ctx)?;
    // s = sum(psig_i) mod n
    let mut s = Secp256k1Scalar::zero();
    for psig in psigs {
        let psig =
            Secp256k1Scalar::from_be_bytes(psig).ok_or(MusigError::InvalidPartialSignature)?;
        s = &s + &psig;
    }

    // Adjust by the additive-tweak contribution: s += e * g * tacc, where
    // g = 1 if has_even_y(Q) else n - 1.
    let g = if has_even_y(&values.q) {
        Secp256k1Scalar::one()
    } else {
        -&Secp256k1Scalar::one()
    };
    s = &s + &(&values.e * &(&g * &values.tacc));

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(values.r.x());
    out[32..].copy_from_slice(s.as_be_bytes());
    Ok(out)
}

// =============================================================================
// BIP-388 aggregate xpub + BIP-32 unhardened CKDpub (with tweak exposure)
// =============================================================================

/// Constructs the BIP-388 aggregate synthetic xpub for a list of participants.
///
/// Steps:
/// 1. Sort participants' compressed pubkeys per BIP-327 KeySort.
/// 2. Run [`key_agg`] to obtain the aggregate point `Q`.
/// 3. Wrap `Q.x` (with x-only-implied `0x02` prefix per BIP-328) plus the
///    fixed [`BIP_328_CHAINCODE`] into an [`Xpub`] that can be fed into
///    further BIP-32 unhardened derivation.
///
/// The synthetic xpub is *not* meant to be serialized; depth, parent
/// fingerprint, child number and network are zero / arbitrary.
pub fn aggregate_xpub(participant_xpubs: &[Xpub]) -> Result<Xpub, MusigError> {
    let mut pks: Vec<PlainPk> = participant_xpubs
        .iter()
        .map(|x| x.public_key.serialize())
        .collect();
    pks.sort();
    let ctx = key_agg(&pks)?;

    // The synthetic xpub must preserve the *natural* parity of `Q`, not
    // synthesise an even-y lift. Otherwise BIP-32 derivation on top of this
    // xpub diverges from BIP-327's internal `apply_tweak` math whenever `Q`
    // happens to have odd-y, and the resulting per-input agg key — and hence
    // every downstream sighash — drifts.
    let mut compressed = [0u8; 33];
    compressed[0] = if has_even_y(&ctx.q) { 0x02 } else { 0x03 };
    compressed[1..].copy_from_slice(ctx.q.x());
    let public_key =
        secp256k1::PublicKey::from_slice(&compressed).map_err(|_| MusigError::InvalidPoint)?;

    let network = participant_xpubs
        .first()
        .map(|x| x.network)
        .unwrap_or(bitcoin::NetworkKind::Test);

    Ok(Xpub {
        network,
        depth: 0,
        parent_fingerprint: Default::default(),
        child_number: ChildNumber::Normal { index: 0 },
        public_key,
        chain_code: ChainCode::from(BIP_328_CHAINCODE),
    })
}

/// Performs one BIP-32 unhardened CKDpub step and returns both the child
/// [`Xpub`] and the 32-byte additive tweak scalar.
///
/// The tweak is the left half of `HMAC-SHA512(chain_code, pubkey || index_be)`,
/// and it's what callers feed into [`apply_tweak`] (with `is_xonly = false`).
pub fn ckdpub_with_tweak(
    parent: &Xpub,
    child: ChildNumber,
) -> Result<(Xpub, [u8; 32]), MusigError> {
    let (tweak_sk, chain_code) = parent
        .ckd_pub_tweak(child)
        .map_err(|_| MusigError::DerivationFailed)?;

    let secp = secp256k1::Secp256k1::new();
    let tweaked_pk = parent
        .public_key
        .add_exp_tweak(&secp, &tweak_sk.into())
        .map_err(|_| MusigError::DerivationFailed)?;

    let child_xpub = Xpub {
        network: parent.network,
        depth: parent.depth.saturating_add(1),
        parent_fingerprint: parent.fingerprint(),
        child_number: child,
        public_key: tweaked_pk,
        chain_code,
    };

    Ok((child_xpub, tweak_sk.secret_bytes()))
}

#[cfg(test)]
mod tests;
