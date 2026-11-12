//! Per-PSBT MuSig2 session storage.
//!
//! Port of `src/musig/musig_sessions.{h,c}` from the C reference Bitcoin app.
//! The initial cut supports a single concurrent session, occupying two
//! persistent storage slots:
//! - Slot [`MUSIG_SESSION_ID_SLOT`] (= 1): 32-byte session id.
//! - Slot [`MUSIG_SESSION_RAND_SLOT`] (= 2): 32-byte root randomness.
//!
//! One signing pass is one session, whose id binds it to the transaction and to the PSBT's
//! MuSig2 accounts (see [`compute_psbt_session_id`]), and runs a single round for all of its
//! MuSig2 placeholders. Lifecycle (mirroring the C ref):
//! - Round 1 generates a fresh `rand_root` in volatile state. It is persisted
//!   only by [`MusigSigningState::commit`], which the caller must invoke at the
//!   *end* of a successful round-1 signing pass.
//! - Round 2 retrieves and atomically deletes the persistent session via
//!   [`MusigSigningState::round2`]. Subsequent calls within the same signing pass
//!   reuse the volatile copy.
//!
//! Capacity (1 concurrent session) is a deliberate constraint of the initial
//! implementation; expanding to N sessions only requires a slot-pair scan and
//! a small bump of `n_storage_slots` in the manifest.

use alloc::vec::Vec;
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::hashes::{sha256t_hash_newtype, Hash, HashEngine};
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::secp256k1;
use bitcoin::{TapNodeHash, TapTweakHash, XOnlyPublicKey};
use common::bip388::{KeyExpression, KeyInformation};
use common::errors::Error;
use common::fastpsbt;
use common::message::{MuSig2PartialSignature, MuSig2Pubnonce};
use common::musig::{self, MusigError, PlainPk, PubNonce, SessionContext};
use sdk::hash::{Hasher, Sha256};
use subtle::ConstantTimeEq;

/// Slot index for the 32-byte session id.
pub const MUSIG_SESSION_ID_SLOT: u32 = 1;
/// Slot index for the 32-byte session randomness root.
pub const MUSIG_SESSION_RAND_SLOT: u32 = 2;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PsbtSession {
    pub id: [u8; 32],
    pub rand_root: [u8; 32],
}

/// Volatile state of one signing pass: its session id, and the round it runs. Mirrors the C
/// `musig_signing_state_t`.
#[derive(Debug)]
pub struct MusigSigningState {
    id: [u8; 32],
    round: Round,
}

/// The round that a signing pass runs, which the first MuSig2 placeholder that the device holds a
/// key of decides.
#[derive(Debug)]
enum Round {
    Undecided,
    /// Producing pubnonces, from a fresh `rand_root` that [`MusigSigningState::commit`] persists.
    One(PsbtSession),
    /// Producing partial signatures, with the session that round 1 persisted, which is already
    /// deleted from storage.
    Two(PsbtSession),
}

/// `SHA-256(rand_root || input_index_be || placeholder_index_be)`.
///
/// Mirrors `compute_rand_i_j` in `musig_sessions.c`. It is *critical* that
/// distinct `(input_index, placeholder_index)` pairs produce distinct outputs:
/// nonce reuse on a MuSig2 signature leaks the secret key.
pub fn compute_rand_i_j(
    session: &PsbtSession,
    input_index: u32,
    placeholder_index: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&session.rand_root);
    h.update(&input_index.to_be_bytes());
    h.update(&placeholder_index.to_be_bytes());
    let mut out = [0u8; 32];
    h.digest(&mut out);
    out
}

impl MusigSigningState {
    /// The state of a signing pass whose session id is `id`.
    pub fn new(id: [u8; 32]) -> Self {
        Self {
            id,
            round: Round::Undecided,
        }
    }

    /// The round-1 session of this pass, for a placeholder whose pubnonce the device must produce.
    ///
    /// The first call generates a fresh `rand_root`; the following ones reuse it, which is what
    /// guarantees that all `(input, placeholder)` pairs of a pass share one root randomness. It
    /// deletes a persisted session with the same id, if any: we assume the client retried round 1,
    /// e.g. because the pubnonces returned earlier never reached the cosigners.
    ///
    /// Fails with [`Error::MixedMusigRounds`] if this pass already runs round 2.
    pub fn round1(&mut self) -> Result<&PsbtSession, Error> {
        if let Round::Undecided = self.round {
            let _ = session_pop(&self.id)?;
            let rand_root: [u8; 32] = sdk::rand::random_bytes(32)
                .try_into()
                .map_err(|_| Error::StorageError)?;
            self.round = Round::One(PsbtSession {
                id: self.id,
                rand_root,
            });
        }
        match &self.round {
            Round::One(session) => Ok(session),
            _ => Err(Error::MixedMusigRounds),
        }
    }

    /// The round-2 session of this pass, for a placeholder whose pubnonce is in the PSBT.
    ///
    /// The first call reads the persisted session and deletes it from storage, so that it is
    /// never used twice; the following ones reuse the volatile copy.
    ///
    /// Fails with [`Error::MissingMusigSession`] if no persisted session has this pass's id: the
    /// PSBT contains pubnonces but the device has no record of generating them. Fails with
    /// [`Error::MixedMusigRounds`] if this pass already runs round 1.
    pub fn round2(&mut self) -> Result<&PsbtSession, Error> {
        if let Round::Undecided = self.round {
            let session = session_pop(&self.id)?.ok_or(Error::MissingMusigSession)?;
            self.round = Round::Two(session);
        }
        match &self.round {
            Round::Two(session) => Ok(session),
            _ => Err(Error::MixedMusigRounds),
        }
    }

    /// Persists the round-1 session, if this pass ran round 1.
    ///
    /// Must be called exactly once at the end of a successful signing pass.
    /// Must *not* be called if the pass aborted: the stale `rand_root` would be
    /// unrecoverable garbage for the (legitimate) client's eventual round 2.
    pub fn commit(&self) -> Result<(), Error> {
        if let Round::One(session) = &self.round {
            write_session_to_storage(session)?;
        }
        Ok(())
    }
}

// =============================================================================
// Internal storage layer
// =============================================================================

fn read_session_from_storage() -> Result<Option<PsbtSession>, Error> {
    if storage::is_slot_empty(MUSIG_SESSION_ID_SLOT)? {
        return Ok(None);
    }
    let id = storage::read_slot(MUSIG_SESSION_ID_SLOT)?;
    let rand_root = storage::read_slot(MUSIG_SESSION_RAND_SLOT)?;
    Ok(Some(PsbtSession { id, rand_root }))
}

fn write_session_to_storage(session: &PsbtSession) -> Result<(), Error> {
    storage::write_slot(MUSIG_SESSION_ID_SLOT, &session.id)?;
    storage::write_slot(MUSIG_SESSION_RAND_SLOT, &session.rand_root)?;
    Ok(())
}

fn clear_session_in_storage() -> Result<(), Error> {
    let zeros = [0u8; 32];
    storage::write_slot(MUSIG_SESSION_ID_SLOT, &zeros)?;
    storage::write_slot(MUSIG_SESSION_RAND_SLOT, &zeros)?;
    Ok(())
}

/// Read-and-atomically-delete the persisted session if its id matches.
fn session_pop(id: &[u8; 32]) -> Result<Option<PsbtSession>, Error> {
    let Some(session) = read_session_from_storage()? else {
        return Ok(None);
    };
    if session.id.ct_eq(id).unwrap_u8() != 1 {
        return Ok(None);
    }
    clear_session_in_storage()?;
    Ok(Some(session))
}

// Production storage is the SDK's slot API; in tests we substitute a
// thread-local in-memory map for isolation from the file-backed native impl
// and from parallel tests.
#[cfg(not(test))]
mod storage {
    use common::errors::Error;
    pub fn is_slot_empty(slot: u32) -> Result<bool, Error> {
        sdk::storage::is_slot_empty(slot).map_err(|_| Error::StorageError)
    }
    pub fn read_slot(slot: u32) -> Result<[u8; 32], Error> {
        sdk::storage::read_slot(slot).map_err(|_| Error::StorageError)
    }
    pub fn write_slot(slot: u32, data: &[u8; 32]) -> Result<(), Error> {
        sdk::storage::write_slot(slot, data).map_err(|_| Error::StorageError)
    }
}

#[cfg(test)]
mod storage {
    use common::errors::Error;
    use std::cell::RefCell;

    // Sized to comfortably hold every slot index this module touches
    // (currently 1 and 2). Bumping the bound has no functional effect.
    const N: usize = 4;

    thread_local! {
        static SLOTS: RefCell<[[u8; 32]; N]> = RefCell::new([[0u8; 32]; N]);
    }

    pub fn is_slot_empty(slot: u32) -> Result<bool, Error> {
        SLOTS.with(|s: &RefCell<[[u8; 32]; N]>| Ok(s.borrow()[slot as usize] == [0u8; 32]))
    }
    pub fn read_slot(slot: u32) -> Result<[u8; 32], Error> {
        SLOTS.with(|s: &RefCell<[[u8; 32]; N]>| Ok(s.borrow()[slot as usize]))
    }
    pub fn write_slot(slot: u32, data: &[u8; 32]) -> Result<(), Error> {
        SLOTS.with(|s: &RefCell<[[u8; 32]; N]>| {
            s.borrow_mut()[slot as usize] = *data;
            Ok(())
        })
    }

    /// Test helper: zero out all slots. Must be called at the start of every
    /// test that touches storage so it doesn't see state left behind by a
    /// previous test on the same thread.
    pub fn reset() {
        SLOTS.with(|s: &RefCell<[[u8; 32]; N]>| {
            for slot in s.borrow_mut().iter_mut() {
                *slot = [0u8; 32];
            }
        })
    }
}

/// Wipes the test-only persistent-storage backing. Available only under
/// `cfg(test)`; cross-module tests that drive `handle_sign_psbt` through
/// multiple musig rounds should call this at the start to guarantee a clean
/// session-storage state.
#[cfg(test)]
pub(crate) fn reset_storage_for_tests() {
    storage::reset();
}

// =============================================================================
// Per-input MuSig2 derivation + signing rounds
// =============================================================================
//
// Port of `src/handler/sign_psbt/musig_signing.{h,c}` from the C reference.

/// Maximum participants in a single musig() expression.
pub const MAX_PUBKEYS_PER_MUSIG: usize = 5;

/// Either a key-path spend (taproot tweak applies) or a script-path spend
/// (a single tapleaf hash is used in BIP-373 lookups but no taptweak).
#[derive(Debug, Clone, Copy)]
pub enum SpendPath<'a> {
    Keypath {
        /// Root of the taproot script tree, or `None` for BIP-86 / BIP-386
        /// style policies that have no tree.
        taptree_hash: Option<&'a [u8; 32]>,
    },
    Tapscript {
        leaf_hash: &'a [u8; 32],
    },
}

impl<'a> SpendPath<'a> {
    fn leaf_hash(&self) -> Option<&'a [u8; 32]> {
        match self {
            SpendPath::Keypath { .. } => None,
            SpendPath::Tapscript { leaf_hash } => Some(*leaf_hash),
        }
    }
}

/// Output of [`compute_per_input_info`]: everything the round-1 and round-2
/// flows need that depends on `(input, placeholder)`. Mirrors the C ref's
/// `musig_per_input_info_t`.
#[derive(Debug)]
pub struct PerInputInfo {
    /// Sorted (per BIP-327 KeySort) participant pubkeys.
    pub keys: Vec<PlainPk>,
    /// 33-byte SEC1 compressed aggregate pubkey *after* all tweaks (the
    /// 2 BIP-32 ones for keypath/tapscript, plus the BIP-341 taptweak for
    /// keypath). This is the `agg_pk` used as a PSBT BIP-373 key.
    pub agg_key_tweaked: [u8; 33],
    /// Up to three 32-byte tweak scalars, packed into a fixed-size array.
    pub tweaks: [[u8; 32]; 3],
    /// Number of populated entries in `tweaks` and `is_xonly` (2 or 3).
    pub n_tweaks: usize,
    /// Whether each tweak is an x-only (BIP-341) tweak rather than an
    /// additive (BIP-32) one.
    pub is_xonly: [bool; 3],
}

// Round 1 / round 2 outputs are emitted directly as wire types from
// [`common::message`] — no conversion needed at the handler boundary.

// PSBT-session-id tagged hash. Binding the session to both the transaction and
// its MuSig2 accounts ensures distinct PSBTs never collide on the persistent
// session slot — accidental collisions would force a Round 2 failure, but never
// key compromise (mirrors the C ref's invariant).
sha256t_hash_newtype! {
    pub struct PsbtSessionIdTag = hash_str("PsbtSessionId");
    pub struct PsbtSessionIdHash(_);
}

/// `tagged_hash("PsbtSessionId", tx_id || account_ids[0] || account_ids[1] || ...)`.
///
/// `tx_id` is the unsigned transaction's txid, which uniquely identifies the
/// PSBT contents. `account_ids` are the account ids (the hash of the account's
/// serialization, including its name) of the PSBT's accounts that have a
/// MuSig2 key, in account order.
///
/// The session is per PSBT rather than per account: the device stores a single
/// session, and every `(input, placeholder)` pair of the PSBT is distinct, so
/// one `rand_root` serves them all.
pub fn compute_psbt_session_id(tx_id: &[u8; 32], account_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut e = PsbtSessionIdHash::engine();
    e.input(tx_id);
    for account_id in account_ids {
        e.input(account_id);
    }
    PsbtSessionIdHash::from_engine(e).to_byte_array()
}

/// Computes all the per-`(input, placeholder)` material a round-1 / round-2
/// MuSig2 step needs.
///
/// Mirrors `compute_musig_per_input_info` in the C reference: collects
/// participants' child pubkeys, sorts them per BIP-327 KeySort, runs the
/// BIP-388 aggregate KeyAgg, applies the two BIP-32 tweaks, and conditionally
/// applies the BIP-341 taptweak (key-path spends only).
pub fn compute_per_input_info(
    key_information: &[KeyInformation],
    placeholder: &KeyExpression,
    is_change: bool,
    address_index: u32,
    spend: SpendPath<'_>,
) -> Result<PerInputInfo, Error> {
    let indices = placeholder
        .musig_key_indices()
        .ok_or(Error::UnsupportedWalletPolicy)?;
    if indices.is_empty() || indices.len() > MAX_PUBKEYS_PER_MUSIG {
        return Err(Error::TooManyKeys);
    }

    let change_step = ChildNumber::from(if is_change {
        placeholder.num2
    } else {
        placeholder.num1
    });
    let address_step = ChildNumber::from(address_index);

    // 1) Per BIP-388, MuSig2 key-aggregation runs on the *master* participant
    //    pubkeys — the BIP-32 `(change, address_index)` derivation is applied
    //    *after* aggregation (and shows up as two non-xonly tweaks in the
    //    session context below). The participants therefore sign with their
    //    master private keys; their derived children are never used.
    let mut keys: Vec<PlainPk> = Vec::with_capacity(indices.len());
    let mut participant_xpubs: Vec<Xpub> = Vec::with_capacity(indices.len());
    for &idx in indices {
        let xpub = key_information
            .get(idx as usize)
            .ok_or(Error::InvalidKeyIndex)?
            .pubkey;
        keys.push(xpub.public_key.serialize());
        participant_xpubs.push(xpub);
    }
    keys.sort();

    // 2) Aggregate xpub + 2 BIP-32 derivations to (change, address_index).
    let secp = secp256k1::Secp256k1::new();
    let agg = musig::aggregate_xpub(&participant_xpubs).map_err(|_| Error::InvalidKey)?;
    let (child1, t0) =
        musig::ckdpub_with_tweak(&agg, change_step).map_err(|_| Error::KeyDerivationFailed)?;
    let (child2, t1) =
        musig::ckdpub_with_tweak(&child1, address_step).map_err(|_| Error::KeyDerivationFailed)?;

    let mut tweaks: [[u8; 32]; 3] = [[0u8; 32]; 3];
    let mut is_xonly: [bool; 3] = [false; 3];
    tweaks[0] = t0;
    tweaks[1] = t1;

    let agg_key_pre_taptweak: [u8; 33] = child2.public_key.serialize();

    let (agg_key_tweaked, n_tweaks) = match spend {
        SpendPath::Tapscript { .. } => (agg_key_pre_taptweak, 2),
        SpendPath::Keypath { taptree_hash } => {
            // 3) Apply BIP-341 taptweak.
            let merkle_root: Option<TapNodeHash> =
                taptree_hash.map(|h| TapNodeHash::from_byte_array(*h));
            let xonly_internal: UntweakedPublicKey = XOnlyPublicKey::from(child2.public_key);
            tweaks[2] =
                TapTweakHash::from_key_and_tweak(xonly_internal, merkle_root).to_byte_array();
            is_xonly[2] = true;
            let (tweaked_xonly, parity) = xonly_internal.tap_tweak(&secp, merkle_root);

            let mut out = [0u8; 33];
            out[0] = 0x02 + parity.to_u8();
            out[1..].copy_from_slice(&tweaked_xonly.to_x_only_public_key().serialize());
            (out, 3)
        }
    };

    Ok(PerInputInfo {
        keys,
        agg_key_tweaked,
        tweaks,
        n_tweaks,
        is_xonly,
    })
}

/// Round 1: derives the per-`(input, placeholder)` pubnonce.
///
/// The corresponding `secnonce` is recoverable from the session's
/// `rand_root` and `(input_index, placeholder_index)` (see
/// [`compute_rand_i_j`]) so it does not need to be persisted between rounds;
/// `nonce_gen` is invoked here only to produce the pubnonce.
pub fn produce_pubnonce(
    per_input_info: &PerInputInfo,
    internal_pk: &[u8; 33],
    session: &PsbtSession,
    input_index: u32,
    placeholder_index: u32,
    spend: SpendPath<'_>,
) -> Result<MuSig2Pubnonce, Error> {
    let rand_i_j = compute_rand_i_j(session, input_index, placeholder_index);
    let aggpk_xonly: [u8; 32] = per_input_info.agg_key_tweaked[1..]
        .try_into()
        .expect("agg_key_tweaked is 33 bytes");

    let (_secnonce, pubnonce) =
        musig::nonce_gen(&rand_i_j, internal_pk, &aggpk_xonly).map_err(map_musig_err)?;
    // `_secnonce` is dropped here, zeroizing its k1/k2 (see SecNonce's Drop).

    Ok(MuSig2Pubnonce {
        input_index,
        pubnonce: *pubnonce.as_bytes(),
        participant_pk: *internal_pk,
        aggregate_pubkey: per_input_info.agg_key_tweaked,
        leaf_hash: spend.leaf_hash().copied(),
    })
}

/// Round 2: produces a partial signature for the given `sighash`.
///
/// Looks up *this signer's* and every cosigner's pubnonce in `psbt_input`
/// (BIP-373 `PSBT_IN_MUSIG2_PUB_NONCE` field), aggregates them, recomputes
/// this signer's secnonce deterministically from the session, and runs
/// [`musig::sign`].
pub fn sign_sighash_musig(
    per_input_info: &PerInputInfo,
    internal_pk: &[u8; 33],
    sk: &[u8; 32],
    sighash: &[u8; 32],
    session: &PsbtSession,
    input_index: u32,
    placeholder_index: u32,
    psbt_input: &fastpsbt::Input<'_>,
    spend: SpendPath<'_>,
) -> Result<MuSig2PartialSignature, Error> {
    let agg_pk = &per_input_info.agg_key_tweaked;
    let leaf = spend.leaf_hash();

    // Confirm our own pubnonce is in the PSBT — if not, the client never
    // ran round 1 against this input/placeholder.
    let my_pubnonce = psbt_input
        .get_musig2_pub_nonce(internal_pk, agg_pk, leaf)
        .map_err(|_| Error::FailedToDeserializePsbt)?
        .ok_or(Error::MissingMusigPubnonce)?;

    // Collect every participant's pubnonce.
    let mut pubnonces: Vec<PubNonce> = Vec::with_capacity(per_input_info.keys.len());
    for participant_pk in &per_input_info.keys {
        let raw = psbt_input
            .get_musig2_pub_nonce(participant_pk, agg_pk, leaf)
            .map_err(|_| Error::FailedToDeserializePsbt)?
            .ok_or(Error::MissingMusigPubnonce)?;
        pubnonces.push(PubNonce(raw));
    }
    let aggnonce = musig::nonce_agg(&pubnonces).map_err(map_musig_err)?;

    // Recompute our secnonce deterministically from the session.
    let rand_i_j = compute_rand_i_j(session, input_index, placeholder_index);
    let aggpk_xonly: [u8; 32] = agg_pk[1..].try_into().expect("agg_key_tweaked is 33 bytes");
    let (secnonce, pubnonce) =
        musig::nonce_gen(&rand_i_j, internal_pk, &aggpk_xonly).map_err(map_musig_err)?;
    // The aggregate nonce must contain the nonce we sign with: our pubnonce in the
    // PSBT must be the one that this session produced in round 1.
    if *pubnonce.as_bytes() != my_pubnonce {
        return Err(Error::MusigPubnonceMismatch);
    }

    // Partial sign.
    let tweaks_slice: &[[u8; 32]] = &per_input_info.tweaks[..per_input_info.n_tweaks];
    let is_xonly_slice: &[bool] = &per_input_info.is_xonly[..per_input_info.n_tweaks];
    let ctx = SessionContext {
        aggnonce: &aggnonce,
        pubkeys: &per_input_info.keys,
        tweaks: tweaks_slice,
        is_xonly: is_xonly_slice,
        msg: sighash,
    };
    let psig = musig::sign(secnonce, sk, &ctx).map_err(map_musig_err)?;

    Ok(MuSig2PartialSignature {
        input_index,
        signature: psig,
        participant_pk: *internal_pk,
        aggregate_pubkey: *agg_pk,
        leaf_hash: leaf.copied(),
    })
}

fn map_musig_err(err: MusigError) -> Error {
    match err {
        MusigError::InvalidPoint
        | MusigError::EmptyPubkeyList
        | MusigError::InvalidContribution(_)
        | MusigError::PubkeyNotInList
        | MusigError::InvalidPartialSignature => Error::InvalidKey,
        MusigError::KeyAggInfinity
        | MusigError::TweakOutOfRange
        | MusigError::TweakInfinity
        | MusigError::NonceGenFailed
        | MusigError::NonceOutOfRange
        | MusigError::SecretKeyOutOfRange
        | MusigError::PubkeyMismatch
        | MusigError::DerivationFailed => Error::SigningFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: [u8; 32] = [0xAAu8; 32];
    const ID_B: [u8; 32] = [0xBBu8; 32];

    /// `compute_rand_i_j` mixes rand_root, input_index and placeholder_index.
    /// Two distinct `(i, j)` tuples must never collide.
    #[test]
    fn compute_rand_i_j_is_distinct_per_indices() {
        let s = PsbtSession {
            id: ID_A,
            rand_root: [0x42u8; 32],
        };
        let r_0_0 = compute_rand_i_j(&s, 0, 0);
        let r_0_1 = compute_rand_i_j(&s, 0, 1);
        let r_1_0 = compute_rand_i_j(&s, 1, 0);
        let r_1_1 = compute_rand_i_j(&s, 1, 1);
        let all = [r_0_0, r_0_1, r_1_0, r_1_1];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "rand_i_j collision at {} vs {}", i, j);
            }
        }
        // Same (i, j) reproduces the same output.
        assert_eq!(r_0_0, compute_rand_i_j(&s, 0, 0));
    }

    /// `compute_rand_i_j` must differ when `rand_root` differs.
    #[test]
    fn compute_rand_i_j_changes_with_rand_root() {
        let s1 = PsbtSession {
            id: ID_A,
            rand_root: [0x11u8; 32],
        };
        let s2 = PsbtSession {
            id: ID_A,
            rand_root: [0x22u8; 32],
        };
        assert_ne!(compute_rand_i_j(&s1, 0, 0), compute_rand_i_j(&s2, 0, 0));
    }

    /// Round 1 produces a fresh rand_root and caches it for subsequent calls
    /// during the same signing pass.
    #[test]
    fn round1_caches_rand_root() {
        storage::reset();
        let mut state = MusigSigningState::new(ID_A);

        let rand1 = state.round1().unwrap().rand_root;
        assert_ne!(rand1, [0u8; 32], "rand_root must be initialized");

        // A second call keeps the same rand_root.
        assert_eq!(state.round1().unwrap().rand_root, rand1);

        // Another pass gets fresh randomness.
        let mut state2 = MusigSigningState::new(ID_A);
        assert_ne!(state2.round1().unwrap().rand_root, rand1);
    }

    /// Until `commit`, nothing is persisted.
    #[test]
    fn round1_does_not_persist_before_commit() {
        storage::reset();
        let mut state = MusigSigningState::new(ID_A);
        let _ = state.round1().unwrap();

        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
        assert!(storage::is_slot_empty(MUSIG_SESSION_RAND_SLOT).unwrap());
    }

    /// `commit` persists the round-1 session; round 2 finds it once, then
    /// finds nothing on a second lookup (one-time-read semantics).
    #[test]
    fn round1_commit_then_round2_pop() {
        storage::reset();
        let mut state = MusigSigningState::new(ID_A);
        let rand_root_at_commit = state.round1().unwrap().rand_root;
        state.commit().unwrap();

        // Round 2 in a fresh signing pass.
        let mut state2 = MusigSigningState::new(ID_A);
        assert_eq!(state2.round2().unwrap().rand_root, rand_root_at_commit);

        // The persistent slots are now zero.
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
        assert!(storage::is_slot_empty(MUSIG_SESSION_RAND_SLOT).unwrap());

        // A second round 2 in another fresh state finds nothing.
        let mut state3 = MusigSigningState::new(ID_A);
        assert_eq!(state3.round2().err(), Some(Error::MissingMusigSession));
    }

    /// Round 2 on a never-persisted id fails.
    #[test]
    fn round2_missing_session_fails() {
        storage::reset();
        write_session_to_storage(&PsbtSession {
            id: ID_B,
            rand_root: [0x99u8; 32],
        })
        .unwrap();

        let mut state = MusigSigningState::new(ID_A);
        assert_eq!(state.round2().err(), Some(Error::MissingMusigSession));
        // The session of another id is left alone.
        assert!(!storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
    }

    /// Within the same signing pass, repeated round 2 lookups reuse the
    /// volatile cached session even though the persistent slot was already
    /// cleared.
    #[test]
    fn round2_caches_after_first_pop() {
        storage::reset();
        // Persist a session for ID_A.
        write_session_to_storage(&PsbtSession {
            id: ID_A,
            rand_root: [0x99u8; 32],
        })
        .unwrap();

        let mut state = MusigSigningState::new(ID_A);
        let r1 = state.round2().unwrap().rand_root;
        assert_eq!(r1, [0x99u8; 32]);
        // Persistent slots are now empty.
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());

        // A second call still works via the volatile cache.
        assert_eq!(state.round2().unwrap().rand_root, r1);
    }

    /// `round1` deletes a stale persisted session with the same id (per the C
    /// ref's "client retried round 1" handling).
    #[test]
    fn round1_drops_stale_persistent() {
        storage::reset();
        write_session_to_storage(&PsbtSession {
            id: ID_A,
            rand_root: [0x55u8; 32],
        })
        .unwrap();

        let mut state = MusigSigningState::new(ID_A);
        // The fresh rand_root differs from the stale one.
        assert_ne!(state.round1().unwrap().rand_root, [0x55u8; 32]);
        // And the persistent storage has been wiped.
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
    }

    /// A signing pass runs one round: once it has run one, it refuses the other.
    #[test]
    fn a_pass_runs_a_single_round() {
        storage::reset();
        let mut state = MusigSigningState::new(ID_A);
        let _ = state.round1().unwrap();
        assert_eq!(state.round2().err(), Some(Error::MixedMusigRounds));

        write_session_to_storage(&PsbtSession {
            id: ID_A,
            rand_root: [0x99u8; 32],
        })
        .unwrap();
        let mut state = MusigSigningState::new(ID_A);
        let _ = state.round2().unwrap();
        assert_eq!(state.round1().err(), Some(Error::MixedMusigRounds));
    }

    /// `commit` is a no-op when no round-1 session was created: the signing
    /// pass involved no musig placeholders, or ran round 2.
    #[test]
    fn commit_noop_without_round1() {
        storage::reset();
        let state = MusigSigningState::new(ID_A);
        state.commit().unwrap();
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());

        write_session_to_storage(&PsbtSession {
            id: ID_A,
            rand_root: [0x99u8; 32],
        })
        .unwrap();
        let mut state = MusigSigningState::new(ID_A);
        let _ = state.round2().unwrap();
        state.commit().unwrap();
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
    }

    // =========================================================================
    // Per-input MuSig2 info + round 1 / round 2 cores
    // =========================================================================

    use common::account::WalletPolicy;
    use common::script::ToScript;
    use hex_literal::hex;

    // Cosigner xpubs used by the C reference's `test_musig2_hotsigner_keypath`.
    const COSIGNER_1_XPUB: &str = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT";
    const COSIGNER_2_XPUB: &str = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm";

    #[test]
    fn compute_psbt_session_id_is_deterministic_and_distinct() {
        let w1: [u8; 32] = [0x11; 32];
        let w2: [u8; 32] = [0x33; 32];
        let t1: [u8; 32] = [0x22; 32];
        let id_a = compute_psbt_session_id(&t1, &[w1]);
        assert_eq!(id_a, compute_psbt_session_id(&t1, &[w1]));

        // Changing the transaction, or the accounts, changes the output.
        let t2: [u8; 32] = [0x44; 32];
        let others = [
            compute_psbt_session_id(&t2, &[w1]),
            compute_psbt_session_id(&t1, &[w2]),
            compute_psbt_session_id(&t1, &[w1, w2]),
            compute_psbt_session_id(&t1, &[w2, w1]),
            compute_psbt_session_id(&t1, &[]),
        ];
        for (i, other) in others.iter().enumerate() {
            assert_ne!(id_a, *other);
            for other2 in &others[i + 1..] {
                assert_ne!(other, other2);
            }
        }
    }

    fn make_musig_keypath_policy() -> WalletPolicy {
        WalletPolicy::new(
            "tr(musig(@0,@1)/**)",
            vec![
                COSIGNER_1_XPUB.try_into().unwrap(),
                COSIGNER_2_XPUB.try_into().unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn compute_per_input_info_keypath_matches_script_derivation() {
        let policy = make_musig_keypath_policy();
        let placeholder = policy
            .descriptor_template()
            .placeholders()
            .next()
            .unwrap()
            .0
            .clone();

        let info = compute_per_input_info(
            policy.key_information(),
            &placeholder,
            false,
            3,
            SpendPath::Keypath {
                taptree_hash: None, // `tr(musig(@0,@1)/**)` has no script tree
            },
        )
        .unwrap();

        // Shape: keypath spend → 3 tweaks, last is x-only.
        assert_eq!(info.n_tweaks, 3);
        assert_eq!(info.is_xonly, [false, false, true]);
        assert_eq!(info.keys.len(), 2);
        // BIP-327 KeySort sorts pubkeys lexicographically.
        assert!(info.keys[0] < info.keys[1]);

        // The post-taptweak x-only key must match the P2TR scriptPubKey from
        // the script-derivation path (independently validated in
        // `common::script::tests::tr_musig_keypath_to_script`).
        let script = policy.to_script(false, 3).unwrap();
        let expected_xonly: [u8; 32] = script.as_bytes()[2..34].try_into().unwrap();
        assert_eq!(&info.agg_key_tweaked[1..], &expected_xonly);
    }

    #[test]
    fn compute_per_input_info_tapscript_no_taptweak() {
        // Tapscript musig: outer key is plain, the script-path leaf contains
        // pk(musig(@1,@2)/**). compute_per_input_info on the *musig*
        // placeholder must NOT apply a BIP-341 taptweak.
        let policy = WalletPolicy::new(
            "tr(@0/**,pk(musig(@1,@2)/**))",
            vec![
                "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN".try_into().unwrap(),
                COSIGNER_1_XPUB.try_into().unwrap(),
                COSIGNER_2_XPUB.try_into().unwrap(),
            ],
        )
        .unwrap();

        // Find the musig placeholder (it's the second one yielded; the first
        // is the outer plain @0).
        let placeholder = policy
            .descriptor_template()
            .placeholders()
            .find(|(kp, _)| kp.is_musig())
            .expect("musig placeholder present")
            .0
            .clone();

        // Tapscript: we don't strictly need a real leaf_hash for this shape
        // check; any 32-byte value works.
        let dummy_leaf = [0xCDu8; 32];
        let info = compute_per_input_info(
            policy.key_information(),
            &placeholder,
            false,
            0,
            SpendPath::Tapscript {
                leaf_hash: &dummy_leaf,
            },
        )
        .unwrap();

        assert_eq!(info.n_tweaks, 2);
        assert_eq!(info.is_xonly, [false, false, false]);
        assert_eq!(info.keys.len(), 2);
        // No taptweak ⇒ the aggregate's prefix carries its natural parity
        // (0x02 or 0x03), not synthetic 0x02.
        assert!(info.agg_key_tweaked[0] == 0x02 || info.agg_key_tweaked[0] == 0x03);
    }

    #[test]
    fn compute_per_input_info_rejects_plain_placeholder() {
        // `tr(@0/**)` — the only placeholder is plain, not musig.
        let policy =
            WalletPolicy::new("tr(@0/**)", vec![COSIGNER_1_XPUB.try_into().unwrap()]).unwrap();
        let placeholder = policy
            .descriptor_template()
            .placeholders()
            .next()
            .unwrap()
            .0
            .clone();

        let err = compute_per_input_info(
            policy.key_information(),
            &placeholder,
            false,
            0,
            SpendPath::Keypath { taptree_hash: None },
        )
        .unwrap_err();
        assert_eq!(err, Error::UnsupportedWalletPolicy);
    }

    #[test]
    fn produce_pubnonce_shape_and_session_dependence() {
        let policy = make_musig_keypath_policy();
        let placeholder = policy
            .descriptor_template()
            .placeholders()
            .next()
            .unwrap()
            .0
            .clone();
        let info = compute_per_input_info(
            policy.key_information(),
            &placeholder,
            false,
            3,
            SpendPath::Keypath { taptree_hash: None },
        )
        .unwrap();

        // BIP-388 musig signs with the *master* participant key — `info.keys`
        // contains the (sorted) master pubkeys directly, not derived children.
        let internal_pk: [u8; 33] = {
            let xpub: Xpub = COSIGNER_1_XPUB.parse().unwrap();
            xpub.public_key.serialize()
        };
        assert!(info.keys.contains(&internal_pk));

        let session = PsbtSession {
            id: [0x77; 32],
            rand_root: [0x11; 32],
        };
        let data = produce_pubnonce(
            &info,
            &internal_pk,
            &session,
            4,
            0,
            SpendPath::Keypath { taptree_hash: None },
        )
        .unwrap();

        assert_eq!(data.input_index, 4);
        assert_eq!(data.participant_pk, internal_pk);
        assert_eq!(data.aggregate_pubkey, info.agg_key_tweaked);
        assert!(data.leaf_hash.is_none());

        // Same session + (i, j) → same pubnonce; different rand_root → different.
        let again = produce_pubnonce(
            &info,
            &internal_pk,
            &session,
            4,
            0,
            SpendPath::Keypath { taptree_hash: None },
        )
        .unwrap();
        assert_eq!(again.pubnonce, data.pubnonce);

        let session2 = PsbtSession {
            id: [0x77; 32],
            rand_root: [0x22; 32],
        };
        let other = produce_pubnonce(
            &info,
            &internal_pk,
            &session2,
            4,
            0,
            SpendPath::Keypath { taptree_hash: None },
        )
        .unwrap();
        assert_ne!(other.pubnonce, data.pubnonce);
    }

    #[test]
    fn produce_pubnonce_carries_leaf_hash_for_tapscript() {
        let policy = WalletPolicy::new(
            "tr(@0/**,pk(musig(@1,@2)/**))",
            vec![
                "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN".try_into().unwrap(),
                COSIGNER_1_XPUB.try_into().unwrap(),
                COSIGNER_2_XPUB.try_into().unwrap(),
            ],
        )
        .unwrap();
        let placeholder = policy
            .descriptor_template()
            .placeholders()
            .find(|(kp, _)| kp.is_musig())
            .unwrap()
            .0
            .clone();
        let leaf_hash = hex!("F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0");
        let info = compute_per_input_info(
            policy.key_information(),
            &placeholder,
            false,
            0,
            SpendPath::Tapscript {
                leaf_hash: &leaf_hash,
            },
        )
        .unwrap();

        // Pick the first sorted key as "ours".
        let internal_pk = info.keys[0];
        let session = PsbtSession {
            id: [0x99; 32],
            rand_root: [0x55; 32],
        };
        let data = produce_pubnonce(
            &info,
            &internal_pk,
            &session,
            0,
            0,
            SpendPath::Tapscript {
                leaf_hash: &leaf_hash,
            },
        )
        .unwrap();

        assert_eq!(data.leaf_hash, Some(leaf_hash));
    }
}
