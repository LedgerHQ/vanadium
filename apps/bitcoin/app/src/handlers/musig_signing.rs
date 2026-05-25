//! Per-PSBT MuSig2 session storage.
//!
//! Port of `src/musig/musig_sessions.{h,c}` from the C reference Bitcoin app
//! (app-bitcoin-new). The initial cut supports a single concurrent session,
//! occupying two persistent storage slots:
//! - Slot [`MUSIG_SESSION_ID_SLOT`] (= 1): 32-byte session id.
//! - Slot [`MUSIG_SESSION_RAND_SLOT`] (= 2): 32-byte root randomness.
//!
//! Lifecycle (mirroring the C ref):
//! - Round 1 generates a fresh `rand_root` in volatile state. It is persisted
//!   only by [`commit`], which the caller must invoke at the *end* of a
//!   successful round-1 signing pass.
//! - Round 2 retrieves and atomically deletes the persistent session via
//!   [`round2_initialize`]. Subsequent calls within the same signing pass reuse
//!   the volatile copy.
//!
//! Capacity (1 concurrent session) is a deliberate constraint of the initial
//! implementation; expanding to N sessions only requires a slot-pair scan and
//! a small bump of `n_storage_slots` in the manifest.

use common::errors::Error;
use sdk::hash::{Hasher, Sha256};
use subtle::ConstantTimeEq;

/// Slot index for the 32-byte session id.
pub const MUSIG_SESSION_ID_SLOT: u32 = 1;
/// Slot index for the 32-byte session randomness root.
pub const MUSIG_SESSION_RAND_SLOT: u32 = 2;

/// Maximum number of MuSig2 sessions stored at once. The initial cut is 1; the
/// constant is exposed for future expansion.
pub const MAX_N_MUSIG_SESSIONS: usize = 1;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PsbtSession {
    pub id: [u8; 32],
    pub rand_root: [u8; 32],
}

impl PsbtSession {
    /// A session is "initialized" once its id is non-zero. The all-zero id is
    /// reserved to mean "no session"; an honest PSBT will never collide.
    pub fn is_initialized(&self) -> bool {
        self.id != [0u8; 32]
    }
}

/// Volatile per-signing-call state. Mirrors the C `musig_signing_state_t`.
#[derive(Debug, Default)]
pub struct MusigSigningState {
    pub round1: PsbtSession,
    pub round2: PsbtSession,
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

/// Initializes / returns the round-1 session for the given `id`.
///
/// If a persisted session with this id exists, it is deleted (we assume the
/// client retried round 1, e.g. because the pubnonces returned earlier never
/// reached the cosigners; we start fresh and discard the stale entry).
///
/// On first invocation for an id during this signing pass, generates a fresh
/// `rand_root`. Subsequent invocations with the same id reuse the volatile
/// state — this is what guarantees that all `(input, placeholder)` pairs in a
/// single signing pass share one root randomness.
pub fn round1_initialize<'a>(
    id: &[u8; 32],
    state: &'a mut MusigSigningState,
) -> Result<&'a PsbtSession, Error> {
    // Drop any stale persisted session with the same id.
    let _ = session_pop(id)?;

    if state.round1.id != *id {
        let rand: [u8; 32] = sdk::rand::random_bytes(32)
            .try_into()
            .map_err(|_| Error::StorageError)?;
        state.round1.id = *id;
        state.round1.rand_root = rand;
    }
    Ok(&state.round1)
}

/// Retrieves the round-2 session for the given `id`, deleting it from
/// persistent storage on first read.
///
/// Returns `Ok(None)` if no persisted session matches the id: the PSBT
/// contains pubnonces but the device has no record of generating them.
pub fn round2_initialize<'a>(
    id: &[u8; 32],
    state: &'a mut MusigSigningState,
) -> Result<Option<&'a PsbtSession>, Error> {
    if state.round2.id != *id {
        match session_pop(id)? {
            Some(s) => state.round2 = s,
            None => return Ok(None),
        }
    }
    Ok(Some(&state.round2))
}

/// Persists the round-1 session, if any, to permanent storage.
///
/// Must be called exactly once at the end of a successful round-1 signing pass.
/// Must *not* be called if the pass aborted: the stale `rand_root` would be
/// unrecoverable garbage for the (legitimate) client's eventual round 2.
pub fn commit(state: &MusigSigningState) -> Result<(), Error> {
    if state.round1.is_initialized() {
        write_session_to_storage(&state.round1)?;
    }
    Ok(())
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
        SLOTS.with(|s: &RefCell<[[u8; 32]; N]>| {
            Ok(s.borrow()[slot as usize] == [0u8; 32])
        })
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
    /// with the same id during the same signing pass.
    #[test]
    fn round1_initialize_caches_rand_root() {
        storage::reset();
        let mut state = MusigSigningState::default();

        let s1 = round1_initialize(&ID_A, &mut state).unwrap();
        let rand1 = s1.rand_root;
        assert_ne!(rand1, [0u8; 32], "rand_root must be initialized");

        // Second call with the same id keeps the same rand_root.
        let s2 = round1_initialize(&ID_A, &mut state).unwrap();
        assert_eq!(s2.rand_root, rand1);

        // A different id triggers fresh randomness.
        let s3 = round1_initialize(&ID_B, &mut state).unwrap();
        assert_ne!(s3.rand_root, rand1);
    }

    /// Until `commit`, nothing is persisted.
    #[test]
    fn round1_does_not_persist_before_commit() {
        storage::reset();
        let mut state = MusigSigningState::default();
        let _ = round1_initialize(&ID_A, &mut state).unwrap();

        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
        assert!(storage::is_slot_empty(MUSIG_SESSION_RAND_SLOT).unwrap());
    }

    /// `commit` persists the round-1 session; round 2 finds it once, then
    /// finds nothing on a second lookup (one-time-read semantics).
    #[test]
    fn round1_commit_then_round2_pop() {
        storage::reset();
        let mut state = MusigSigningState::default();
        let rand_root_at_commit = {
            let s = round1_initialize(&ID_A, &mut state).unwrap();
            s.rand_root
        };
        commit(&state).unwrap();

        // Round 2 in a fresh signing pass.
        let mut state2 = MusigSigningState::default();
        let s = round2_initialize(&ID_A, &mut state2).unwrap().unwrap();
        assert_eq!(s.rand_root, rand_root_at_commit);

        // The persistent slots are now zero.
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
        assert!(storage::is_slot_empty(MUSIG_SESSION_RAND_SLOT).unwrap());

        // A second round 2 in another fresh state finds nothing.
        let mut state3 = MusigSigningState::default();
        assert!(round2_initialize(&ID_A, &mut state3).unwrap().is_none());
    }

    /// Round 2 on a never-persisted id returns `None`.
    #[test]
    fn round2_missing_session_returns_none() {
        storage::reset();
        let mut state = MusigSigningState::default();
        assert!(round2_initialize(&ID_A, &mut state).unwrap().is_none());
    }

    /// Within the same signing pass, repeated round 2 lookups for the same id
    /// reuse the volatile cached session even though the persistent slot was
    /// already cleared.
    #[test]
    fn round2_caches_after_first_pop() {
        storage::reset();
        // Persist a session for ID_A.
        write_session_to_storage(&PsbtSession {
            id: ID_A,
            rand_root: [0x99u8; 32],
        })
        .unwrap();

        let mut state = MusigSigningState::default();
        let r1 = round2_initialize(&ID_A, &mut state).unwrap().unwrap().rand_root;
        assert_eq!(r1, [0x99u8; 32]);
        // Persistent slots are now empty.
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());

        // Second call with the same id still works via the volatile cache.
        let r2 = round2_initialize(&ID_A, &mut state).unwrap().unwrap().rand_root;
        assert_eq!(r1, r2);
    }

    /// `round1_initialize` deletes a stale persisted session with the same id
    /// (per the C ref's "client retried round 1" handling).
    #[test]
    fn round1_initialize_drops_stale_persistent() {
        storage::reset();
        write_session_to_storage(&PsbtSession {
            id: ID_A,
            rand_root: [0x55u8; 32],
        })
        .unwrap();

        let mut state = MusigSigningState::default();
        let s = round1_initialize(&ID_A, &mut state).unwrap();
        // The fresh rand_root differs from the stale one.
        assert_ne!(s.rand_root, [0x55u8; 32]);
        // And the persistent storage has been wiped.
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
    }

    /// `commit` is a no-op when no round-1 session was created (e.g. the
    /// signing pass involved no musig placeholders).
    #[test]
    fn commit_noop_on_empty_state() {
        storage::reset();
        let state = MusigSigningState::default();
        commit(&state).unwrap();
        assert!(storage::is_slot_empty(MUSIG_SESSION_ID_SLOT).unwrap());
    }
}
