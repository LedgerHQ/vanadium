//! The interface through which a signing policy observes the transaction.
//!
//! This module is the boundary between the engine and the data it queries. It must
//! stay free of engine internals — no ecall numbers, no memory layout, no
//! interpreter types — so that a different execution backend can reuse it
//! unchanged.
//!
//! Two levels of absence are distinguished throughout: the outer `Option` is
//! `None` when an index is out of range, which is a programming error in the
//! policy; the inner `Option` is `None` when the datum is legitimately absent,
//! which the ABI reports as `NOT_FOUND`.

/// One opportunity for a policy-bound key to produce one signature: a plain key in
/// a descriptor placeholder, or one `musig(...)` participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyAttempt {
    pub input_index: u32,
    pub placeholder_index: u32,
    pub is_musig: bool,
}

/// Wallet-policy coordinates, flattened. Other account types are not exposed, so
/// that adding one cannot silently change what a policy sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyCoords {
    pub account_index: u32,
    pub is_change: bool,
    pub address_index: u32,
}

/// The prevout amount was verified against the full previous transaction.
pub const INPUT_FLAG_AMOUNT_VERIFIED: u32 = 1 << 0;
/// A witness UTXO is present for this input.
pub const INPUT_FLAG_HAS_WITNESS_UTXO: u32 = 1 << 1;
/// The input belongs to a recognized account.
pub const INPUT_FLAG_IN_ACCOUNT: u32 = 1 << 2;
/// Bit position of the 4-bit segwit-version field: segwit version + 1, or 0 when
/// the input is not segwit.
pub const INPUT_FLAG_SEGWIT_SHIFT: u32 = 8;

/// The output belongs to a recognized account (change or internal).
pub const OUTPUT_FLAG_IS_INTERNAL: u32 = 1 << 0;
/// The output carries a valid signature from a registered identity key.
pub const OUTPUT_FLAG_IS_AUTHENTICATED: u32 = 1 << 1;

/// Everything a signing policy can learn about the transaction being signed.
///
/// Deliberately absent: randomness, the clock, the block height, persistent
/// storage, private keys, signing, and the display.
pub trait PolicyHost {
    // --- transaction shape ---

    fn tx_version(&self) -> u32;
    /// The resolved locktime of the unsigned transaction, not the raw fallback.
    fn locktime(&self) -> u32;
    fn input_count(&self) -> u32;
    fn output_count(&self) -> u32;
    fn inputs_total(&self) -> u64;
    fn outputs_total(&self) -> u64;

    fn fee(&self) -> u64 {
        self.inputs_total().saturating_sub(self.outputs_total())
    }

    // --- the running policy and its signing attempts ---

    /// Hash of the policy being evaluated, so a program can reconstruct its own
    /// key path.
    fn policy_hash(&self) -> [u8; 32];

    /// The attempts this policy will be invoked for, in the order the engine uses:
    /// input index ascending, then placeholder index ascending, then musig
    /// participant order.
    fn attempts(&self) -> &[PolicyAttempt];

    /// The compressed public key that would produce attempt `k`'s signature.
    fn self_pubkey(&self, k: u32) -> Option<[u8; 33]>;

    // --- inputs ---

    fn input_amount(&self, i: u32) -> Option<u64>;
    /// 32-byte txid in internal byte order, then the 4-byte little-endian vout.
    fn input_prevout(&self, i: u32) -> Option<[u8; 36]>;
    fn input_sequence(&self, i: u32) -> Option<u32>;
    fn input_script_pubkey(&self, i: u32) -> Option<&[u8]>;
    fn input_flags(&self, i: u32) -> Option<u32>;
    fn input_account(&self, i: u32) -> Option<Option<PolicyCoords>>;
    fn input_taptree_hash(&self, i: u32) -> Option<Option<[u8; 32]>>;

    // --- outputs ---

    fn output_amount(&self, i: u32) -> Option<u64>;
    fn output_script_pubkey(&self, i: u32) -> Option<&[u8]>;
    fn output_flags(&self, i: u32) -> Option<u32>;
    fn output_account(&self, i: u32) -> Option<Option<PolicyCoords>>;

    // --- raw access ---

    /// The PSBT exactly as received, before any interpretation. The escape hatch
    /// for structures this interface has no accessor for.
    fn raw_psbt(&self) -> &[u8];
}
