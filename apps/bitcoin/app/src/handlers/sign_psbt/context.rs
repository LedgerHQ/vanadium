//! The state threaded through the signing pass.
//!
//! A leaf module: it defines the types that [`super::signing`] and [`super::musig`]
//! both operate on, so neither has to depend on the other.

use alloc::vec::Vec;

use bitcoin::{sighash::SighashCache, Transaction, TxOut};
use common::{
    bip388::{DescriptorTemplate, KeyExpression, WalletPolicy},
    fastpsbt,
    message::{MuSig2PartialSignature, MuSig2Pubnonce, PartialSignature, WalletPolicyCoordinates},
};

/// All signing outputs produced by a single `SignPsbt` call.
pub(super) struct SignedInputs {
    pub(super) signatures: Vec<PartialSignature>,
    pub(super) musig_pubnonces: Vec<MuSig2Pubnonce>,
    pub(super) musig_partial_sigs: Vec<MuSig2PartialSignature>,
}

/// State shared by every input of one signing pass: the PSBT, the caches that all
/// sighashes draw on, the local master fingerprints, and the accumulating output.
///
/// Both signing paths take this by `&mut` and reach into individual fields, which lets
/// them hold the prevouts and the sighash cache borrowed at the same time.
pub(super) struct SigningCtx<'a> {
    pub(super) psbt: &'a fastpsbt::Psbt<'a>,
    pub(super) sighash_cache: SighashCache<&'a Transaction>,
    /// Materialized on first use by [`super::analyze::ensure_prevouts`]; taproot inputs
    /// all share it.
    pub(super) prevouts: Option<Vec<TxOut>>,
    pub(super) standard_fpr: u32,
    pub(super) resident_fpr: u32,
    pub(super) out: SignedInputs,
}

/// Where in the PSBT the signing paths currently are: one (input, placeholder) pair,
/// plus the account it belongs to.
pub(super) struct PlaceholderCtx<'a> {
    pub(super) input: &'a fastpsbt::Input<'a>,
    pub(super) input_index: usize,
    pub(super) placeholder_index: usize,
    pub(super) wallet_policy: &'a WalletPolicy,
    pub(super) coords: &'a WalletPolicyCoordinates,
    pub(super) kp: &'a KeyExpression,
    /// `Some` for a script-path placeholder, `None` for keypath / non-taproot.
    pub(super) tapleaf_desc: Option<&'a DescriptorTemplate>,
    /// Binds MuSig2 session state to this (wallet policy, transaction) pair.
    pub(super) session_id: [u8; 32],
}
