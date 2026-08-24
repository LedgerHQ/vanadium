//! The state threaded through the signing pass.
//!
//! A leaf module: it defines the types that [`super::signing`] and [`super::musig`]
//! both operate on, so neither has to depend on the other.

use alloc::vec::Vec;
use core::cell::OnceCell;

use bitcoin::{sighash::SighashCache, Transaction, TxOut};
use common::{
    bip388::{DescriptorTemplate, KeyExpression, WalletPolicy},
    errors::Error,
    fastpsbt,
    message::{MuSig2PartialSignature, MuSig2Pubnonce, PartialSignature, WalletPolicyCoordinates},
};

use super::key_resolution::LocalKeys;
use super::sighash::taptree_hash_for;

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
    pub(super) local_keys: LocalKeys,
    pub(super) out: SignedInputs,
}

/// Where in the PSBT the signing paths currently are: one (input, placeholder) pair,
/// plus the account it belongs to.
pub(super) struct PlaceholderCtx<'a> {
    pub(super) input: &'a fastpsbt::Input<'a>,
    pub(super) input_index: usize,
    pub(super) placeholder_index: usize,
    pub(super) account_id: u32,
    pub(super) wallet_policy: &'a WalletPolicy,
    pub(super) coords: &'a WalletPolicyCoordinates,
    pub(super) kp: &'a KeyExpression,
    /// `Some` for a script-path placeholder, `None` for keypath / non-taproot.
    pub(super) tapleaf_desc: Option<&'a DescriptorTemplate>,
    /// Binds MuSig2 session state to this (wallet policy, transaction) pair.
    pub(super) session_id: [u8; 32],
    /// Backs [`Self::taptree_hash`]. Owned by the input, so all of its placeholders
    /// share one answer.
    pub(super) taptree_hash_memo: &'a OnceCell<Option<[u8; 32]>>,
}

impl PlaceholderCtx<'_> {
    /// The merkle root of the account's tap tree at [`Self::coords`], or `None` for a
    /// `tr()` with no script tree.
    ///
    /// Only key-path spends need this — a script-path spend signs with the untweaked
    /// leaf key — so ask for it only on that branch: the walk behind it is by far the
    /// most expensive thing in the signing pass. The first placeholder of an input to
    /// ask pays for it; the rest read the memo.
    pub(super) fn taptree_hash(&self) -> Result<Option<[u8; 32]>, Error> {
        if let Some(cached) = self.taptree_hash_memo.get() {
            return Ok(*cached);
        }
        let computed = taptree_hash_for(self.wallet_policy, self.coords)?;
        let _ = self.taptree_hash_memo.set(computed);
        Ok(computed)
    }
}
