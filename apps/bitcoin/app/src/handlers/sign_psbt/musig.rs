//! MuSig2 placeholder dispatch: the glue between [`super::signing`]'s per-input loop
//! and the PSBT-structure-agnostic MuSig2 session/crypto engine in
//! `crate::handlers::musig_signing`.
//!
//! Depends on [`super::sighash`] and [`super::key_resolution`] but deliberately not on
//! [`super::signing`], which dispatches to this module.

use alloc::vec::Vec;

use bitcoin::hashes::Hash;
use common::errors::Error;
use sdk::curve::{EcfpPrivateKey, ToPublicKey};

use crate::handlers::musig_signing::{self, MusigSigningState, SpendPath};

use super::analyze::ensure_prevouts;
use super::context::{PlaceholderCtx, SigningCtx};
use super::key_resolution::{resolve_private_key, KeySource};
use super::sighash::{compute_taproot_sighash, is_taproot_policy, leaf_hash_for};

/// Handles a single `musig(...)` placeholder for one PSBT input. Pushes either
/// a round-1 pubnonce or a round-2 partial signature into `out`, *for each*
/// participant this device controls.
pub(super) fn handle_musig_placeholder(
    ctx: &mut SigningCtx<'_>,
    ph: &PlaceholderCtx<'_>,
    musig_state: &mut MusigSigningState,
) -> Result<(), Error> {
    // musig() can only appear inside tr() per BIP-388; this rejects anything else. It
    // only inspects the descriptor's kind, so it is free — the tree root itself is
    // fetched below, and only if this turns out to be a key-path spend.
    if !is_taproot_policy(ph.wallet_policy) {
        return Err(Error::UnexpectedTaprootPolicy);
    }

    // Identify which participants this device controls. For BIP-388 musig,
    // signing uses the *master* participant key (no `(change, address_index)`
    // suffix in the path) — that derivation is folded into the SessionContext
    // tweaks below.
    //
    // Done before any of the tapleaf work, so a placeholder we hold no key for costs
    // nothing beyond this scan.
    let indices = ph
        .kp
        .musig_key_indices()
        .expect("kp must be musig because is_musig() returned true");
    let mut ours: Vec<KeySource> = Vec::new();
    for &participant_idx in indices {
        let key_info = &ph.wallet_policy.key_information()[participant_idx as usize];
        if let Some(ks) = ctx
            .local_keys
            .resolve(key_info, (ph.account_id, participant_idx), None)
        {
            ours.push(ks);
        }
    }
    if ours.is_empty() {
        return Ok(());
    }

    let leaf_hash = leaf_hash_for(ph.tapleaf_desc, ph.wallet_policy, ph.coords)?;
    let leaf_hash_bytes: Option<[u8; 32]> = leaf_hash.map(|l| l.to_byte_array());

    // Only the key-path spend is tweaked by the tree root; a tapscript spend never
    // reads it, so it doesn't pay for the walk.
    let taptree_hash = match leaf_hash_bytes {
        Some(_) => None,
        None => ph.taptree_hash()?,
    };

    let spend = match leaf_hash_bytes.as_ref() {
        Some(lh) => SpendPath::Tapscript { leaf_hash: lh },
        None => SpendPath::Keypath {
            taptree_hash: taptree_hash.as_ref(),
        },
    };

    // Per-input info is the same for every "ours" participant; compute once.
    let info = musig_signing::compute_per_input_info(
        ph.wallet_policy.key_information(),
        ph.kp,
        ph.coords.is_change,
        ph.coords.address_index,
        spend,
    )?;

    for ks in &ours {
        // This participant's own derived child pubkey (= one entry in
        // `info.keys`).
        let hd = resolve_private_key(ks)?;
        let internal_pk = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*hd.privkey)
            .to_public_key()
            .to_compressed();

        let my_pubnonce_in_psbt = ph
            .input
            .get_musig2_pub_nonce(
                &internal_pk,
                &info.agg_key_tweaked,
                leaf_hash_bytes.as_ref(),
            )
            .map_err(|_| Error::FailedToDeserializePsbt)?
            .is_some();

        if !my_pubnonce_in_psbt {
            // Round 1: yield the device's pubnonce.
            let session = musig_signing::round1_initialize(&ph.session_id, musig_state)?;
            let data = musig_signing::produce_pubnonce(
                &info,
                &internal_pk,
                session,
                ph.input_index as u32,
                ph.placeholder_index as u32,
                spend,
            )?;
            ctx.out.musig_pubnonces.push(data);
        } else {
            // Round 2: aggregate nonces and produce a partial signature.
            let prev = ensure_prevouts(&mut ctx.prevouts, ctx.psbt)?;
            let sighash =
                compute_taproot_sighash(ph.input_index, &mut ctx.sighash_cache, prev, leaf_hash)?;
            let session = musig_signing::round2_initialize(&ph.session_id, musig_state)?
                .ok_or(Error::MissingMusigSession)?;
            let data = musig_signing::sign_sighash_musig(
                &info,
                &internal_pk,
                &*hd.privkey,
                &sighash,
                session,
                ph.input_index as u32,
                ph.placeholder_index as u32,
                ph.input,
                spend,
            )?;
            ctx.out.musig_partial_sigs.push(data);
        }
    }

    Ok(())
}
