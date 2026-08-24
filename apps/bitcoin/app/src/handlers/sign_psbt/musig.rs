//! MuSig2 placeholder dispatch: the glue between [`super::signing`]'s per-input loop
//! and the PSBT-structure-agnostic MuSig2 session/crypto engine in
//! `crate::handlers::musig_signing`.

use alloc::vec::Vec;

use bitcoin::{hashes::Hash, sighash::SighashCache, Transaction, TxOut};
use common::{
    bip388::{DescriptorTemplate, KeyExpression},
    errors::Error,
    fastpsbt,
};
use sdk::curve::{EcfpPrivateKey, ToPublicKey};

use crate::handlers::musig_signing::{self, MusigSigningState, SpendPath};

use super::key_resolution::{resolve_local_key_source, resolve_private_key, KeySource};
use super::sighash::{compute_taproot_sighash, ensure_prevouts, leaf_hash_for, taptree_hash_for};
use super::signing::SignedInputs;

/// Handles a single `musig(...)` placeholder for one PSBT input. Pushes either
/// a round-1 pubnonce or a round-2 partial signature into `out`, *for each*
/// participant this device controls.
pub(super) fn handle_musig_placeholder(
    input: &fastpsbt::Input<'_>,
    input_index: usize,
    placeholder_index: usize,
    kp: &KeyExpression,
    tapleaf_desc: Option<&DescriptorTemplate>,
    wallet_policy: &common::bip388::WalletPolicy,
    coords: &common::message::WalletPolicyCoordinates,
    session_id: [u8; 32],
    musig_state: &mut MusigSigningState,
    psbt: &fastpsbt::Psbt,
    sighash_cache: &mut SighashCache<&Transaction>,
    prevouts: &mut Option<Vec<TxOut>>,
    standard_fpr: u32,
    resident_fpr: u32,
    out: &mut SignedInputs,
) -> Result<(), Error> {
    // musig() can only appear inside tr() per BIP-388.
    let taptree_hash = taptree_hash_for(wallet_policy, coords)?;
    let leaf_hash = leaf_hash_for(tapleaf_desc, wallet_policy, coords)?;
    let leaf_hash_bytes: Option<[u8; 32]> = leaf_hash.map(|l| l.to_byte_array());

    let spend = match leaf_hash_bytes.as_ref() {
        Some(lh) => SpendPath::Tapscript { leaf_hash: lh },
        None => SpendPath::Keypath {
            taptree_hash: taptree_hash.as_ref(),
        },
    };

    // Identify which participants this device controls. For BIP-388 musig,
    // signing uses the *master* participant key (no `(change, address_index)`
    // suffix in the path) — that derivation is folded into the SessionContext
    // tweaks below.
    let indices = kp
        .musig_key_indices()
        .expect("kp must be musig because is_musig() returned true");
    let mut ours: Vec<KeySource> = Vec::new();
    for &participant_idx in indices {
        let key_info = &wallet_policy.key_information()[participant_idx as usize];
        if let Some(ks) = resolve_local_key_source(key_info, None, standard_fpr, resident_fpr) {
            ours.push(ks);
        }
    }
    if ours.is_empty() {
        return Ok(());
    }

    // Per-input info is the same for every "ours" participant; compute once.
    let info = musig_signing::compute_per_input_info(
        wallet_policy.key_information(),
        kp,
        coords.is_change,
        coords.address_index,
        spend,
    )?;

    for ks in &ours {
        // This participant's own derived child pubkey (= one entry in
        // `info.keys`).
        let hd = resolve_private_key(ks)?;
        let internal_pk = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*hd.privkey)
            .to_public_key()
            .to_compressed();

        let my_pubnonce_in_psbt = input
            .get_musig2_pub_nonce(
                &internal_pk,
                &info.agg_key_tweaked,
                leaf_hash_bytes.as_ref(),
            )
            .map_err(|_| Error::FailedToDeserializePsbt)?
            .is_some();

        if !my_pubnonce_in_psbt {
            // Round 1: yield the device's pubnonce.
            let session = musig_signing::round1_initialize(&session_id, musig_state)?;
            let data = musig_signing::produce_pubnonce(
                &info,
                &internal_pk,
                session,
                input_index as u32,
                placeholder_index as u32,
                spend,
            )?;
            out.musig_pubnonces.push(data);
        } else {
            // Round 2: aggregate nonces and produce a partial signature.
            let prev = ensure_prevouts(prevouts, psbt)?;
            let sighash = compute_taproot_sighash(input_index, sighash_cache, prev, leaf_hash)?;
            let session = musig_signing::round2_initialize(&session_id, musig_state)?
                .ok_or(Error::MissingMusigSession)?;
            let data = musig_signing::sign_sighash_musig(
                &info,
                &internal_pk,
                &*hd.privkey,
                &sighash,
                session,
                input_index as u32,
                placeholder_index as u32,
                input,
                spend,
            )?;
            out.musig_partial_sigs.push(data);
        }
    }

    Ok(())
}
