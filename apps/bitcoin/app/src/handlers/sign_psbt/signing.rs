//! Plain-key signing (ECDSA and Schnorr) and the per-input/per-placeholder loop that
//! dispatches each PSBT input to either the plain-key path here or the MuSig2 path in
//! [`super::musig`].

use alloc::vec::Vec;

use bitcoin::{
    bip32::ChildNumber,
    hashes::Hash,
    key::{Keypair, TapTweak},
    sighash::SighashCache,
    TapLeafHash, TapNodeHash, TapSighashType, Transaction, TxOut,
};
use common::{
    account::Account,
    bip388::SegwitVersion,
    errors::Error,
    fastpsbt,
    message::PartialSignature,
    psbt::{PsbtAccount, PsbtAccountCoordinates},
};
use sdk::curve::{Curve, EcfpPrivateKey, ToPublicKey};

use crate::handlers::musig_signing::{self, MusigSigningState};
use crate::resident_key::get_resident_master_fingerprint;

use super::analyze::{ensure_prevouts, TransactionSummary};
use super::context::{PlaceholderCtx, SignedInputs, SigningCtx};
use super::key_resolution::{resolve_local_key_source, resolve_private_key, KeySource};
use super::musig;
use super::sighash::{compute_taproot_sighash, leaf_hash_for, taptree_hash_for};

fn sign_input_ecdsa(
    psbt: &fastpsbt::Psbt,
    input_index: usize,
    sighash_cache: &mut SighashCache<&Transaction>,
    key_source: &KeySource,
) -> Result<PartialSignature, Error> {
    let (sighash, sighash_type) = psbt
        .sighash_ecdsa(input_index, sighash_cache)
        .map_err(|_| Error::ErrorComputingSighash)?;

    let hd_node = resolve_private_key(key_source)?;
    let privkey: EcfpPrivateKey<sdk::curve::Secp256k1, 32> = EcfpPrivateKey::new(*hd_node.privkey);
    let pubkey = privkey.to_public_key();
    let pubkey_uncompressed = pubkey.as_ref().to_bytes();
    let mut pubkey_compressed = Vec::with_capacity(33);
    pubkey_compressed.push(2 + pubkey_uncompressed[64] % 2);
    pubkey_compressed.extend_from_slice(&pubkey_uncompressed[1..33]);

    let mut signature = privkey
        .ecdsa_sign_hash(sighash.as_ref())
        .map_err(|_| Error::SigningFailed)?;
    signature.push(sighash_type.to_u32() as u8);

    Ok(PartialSignature {
        input_index: input_index as u32,
        signature,
        pubkey: pubkey_compressed,
        leaf_hash: None,
    })
}

fn sign_input_schnorr(
    input_index: usize,
    sighash_cache: &mut SighashCache<&Transaction>,
    prevouts: &[TxOut],
    key_source: &KeySource,
    taptree_hash: Option<[u8; 32]>,
    leaf_hash: Option<TapLeafHash>,
) -> Result<PartialSignature, Error> {
    let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now
    let sighash = compute_taproot_sighash(input_index, sighash_cache, prevouts, leaf_hash)?;

    let hd_node = resolve_private_key(key_source)?;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let keypair: Keypair = Keypair::from_seckey_slice(&secp, hd_node.privkey.as_ref())
        .map_err(|_| Error::InvalidKey)?;

    let signing_privkey = if !leaf_hash.is_none() {
        // script path signing, no further tweak
        EcfpPrivateKey::new(keypair.secret_bytes())
    } else {
        // key path signing, apply tap_tweak
        let tweaked_keypair =
            keypair.tap_tweak(&secp, taptree_hash.map(TapNodeHash::from_byte_array));

        EcfpPrivateKey::new(tweaked_keypair.to_keypair().secret_bytes())
    };

    let mut signature = signing_privkey
        .schnorr_sign(sighash.as_ref(), None)
        .map_err(|_| Error::SigningFailed)?;

    if sighash_type != TapSighashType::Default {
        signature.push(sighash_type as u8)
    }

    Ok(PartialSignature {
        input_index: input_index as u32,
        signature,
        pubkey: signing_privkey.to_public_key().as_ref().to_bytes()[1..33].to_vec(),
        leaf_hash: leaf_hash.map(|x| x.to_byte_array().to_vec()),
    })
}

/// Signs a single plain-key placeholder for one input: dispatches on the input's
/// segwit version to produce either an ECDSA or a Schnorr partial signature, and
/// pushes it into `ctx.out`. Mirrors the shape of [`musig::handle_musig_placeholder`].
fn sign_plain_key_placeholder(
    ctx: &mut SigningCtx<'_>,
    ph: &PlaceholderCtx<'_>,
    key_source: &KeySource,
) -> Result<(), Error> {
    if ph.input.witness_utxo.is_some() {
        match ph.wallet_policy.get_segwit_version() {
            Ok(SegwitVersion::SegwitV0) => {
                let sig =
                    sign_input_ecdsa(ctx.psbt, ph.input_index, &mut ctx.sighash_cache, key_source)?;
                ctx.out.signatures.push(sig);
            }
            Ok(SegwitVersion::Taproot) => {
                let taptree_hash = taptree_hash_for(ph.wallet_policy, ph.coords)?;
                let leaf_hash = leaf_hash_for(ph.tapleaf_desc, ph.wallet_policy, ph.coords)?;
                let prev = ensure_prevouts(&mut ctx.prevouts, ctx.psbt)?;
                let sig = sign_input_schnorr(
                    ph.input_index,
                    &mut ctx.sighash_cache,
                    prev,
                    key_source,
                    taptree_hash,
                    leaf_hash,
                )?;
                ctx.out.signatures.push(sig);
            }
            _ => return Err(Error::UnexpectedSegwitVersion),
        }
    } else {
        let sig = sign_input_ecdsa(ctx.psbt, ph.input_index, &mut ctx.sighash_cache, key_source)?;
        ctx.out.signatures.push(sig);
    }
    Ok(())
}

/// Sign all inputs of the PSBT, producing the per-input signing material.
///
/// For each (input, placeholder) where this device controls the key:
/// - Plain key + segwit v0 → ECDSA partial signature.
/// - Plain key + taproot   → Schnorr partial signature.
/// - Plain key + legacy    → ECDSA partial signature.
/// - musig() inside tr()   → round 1 pubnonce or round 2 partial signature,
///   depending on whether this device's pubnonce is already in the PSBT.
pub(super) fn sign_all_inputs(
    psbt: &fastpsbt::Psbt,
    summary: &TransactionSummary,
    musig_state: &mut MusigSigningState,
) -> Result<SignedInputs, Error> {
    let unsigned_tx = psbt
        .unsigned_tx()
        .map_err(|_| Error::FailedUnsignedTransaction)?;
    let unsigned_tx_id: [u8; 32] = unsigned_tx.compute_txid().to_byte_array();

    let mut ctx = SigningCtx {
        psbt,
        sighash_cache: SighashCache::new(unsigned_tx),
        prevouts: None,
        standard_fpr: sdk::curve::Secp256k1::get_master_fingerprint(),
        resident_fpr: get_resident_master_fingerprint()?,
        out: SignedInputs {
            signatures: Vec::with_capacity(psbt.inputs.len()),
            musig_pubnonces: Vec::new(),
            musig_partial_sigs: Vec::new(),
        },
    };

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let (account_id, ref coords) = summary.input_coordinates[input_index];
        let PsbtAccountCoordinates::WalletPolicy(coords) = coords;
        let PsbtAccount::WalletPolicy(wallet_policy) = &summary.accounts[account_id as usize];

        // (wallet, tx) → 32-byte session id, used to bind MuSig2 session
        // state to a specific (wallet policy, transaction) pair.
        let account_name = summary.account_names[account_id as usize]
            .as_deref()
            .unwrap_or("");
        let wallet_id = wallet_policy.get_id(account_name);
        let session_id = musig_signing::compute_psbt_session_id(&wallet_id, &unsigned_tx_id);

        for (placeholder_index, (kp, tapleaf_desc)) in wallet_policy
            .descriptor_template()
            .placeholders()
            .enumerate()
        {
            let ph = PlaceholderCtx {
                input,
                input_index,
                placeholder_index,
                wallet_policy,
                coords,
                kp,
                tapleaf_desc,
                session_id,
            };

            if kp.is_musig() {
                musig::handle_musig_placeholder(&mut ctx, &ph, musig_state)?;
                continue;
            }

            // ===== plain key path =====
            let key_index = kp
                .plain_key_index()
                .expect("kp must be plain because not musig");
            let key_info = &wallet_policy.key_information()[key_index as usize];
            let change_step: ChildNumber = if !coords.is_change {
                kp.num1.into()
            } else {
                kp.num2.into()
            };
            let address_index: ChildNumber = coords.address_index.into();
            let Some(key_source) = resolve_local_key_source(
                key_info,
                Some((change_step, address_index)),
                ctx.standard_fpr,
                ctx.resident_fpr,
            ) else {
                continue;
            };

            sign_plain_key_placeholder(&mut ctx, &ph, &key_source)?;
        }
    }

    Ok(ctx.out)
}
