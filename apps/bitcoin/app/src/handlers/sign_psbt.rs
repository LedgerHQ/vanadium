use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use common::{
    account::Account,
    bip388::{DescriptorTemplate, KeyExpression, SegwitVersion},
    errors::Error,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_OUTPUT},
    message::{MuSig2PartialSignature, MuSig2Pubnonce, PartialSignature, Response},
    por::{ProofOfRegistration, Registerable},
    psbt::{
        PsbtAccount, PsbtAccountCoordinates, PsbtAccountGlobalRead, PsbtAccountInputRead,
        PsbtAccountOutputRead, PsbtIdAuthGlobalRead, PsbtOutputAuthRead,
    },
    script::ToScript,
    taproot::{GetTapLeafHash, GetTapTreeHash},
};

use bitcoin::{
    bip32::ChildNumber,
    hashes::Hash,
    key::{Keypair, TapTweak},
    sighash::SighashCache,
    Address, ScriptBuf, TapLeafHash, TapNodeHash, TapSighashType, Transaction, TxOut,
};
use common::fastpsbt;
use sdk::{
    curve::{Curve, EcfpPrivateKey, EcfpPublicKey, HDPrivNode, ToPublicKey},
    ux::TagValue,
};

use crate::bip32::KeyTree;
use crate::constants::COIN_TICKER;
use crate::handlers::musig_signing::{self, MusigSigningState, SpendPath};
use crate::resident_key::{derive_resident_hd_node, get_resident_master_fingerprint};

#[cfg(not(any(test, feature = "autoapprove")))]
use sdk::ux::Icon;

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_warning_high_fee(app: &mut sdk::App, fee_percent: u64) -> bool {
    app.show_confirm_reject(
        "High fees",
        &format!("Transaction fee fraction is higher than {}%", fee_percent),
        "Continue",
        "Reject",
    )
    .await
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_warning_high_fee(_app: &mut sdk::App, _fee_percent: u64) -> bool {
    true
}

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_warning_unverified_inputs(app: &mut sdk::App) -> bool {
    app.show_confirm_reject(
        "Unverified inputs",
        "Some inputs could not be verified.\nReject if you're not sure.",
        "Continue",
        "Reject",
    )
    .await
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_warning_unverified_inputs(_app: &mut sdk::App) -> bool {
    true
}

#[cfg(not(any(test, feature = "autoapprove")))]
async fn display_transaction(app: &mut sdk::App, pairs: &[TagValue]) -> bool {
    // message on speculos or real device

    let button_text = if sdk::ux::has_page_api() {
        "Hold to sign"
    } else {
        "Confirm"
    };

    let (intro_text, intro_subtext) = if sdk::ux::has_page_api() {
        ("Review transaction\nto send Bitcoin", "")
    } else {
        ("Review transaction", "to send Bitcoin")
    };
    app.review_pairs(
        intro_text,
        intro_subtext,
        pairs,
        "Sign transaction",
        button_text,
        true,
    )
    .await
}

#[cfg(any(test, feature = "autoapprove"))]
async fn display_transaction(_app: &mut sdk::App, _pairs: &[TagValue]) -> bool {
    true
}

const SATS_PER_BTC: u64 = 100_000_000;

fn format_amount(value: u64, ticker: &str) -> String {
    let whole_part = value / SATS_PER_BTC;
    let fractional_part = value % SATS_PER_BTC;
    // Pad fractional part with leading zeros to ensure 8 digits
    format!("{}.{:08} {}", whole_part, fractional_part, ticker)
}

/// Identifies how the signing private key should be obtained: a key tree and a
/// full BIP-32 derivation path relative to that tree's master.
struct KeySource {
    tree: KeyTree,
    path: Vec<ChildNumber>,
}

/// Resolves a `KeySource` into an `HDPrivNode` containing the final private key.
fn resolve_private_key(
    key_source: &KeySource,
) -> Result<HDPrivNode<sdk::curve::Secp256k1, 32>, Error> {
    let path: Vec<u32> = key_source.path.iter().map(|&x| x.into()).collect();
    match key_source.tree {
        KeyTree::Standard => {
            sdk::curve::Secp256k1::derive_hd_node(&path).map_err(|_| Error::KeyDerivationFailed)
        }
        KeyTree::Resident => derive_resident_hd_node(&path),
    }
}

/// Identifies whether `key_info` refers to a locally-controlled key (Standard
/// or Resident tree) and, if so, returns its full BIP-32 path including the
/// `(change, address_index)` suffix. Verifies the derivation by recomputing
/// the pubkey + chaincode so a fingerprint collision cannot trick us into
/// signing.
///
/// Returns `None` if:
/// - the key has no origin info (bare xpub, can't be derived locally), or
/// - the fingerprint matches neither local tree, or
/// - the local derivation doesn't yield the claimed pubkey/chaincode.
fn resolve_local_key_source(
    key_info: &common::bip388::KeyInformation,
    change_step: ChildNumber,
    address_index: ChildNumber,
    standard_fpr: u32,
    resident_fpr: u32,
) -> Option<KeySource> {
    let key_origin = key_info.origin_info.as_ref()?;

    let tree = if key_origin.fingerprint == standard_fpr {
        KeyTree::Standard
    } else if key_origin.fingerprint == resident_fpr {
        KeyTree::Resident
    } else {
        return None;
    };

    let mut path = Vec::with_capacity(key_origin.derivation_path.len() + 2);
    path.extend_from_slice(&key_origin.derivation_path);
    path.push(change_step);
    path.push(address_index);

    let path_u32: Vec<u32> = key_origin
        .derivation_path
        .iter()
        .map(|&s| u32::from(s))
        .collect();
    let claim_node = match tree {
        KeyTree::Standard => sdk::curve::Secp256k1::derive_hd_node(&path_u32).ok()?,
        KeyTree::Resident => derive_resident_hd_node(&path_u32).ok()?,
    };

    let derived_pubkey = EcfpPrivateKey::<sdk::curve::Secp256k1, 32>::new(*claim_node.privkey)
        .to_public_key()
        .to_compressed();
    let expected_pubkey = key_info.pubkey.public_key.serialize();
    let expected_chaincode: &[u8; 32] = key_info.pubkey.chain_code.as_ref();
    if derived_pubkey != expected_pubkey || claim_node.chaincode != *expected_chaincode {
        return None;
    }

    Some(KeySource { tree, path })
}

/// Computes a 32-byte BIP-341 sighash for the given input. The output goes to
/// either `schnorr_sign` (plain key path) or `musig::sign` (musig path).
fn compute_taproot_sighash(
    input_index: usize,
    sighash_cache: &mut SighashCache<&Transaction>,
    prevouts: &[TxOut],
    leaf_hash: Option<TapLeafHash>,
) -> Result<[u8; 32], Error> {
    let sighash_type = TapSighashType::Default;
    let sighash = if let Some(leaf_hash) = leaf_hash {
        sighash_cache
            .taproot_script_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(prevouts),
                leaf_hash,
                sighash_type,
            )
            .map_err(|_| Error::ErrorComputingSighash)?
    } else {
        sighash_cache
            .taproot_key_spend_signature_hash(
                input_index,
                &bitcoin::sighash::Prevouts::All(prevouts),
                sighash_type,
            )
            .map_err(|_| Error::ErrorComputingSighash)?
    };
    Ok(sighash.to_byte_array())
}

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
        let tweaked_keypair = keypair.tap_tweak(
            &secp,
            taptree_hash.map(|t| TapNodeHash::from_slice(&t).unwrap()),
        );

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

/// A script derivation check to be verified in the background task.
struct ScriptCheck {
    account_id: u32,
    is_change: bool,
    address_index: u32,
    expected_script: ScriptBuf,
    is_input: bool,
}

/// The result of analyzing a PSBT: lightweight data needed for UI display and signing.
struct TransactionSummary {
    accounts: Vec<PsbtAccount>,
    account_names: Vec<Option<String>>,
    input_coordinates: Vec<(u32, PsbtAccountCoordinates)>,
    account_spent_amounts: Vec<i64>,
    external_outputs_indexes: Vec<usize>,
    /// Parallel to `external_outputs_indexes`: `Some(name)` if the output carries a valid
    /// id_auth proof from a registered identity key, `None` otherwise.
    external_output_auth_names: Vec<Option<String>>,
    inputs_total_amount: u64,
    outputs_total_amount: u64,
    warn_unverified_inputs: bool,
}

impl TransactionSummary {
    fn fee(&self) -> u64 {
        self.inputs_total_amount - self.outputs_total_amount
    }
}

/// Perform cheap structural validation of the PSBT and extract the data needed for
/// UI display (`TransactionSummary`) and deferred cryptographic verification.
///
/// Returns the summary (which owns accounts and account names), plus the
/// proof-of-registration list and script checks needed by `verify_transaction`.
///
/// Expensive operations (proof-of-registration validation, script derivation) are NOT
/// performed here — they are deferred to `verify_transaction`.
fn analyze_transaction(
    psbt: &fastpsbt::Psbt,
) -> Result<
    (
        TransactionSummary,
        Vec<ProofOfRegistration<common::bip388::WalletPolicy>>,
        Vec<ScriptCheck>,
    ),
    Error,
> {
    let accounts = psbt
        .get_accounts()
        .map_err(|_| Error::InvalidWalletPolicy)?;

    // Extract account names and raw proof-of-registration bytes
    let mut account_names = Vec::with_capacity(accounts.len());
    let mut account_proofs = Vec::with_capacity(accounts.len());
    for account_id in 0..accounts.len() {
        let name = psbt
            .get_account_name(account_id as u32)
            .map_err(|_| Error::InvalidWalletPolicy)?;
        account_names.push(name);

        let por = psbt
            .get_account_proof_of_registration(account_id as u32)
            .map_err(|_| Error::InvalidWalletPolicy)?;
        let por = por.ok_or(Error::DefaultAccountsNotSupported)?;
        let por = ProofOfRegistration::from_bytes(
            por.try_into()
                .map_err(|_| Error::InvalidProofOfRegistrationLength)?,
        );
        account_proofs.push(por);
    }

    // Retrieve registered identity keys from the global PSBT section and verify their
    // proof of registration.  Build a lookup map from compressed pubkey to name.
    let registered_identity_keys = psbt
        .get_registered_identity_keys()
        .map_err(|_| Error::InvalidIdentitySignature)?;
    let mut identity_key_names: Vec<([u8; 33], String)> =
        Vec::with_capacity(registered_identity_keys.len());
    for rik in &registered_identity_keys {
        let ik = IdentityKey::new(rik.pubkey).map_err(|_| Error::InvalidIdentitySignature)?;
        let expected_por = ProofOfRegistration::<IdentityKey>::new(&ik.registration_id(&rik.name));
        let actual_por = ProofOfRegistration::<IdentityKey>::from_bytes(rik.por);
        if actual_por != expected_por {
            return Err(Error::InvalidProofOfRegistration);
        }
        identity_key_names.push((rik.pubkey, rik.name.clone()));
    }

    let mut account_spent_amounts: Vec<i64> = vec![0; accounts.len()];
    let mut external_outputs_indexes = Vec::new();
    let mut external_output_auth_names: Vec<Option<String>> = Vec::new();
    let mut inputs_total_amount: u64 = 0;
    let mut outputs_total_amount: u64 = 0;
    let mut warn_unverified_inputs = false;
    let mut script_checks = Vec::new();

    /***** extract account coordinates for all inputs *****/

    let input_coordinates: Vec<(u32, PsbtAccountCoordinates)> = psbt
        .inputs
        .iter()
        .map(|input| {
            input
                .get_account_coordinates()
                .map_err(|_| Error::FailedToGetAccounts)?
                .ok_or(Error::ExternalInputsNotSupported)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    /***** input checks (structural only — script derivation is deferred) *****/

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let (account_id, ref coords) = input_coordinates[input_index];

        if account_id as usize >= accounts.len() {
            return Err(Error::InvalidAccountId);
        }

        let PsbtAccount::WalletPolicy(wallet_policy) = &accounts[account_id as usize];
        let PsbtAccountCoordinates::WalletPolicy(coords) = coords;

        let segwit_version = wallet_policy
            .get_segwit_version()
            .map_err(|_| Error::InvalidWalletPolicy)?;

        if segwit_version == SegwitVersion::Legacy && input.witness_utxo.is_some() {
            return Err(Error::WitnessUtxoNotAllowedForLegacy);
        }

        if segwit_version == SegwitVersion::Legacy || segwit_version == SegwitVersion::SegwitV0 {
            match input
                .get_non_witness_utxo()
                .map_err(|_| Error::InvalidNonWitnessUtxo)?
            {
                Some(tx) => {
                    let computed_txid = tx.compute_txid();
                    if input.previous_txid != Some(computed_txid.as_byte_array()) {
                        return Err(Error::NonWitnessUtxoMismatch);
                    }
                }
                None => {
                    if segwit_version == SegwitVersion::Legacy {
                        return Err(Error::NonWitnessUtxoRequired);
                    } else if segwit_version == SegwitVersion::SegwitV0 {
                        warn_unverified_inputs = true;
                    }
                }
            }
        }

        if segwit_version.is_segwit() && input.witness_utxo.is_none() {
            return Err(Error::WitnessUtxoRequiredForSegwit);
        }

        let tx_out: &TxOut = if let Some(witness_utxo) = input
            .get_witness_utxo()
            .map_err(|_| Error::InvalidWitnessUtxo)?
        {
            let script = if let Some(redeem_script) = input.redeem_script {
                let redeem_script = ScriptBuf::from_bytes(redeem_script.to_vec());
                if witness_utxo.script_pubkey != redeem_script.to_p2sh() {
                    return Err(Error::RedeemScriptMismatchWitness);
                }
                redeem_script
            } else {
                witness_utxo.script_pubkey.clone()
            };

            if script.is_p2wsh() {
                if let Some(witness_script) = &input.witness_script {
                    let witness_script = ScriptBuf::from_bytes(witness_script.to_vec());
                    if script != witness_script.to_p2wsh() {
                        return Err(Error::WitnessScriptMismatchWitness);
                    }
                } else {
                    return Err(Error::WitnessScriptRequiredForP2WSH);
                }
            }
            &witness_utxo
        } else if let Some(non_witness_utxo) = input
            .get_non_witness_utxo()
            .map_err(|_| Error::InvalidNonWitnessUtxo)?
        {
            let prevout_index = input
                .output_index
                .ok_or(Error::MissingPreviousOutputIndex)? as usize;
            if let Some(redeem_script) = input.redeem_script {
                let redeem_script = ScriptBuf::from_bytes(redeem_script.to_vec());
                if non_witness_utxo.output[prevout_index].script_pubkey != redeem_script.to_p2sh() {
                    return Err(Error::RedeemScriptMismatch);
                }
            }
            &non_witness_utxo.output[prevout_index]
        } else {
            return Err(Error::MissingInputUtxo);
        };

        // Record for deferred script derivation check
        script_checks.push(ScriptCheck {
            account_id,
            is_change: coords.is_change,
            address_index: coords.address_index,
            expected_script: tx_out.script_pubkey.clone(),
            is_input: true,
        });

        account_spent_amounts[account_id as usize] += tx_out.value.to_sat() as i64;
        inputs_total_amount += tx_out.value.to_sat();
    }

    /***** output checks (structural only — script derivation is deferred) *****/

    let output_coordinates: Vec<Option<(u32, PsbtAccountCoordinates)>> = psbt
        .outputs
        .iter()
        .map(|output| {
            output
                .get_account_coordinates()
                .map_err(|_| Error::FailedToGetAccounts)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    for (output_index, output) in psbt.outputs.iter().enumerate() {
        let amount = output.amount.ok_or(Error::OutputAmountMissing)?;
        if let Some((account_id, ref coords)) = output_coordinates[output_index] {
            if account_id as usize >= accounts.len() {
                return Err(Error::InvalidAccountId);
            }

            let PsbtAccountCoordinates::WalletPolicy(coords) = coords;

            let out_script_pubkey = output.script.ok_or(Error::OutputScriptMissing)?;
            let out_script_pubkey = ScriptBuf::from_bytes(out_script_pubkey.to_vec());

            // Record for deferred script derivation check
            script_checks.push(ScriptCheck {
                account_id,
                is_change: coords.is_change,
                address_index: coords.address_index,
                expected_script: out_script_pubkey,
                is_input: false,
            });

            account_spent_amounts[account_id as usize] -= amount as i64;
        } else {
            // Verify any id_auth proofs on external outputs immediately.
            let proofs = output
                .get_auth_proofs()
                .map_err(|_| Error::InvalidIdentitySignature)?;
            let mut first_auth_name: Option<String> = None;
            let out_script_bytes = output.script.ok_or(Error::OutputScriptMissing)?.to_vec();
            for proof in proofs {
                match proof {
                    common::psbt::OutputAuthProof::IdentitySignature { pubkey, sig } => {
                        // Verify the Schnorr signature against the output scriptPubKey.
                        let ecfp_pubkey =
                            EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(&pubkey)
                                .map_err(|_| Error::InvalidIdentitySignature)?;
                        let msg = build_identity_message(MSG_TYPE_OUTPUT, &out_script_bytes)
                            .map_err(|_| Error::InvalidIdentitySignature)?;
                        ecfp_pubkey
                            .schnorr_verify(&msg, &sig)
                            .map_err(|_| Error::InvalidIdentitySignature)?;
                        // Look up the registered name for this pubkey
                        if first_auth_name.is_none() {
                            first_auth_name = identity_key_names
                                .iter()
                                .find(|(pk, _)| *pk == pubkey)
                                .map(|(_, name)| name.clone());
                        }
                    }
                }
            }
            external_outputs_indexes.push(output_index);
            external_output_auth_names.push(first_auth_name);
        };

        outputs_total_amount += amount;
    }

    if outputs_total_amount > inputs_total_amount {
        return Err(Error::InputsLessThanOutputs);
    }

    let summary = TransactionSummary {
        accounts,
        account_names,
        input_coordinates,
        account_spent_amounts,
        external_outputs_indexes,
        external_output_auth_names,
        inputs_total_amount,
        outputs_total_amount,
        warn_unverified_inputs,
    };

    Ok((summary, account_proofs, script_checks))
}

/// Task to perform the expensive verification (proof-of-registration and script
/// derivation checks) in the background.
async fn verify_transaction(
    accounts: &[PsbtAccount],
    account_names: &[Option<String>],
    account_proofs: &[ProofOfRegistration<common::bip388::WalletPolicy>],
    script_checks: &[ScriptCheck],
) -> Result<(), Error> {
    // Verify proof-of-registration for each account
    for (account_id, account) in accounts.iter().enumerate() {
        let PsbtAccount::WalletPolicy(wallet_policy) = account;
        let account_name = account_names[account_id].as_deref().unwrap_or("");
        let id = wallet_policy.registration_id(account_name);
        if account_proofs[account_id] != ProofOfRegistration::new(&id) {
            return Err(Error::InvalidProofOfRegistration);
        }
        sdk::executor::yield_now().await;
    }

    // Verify that each input/output script matches the account derivation
    for check in script_checks {
        let PsbtAccount::WalletPolicy(wallet_policy) = &accounts[check.account_id as usize];
        let derived_script = wallet_policy
            .to_script(check.is_change, check.address_index)
            .map_err(|_| Error::InvalidWalletPolicy)?;
        if derived_script != check.expected_script {
            return Err(if check.is_input {
                Error::InputScriptMismatch
            } else {
                Error::OutputScriptMismatch
            });
        }
        sdk::executor::yield_now().await;
    }

    Ok(())
}

/// Build the `TagValue` pairs shown to the user during transaction review.
fn build_display_pairs(
    psbt: &fastpsbt::Psbt,
    summary: &TransactionSummary,
) -> Result<Vec<TagValue>, Error> {
    let fee = summary.fee();
    let n_accounts = summary.accounts.len();
    let n_external = summary.external_outputs_indexes.len();

    let mut pairs: Vec<TagValue> = Vec::with_capacity(n_accounts * 2 + n_external * 2 + 1);

    // Accounts we're spending from (non-negative spent amount)
    for (account_id, spent_amount) in summary.account_spent_amounts.iter().enumerate() {
        let account_description = match &summary.account_names[account_id] {
            Some(name) => format!("account: {}", name),
            None => "default account".to_string(),
        };
        if *spent_amount >= 0 {
            pairs.push(TagValue {
                tag: "Spend from".into(),
                value: account_description,
            });
            if *spent_amount > 0 {
                pairs.push(TagValue {
                    tag: "Amount".into(),
                    value: format_amount(*spent_amount as u64, COIN_TICKER),
                });
            } else {
                pairs.push(TagValue {
                    tag: "Amount".into(),
                    value: "0 (self-transfer)".to_string(),
                });
            }
        }
    }

    // Accounts we're receiving to (negative spent amount)
    for (account_id, spent_amount) in summary.account_spent_amounts.iter().enumerate() {
        let account_description = match &summary.account_names[account_id] {
            Some(name) => format!("account: {}", name),
            None => "default account".to_string(),
        };
        if *spent_amount < 0 {
            pairs.push(TagValue {
                tag: "Send to".into(),
                value: account_description,
            });
            pairs.push(TagValue {
                tag: "Amount".into(),
                value: format_amount(-*spent_amount as u64, COIN_TICKER),
            });
        }
    }

    // External outputs (show address, prefixed with identity key name if auth proof present)
    for (i, &output_index) in summary.external_outputs_indexes.iter().enumerate() {
        let output = &psbt.outputs[output_index];
        let out_script_pubkey = output.script.ok_or(Error::OutputScriptMissing)?;
        let out_script_pubkey = ScriptBuf::from_bytes(out_script_pubkey.to_vec());
        let amount = output.amount.ok_or(Error::OutputAmountMissing)?;
        let address = Address::from_script(&out_script_pubkey, bitcoin::Network::Testnet)
            .map_err(|_| Error::AddressFromScriptFailed)?;

        let address_value = if let Some(ref name) = summary.external_output_auth_names[i] {
            if sdk::ux::has_page_api() {
                // on large screens, go to a new line for the address
                format!("{}\n\n{}", name, address)
            } else {
                format!("{}:{}", name, address)
            }
        } else {
            format!("{}", address)
        };

        pairs.push(TagValue {
            tag: format!("Output {}", output_index),
            value: address_value,
        });
        pairs.push(TagValue {
            tag: "Amount".into(),
            value: format_amount(amount, COIN_TICKER),
        });
    }

    // Fee
    pairs.push(TagValue {
        tag: "Fee".to_string(),
        value: format!("{} {}", fee, COIN_TICKER),
    });

    Ok(pairs)
}

/// All signing outputs produced by a single `SignPsbt` call.
struct SignedInputs {
    signatures: Vec<PartialSignature>,
    musig_pubnonces: Vec<MuSig2Pubnonce>,
    musig_partial_sigs: Vec<MuSig2PartialSignature>,
}

/// Lazily materializes the prevouts list shared by all taproot sighashes in a
/// PSBT (all witness UTXOs, in input order).
fn ensure_prevouts<'a>(
    cache: &'a mut Option<Vec<TxOut>>,
    psbt: &fastpsbt::Psbt,
) -> &'a [TxOut] {
    cache
        .get_or_insert_with(|| {
            psbt.inputs
                .iter()
                .map(|input| {
                    input
                        .get_witness_utxo()
                        .ok()
                        .flatten()
                        .cloned()
                        .expect("Missing witness UTXO")
                })
                .collect()
        })
        .as_slice()
}

/// Computes the merkle root of a `tr(...)` wallet policy's script tree at the
/// given coordinates, or `None` for BIP-86 / BIP-386 style policies (no tree).
fn taptree_hash_for(
    wallet_policy: &common::bip388::WalletPolicy,
    coords: &common::message::WalletPolicyCoordinates,
) -> Result<Option<[u8; 32]>, Error> {
    match wallet_policy.descriptor_template() {
        DescriptorTemplate::Tr(_, tree) => tree
            .as_ref()
            .map(|t| {
                t.get_taptree_hash(
                    wallet_policy.key_information(),
                    coords.is_change,
                    coords.address_index,
                )
            })
            .transpose()
            .map_err(|_| Error::InvalidWalletPolicy),
        _ => Err(Error::UnexpectedTaprootPolicy),
    }
}

/// Computes the tapleaf hash for a script-path placeholder, or `None` for
/// keypath / non-taproot placeholders.
fn leaf_hash_for(
    tapleaf_desc: Option<&DescriptorTemplate>,
    wallet_policy: &common::bip388::WalletPolicy,
    coords: &common::message::WalletPolicyCoordinates,
) -> Result<Option<TapLeafHash>, Error> {
    tapleaf_desc
        .map(|desc| {
            desc.get_tapleaf_hash(
                wallet_policy.key_information(),
                coords.is_change,
                coords.address_index,
            )
        })
        .transpose()
        .map_err(|_| Error::InvalidWalletPolicy)
}

/// Sign all inputs of the PSBT, producing the per-input signing material.
///
/// For each (input, placeholder) where this device controls the key:
/// - Plain key + segwit v0 → ECDSA partial signature.
/// - Plain key + taproot   → Schnorr partial signature.
/// - Plain key + legacy    → ECDSA partial signature.
/// - musig() inside tr()   → round 1 pubnonce or round 2 partial signature,
///   depending on whether this device's pubnonce is already in the PSBT.
fn sign_all_inputs(
    psbt: &fastpsbt::Psbt,
    summary: &TransactionSummary,
    musig_state: &mut MusigSigningState,
) -> Result<SignedInputs, Error> {
    let unsigned_tx = psbt
        .unsigned_tx()
        .map_err(|_| Error::FailedUnsignedTransaction)?;
    let unsigned_tx_id: [u8; 32] = unsigned_tx.compute_txid().to_byte_array();
    let mut sighash_cache = SighashCache::new(unsigned_tx);

    let mut prevouts: Option<Vec<TxOut>> = None;
    let standard_fpr = sdk::curve::Secp256k1::get_master_fingerprint();
    let resident_fpr = get_resident_master_fingerprint()?;
    let mut out = SignedInputs {
        signatures: Vec::with_capacity(psbt.inputs.len()),
        musig_pubnonces: Vec::new(),
        musig_partial_sigs: Vec::new(),
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
            let change_step: ChildNumber = if !coords.is_change {
                kp.num1.into()
            } else {
                kp.num2.into()
            };
            let address_index: ChildNumber = coords.address_index.into();

            if kp.is_musig() {
                handle_musig_placeholder(
                    input,
                    input_index,
                    placeholder_index,
                    kp,
                    tapleaf_desc,
                    wallet_policy,
                    coords,
                    change_step,
                    address_index,
                    session_id,
                    musig_state,
                    psbt,
                    &mut sighash_cache,
                    &mut prevouts,
                    standard_fpr,
                    resident_fpr,
                    &mut out,
                )?;
                continue;
            }

            // ===== plain key path =====
            let key_index = kp
                .plain_key_index()
                .expect("kp must be plain because not musig");
            let key_info = &wallet_policy.key_information()[key_index as usize];
            let Some(key_source) = resolve_local_key_source(
                key_info,
                change_step,
                address_index,
                standard_fpr,
                resident_fpr,
            ) else {
                continue;
            };

            if input.witness_utxo.is_some() {
                match wallet_policy.get_segwit_version() {
                    Ok(SegwitVersion::SegwitV0) => {
                        out.signatures.push(sign_input_ecdsa(
                            psbt,
                            input_index,
                            &mut sighash_cache,
                            &key_source,
                        )?);
                    }
                    Ok(SegwitVersion::Taproot) => {
                        let taptree_hash = taptree_hash_for(wallet_policy, coords)?;
                        let leaf_hash = leaf_hash_for(tapleaf_desc, wallet_policy, coords)?;
                        let prev = ensure_prevouts(&mut prevouts, psbt);
                        out.signatures.push(sign_input_schnorr(
                            input_index,
                            &mut sighash_cache,
                            prev,
                            &key_source,
                            taptree_hash,
                            leaf_hash,
                        )?);
                    }
                    _ => return Err(Error::UnexpectedSegwitVersion),
                }
            } else {
                out.signatures.push(sign_input_ecdsa(
                    psbt,
                    input_index,
                    &mut sighash_cache,
                    &key_source,
                )?);
            }
        }
    }

    Ok(out)
}

/// Handles a single `musig(...)` placeholder for one PSBT input. Pushes either
/// a round-1 pubnonce or a round-2 partial signature into `out`, *for each*
/// participant this device controls.
fn handle_musig_placeholder(
    input: &fastpsbt::Input<'_>,
    input_index: usize,
    placeholder_index: usize,
    kp: &KeyExpression,
    tapleaf_desc: Option<&DescriptorTemplate>,
    wallet_policy: &common::bip388::WalletPolicy,
    coords: &common::message::WalletPolicyCoordinates,
    change_step: ChildNumber,
    address_index: ChildNumber,
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

    // Identify which participants this device controls.
    let indices = kp
        .musig_key_indices()
        .expect("kp must be musig because is_musig() returned true");
    let mut ours: Vec<KeySource> = Vec::new();
    for &participant_idx in indices {
        let key_info = &wallet_policy.key_information()[participant_idx as usize];
        if let Some(ks) = resolve_local_key_source(
            key_info,
            change_step,
            address_index,
            standard_fpr,
            resident_fpr,
        ) {
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
            let prev = ensure_prevouts(prevouts, psbt);
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

pub async fn handle_sign_psbt(app: &mut sdk::App, psbt: &[u8]) -> Result<Response, Error> {
    app.show_spinner("Processing...");

    let psbt = fastpsbt::Psbt::parse(psbt).map_err(|_| Error::FailedToDeserializePsbt)?;

    // Lightweight analysis: structural validation + extract data for display and verification
    let (summary, account_proofs, script_checks) = analyze_transaction(&psbt)?;

    // Spawn expensive verification (proof-of-registration + script derivation) as a background
    // task so it runs concurrently with the UX flows below.
    let verification_handle = app.spawn_task(async {
        verify_transaction(
            &summary.accounts,
            &summary.account_names,
            &account_proofs,
            &script_checks,
        )
        .await
    });

    // Show warnings (runs while verification task progresses in the background)
    if summary.warn_unverified_inputs {
        if !display_warning_unverified_inputs(app).await {
            return Err(Error::UserRejected);
            // verification_handle is dropped here → task is cancelled
        }
    }

    let fee = summary.fee();
    if summary.inputs_total_amount >= crate::constants::THRESHOLD_WARN_HIGH_FEES_AMOUNT {
        let fee_percent = fee.saturating_mul(100) / summary.inputs_total_amount;
        if fee_percent >= crate::constants::THRESHOLD_WARN_HIGH_FEES_PERCENT {
            if !display_warning_high_fee(app, fee_percent).await {
                return Err(Error::UserRejected);
            }
        }
    }

    // Display transaction for user approval
    let pairs = build_display_pairs(&psbt, &summary)?;
    if !display_transaction(app, &pairs).await {
        #[cfg(not(any(test, feature = "autoapprove")))]
        app.show_info(Icon::Failure, "Transaction rejected");

        return Err(Error::UserRejected);
    }

    // Wait for verification to complete (likely already done by now)
    app.await_task("Verifying...", verification_handle)?;

    // All checks passed — sign
    app.show_spinner("Signing transaction...");
    let mut musig_state = MusigSigningState::default();
    let signed = sign_all_inputs(&psbt, &summary, &mut musig_state)?;

    // Persist the round-1 session, if any, only after the signing pass has
    // completed successfully — partial failures must leave no stale session.
    musig_signing::commit(&musig_state)?;

    #[cfg(not(any(test, feature = "autoapprove")))]
    app.show_info(Icon::Success, "Transaction signed");

    Ok(Response::PsbtSigned {
        signatures: signed.signatures,
        musig_pubnonces: signed.musig_pubnonces,
        musig_partial_sigs: signed.musig_partial_sigs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use bitcoin::{psbt::Psbt, secp256k1::schnorr::Signature, XOnlyPublicKey};
    use common::{bip388::WalletPolicy, psbt::prepare_psbt};
    use hex_literal::hex;

    // rust-bitcoin doesn't support Psbtv2, so we use this helper for conversion
    fn serialize_as_psbtv2(psbt: &Psbt) -> Vec<u8> {
        common::psbt::psbt_v0_to_v2(&psbt.serialize()).expect("Failed to convert PSBTv0 to PSBTv2")
    }

    #[test]
    fn test_handle_sign_psbt_pkh() {
        let psbt_b64 = "cHNidP8BAFUCAAAAAVEiws3mgj5VdUF1uSycV6Co4ayDw44Xh/06H/M0jpUTAQAAAAD9////AXhBDwAAAAAAGXapFBPX1YFmlGw+wCKTQGbYwNER0btBiKwaBB0AAAEA+QIAAAAAAQHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrAJHMEQCIDfstCSDYar9T4wR5wXw+npfvc1ZUXL81WQ/OxG+/11AAiACDG0yb2w31jzsra9OszX67ffETgX17x0raBQLAjvRPQEhA9rIL8Cs/Pw2NI1KSKRvAc6nfyuezj+MO0yZ0LCy+ZXShPIcACIGAu6GCCB+IQKEJvaedkR9fj1eB3BJ9eaDwxNsIxR2KkcYGPWswv0sAACAAQAAgAAAAIAAAAAAAAAAAAAA";
        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "pkh(@0/**)", 
            vec![
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT".try_into().unwrap()
            ]
        ).unwrap();

        let account_name = "My legacy account #0";
        let por = ProofOfRegistration::new(&wallet_policy.registration_id(account_name))
            .dangerous_as_bytes();

        prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        assert_eq!(response, Response::PsbtSigned {
            signatures: vec![
                PartialSignature {
                    input_index: 0,
                    signature: hex!("3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401").to_vec(),
                    pubkey: hex!("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718").to_vec(),
                    leaf_hash: None
                }
            ],
            musig_pubnonces: Vec::new(),
            musig_partial_sigs: Vec::new(),
        });
    }

    #[test]
    fn test_handle_sign_psbt_wpkh() {
        let psbt_b64 = "cHNidP8BAHQCAAAAAXoqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////AqC7DQAAAAAAGXapFDRKD0jKFQ7CuQOBdmC5tosTpnAmiKx0OCMAAAAAABYAFOs4+puBKPgfJule2wxf+uqDaQ/kAAAAAAABAH0CAAAAAa+/rgZZD3Qf8a9ZtqxGESYzakxKgttVPfb++rc3rDPzAQAAAAD9////AnARAQAAAAAAIgAg/e5EHFblsG0N+CwSTHBwFKXKGWWL4LmFa8oW8e0yWfel9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLAAAAAAEBH6X0MAAAAAAAFgAUOvhCmtWVSqXuijPJg/2KHoZ5kksiBgPuLD2Y6x+TwKGqjlpACbcOt7ROrRXxZm8TawEq1Y0waBj1rML9VAAAgAEAAIAAAACAAQAAAAgAAAAAACICAinsR3JxMe0liKIMRu2pq7fapvSf1Quv5wucWqaWHE7MGPWswv1UAACAAQAAgAAAAIABAAAACgAAAAA=";
        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "wpkh(@0/**)", 
            vec![
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P".try_into().unwrap()
            ]
        ).unwrap();
        let account_name = "My segwit account #0";
        let por = ProofOfRegistration::new(&wallet_policy.registration_id(account_name))
            .dangerous_as_bytes();
        prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        assert_eq!(response, Response::PsbtSigned {
            signatures: vec![
                PartialSignature {
                    input_index: 0,
                    signature: hex!("3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01").to_vec(),
                    pubkey: hex!("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068").to_vec(),
                    leaf_hash: None
                }
            ],
            musig_pubnonces: Vec::new(),
            musig_partial_sigs: Vec::new(),
        });
    }

    #[test]
    fn test_handle_sign_psbt_tr() {
        let psbt_b64 = "cHNidP8BAH0CAAAAAeFoYcDSl0n1LNLt3hDLzE9ZEhBxD2QOXY4UQM6F2W3GAQAAAAD9////Ao00lwAAAAAAIlEgC450hrwwagrvt6fACvBAVULbGs1z7syoJ3HM9f5etg+ghgEAAAAAABYAFBOZuKCYR6A5sDUvWNISwYC6sX93AAAAAAABASvfu5gAAAAAACJRIImQSmNI1/+aRNSduLaoB8Yi6Gg2TFR9pCbzC1piExhqIRbpxpsJXtBLVir8jUFpGTa6Vz629om8I2YAvk+jkm9kEhkA9azC/VYAAIABAACAAAAAgAEAAAADAAAAARcg6cabCV7QS1Yq/I1BaRk2ulc+tvaJvCNmAL5Po5JvZBIAAQUgApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwohBwKQgezlYWqhy5kxn8SHTv7kfwjOul9gBGNsjENAml8KGQD1rML9VgAAgAEAAIAAAACAAQAAAAIAAAAAAA==";
        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "tr(@0/**)", 
            vec![
                "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U".try_into().unwrap()
            ]
        ).unwrap();

        let account_name = "My taproot account #0";
        let por = ProofOfRegistration::new(&wallet_policy.registration_id(account_name))
            .dangerous_as_bytes();
        prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        let Response::PsbtSigned {
            signatures: partial_signatures,
            ..
        } = response
        else {
            panic!("Expected PsbtSigned response");
        };

        let expected_pubkey0 = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .unwrap()
            .script_pubkey
            .as_bytes()[2..]
            .to_vec();

        assert_eq!(partial_signatures.len(), 1);
        assert_eq!(partial_signatures[0].input_index, 0);
        assert_eq!(partial_signatures[0].pubkey, expected_pubkey0);

        let sighash = hex!("75C96FB06A12DB4CD011D8C95A5995DB758A4F2837A22F30F0F579619A4466F3");
        let pubkey = XOnlyPublicKey::from_slice(&expected_pubkey0).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        secp.verify_schnorr(
            &Signature::from_slice(&partial_signatures[0].signature).unwrap(),
            &bitcoin::secp256k1::Message::from_digest(sighash),
            &pubkey,
        )
        .expect("Signature verification failed");
    }

    #[test]
    fn test_handle_sign_psbt_with_resident_pubkey() {
        let psbt_b64 = "cHNidP8BAKYCAAAAAs6MJQ9uBSUCmJpgUB9wGYZGqTMGYmOnXuyrkUGhcHyCAQAAAAD9////heZDgiEqZove1y7DCgxH7C8ERyDQkoVefghpmYDeKlwAAAAAAP3///8C5ygAAAAAAAAiUSAGDJP2Niux4bvyYwYNNDt/ff0v3KIN49hbSJrnZb0MQoSQAQAAAAAAFgAUKcCaIuEMi5OceEB5MbFv3Bxi7/AAAAAAAAEBKxFJAQAAAAAAIlEg1Klrfzt/O4NPudEUKKEhj69xxtM3OGnhY4Z3E9fqjHshFsZ2FyAcWD9j8ONZl/Sek1uj3W1JVPmlhZBzRiPIKiG1GQCthdlVMAAAgAEAAIAAAACAAAAAAAAAAAABFyDGdhcgHFg/Y/DjWZf0npNbo91tSVT5pYWQc0YjyCohtQABASsicQAAAAAAACJRIMRxNS3nHwMfn/AcfJ4/Bk3YkBzFZ0mz2NL1Atr1s4MIIRbJq1223YydIq4HkOWtLr6DBB9LrP8lN/ulMpG93sru0xkArYXZVTAAAIABAACAAAAAgAAAAAACAAAAARcgyatdtt2MnSKuB5DlrS6+gwQfS6z/JTf7pTKRvd7K7tMAAQUgOEeAjyIcpdjjuYWnkpRzrpDt2GVALyLidlPWZSDzRRchBzhHgI8iHKXY47mFp5KUc66Q7dhlQC8i4nZT1mUg80UXGQCthdlVMAAAgAEAAIAAAACAAAAAAAMAAAAAAA==";

        let mut psbt = Psbt::deserialize(&STANDARD.decode(&psbt_b64).unwrap()).unwrap();

        let wallet_policy = WalletPolicy::new(
            "tr(@0/**)",
            vec![
                "[ad85d955/44'/1'/0']tpubDD7URPdwnhN6XNWRkMLhaGvhp1xaZNTAqgn8qULdENfMrUbCUcV4Kd4FQzVSHkKx9nmU7sNjBMPa96b9g3KTSJTAvTsTcT5mYDz97fUppvd".try_into().unwrap()
            ]
        ).unwrap();

        let account_name = "Resident taproot account";
        let por = ProofOfRegistration::new(&wallet_policy.registration_id(account_name))
            .dangerous_as_bytes();
        prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        let Response::PsbtSigned {
            signatures: partial_signatures,
            ..
        } = response
        else {
            panic!("Expected PsbtSigned response");
        };

        assert_eq!(partial_signatures.len(), 2);
    }

    #[test]
    fn test_handle_sign_psbt_identity_key_failures() {
        // Case 1: wrong PoR, valid output signature ==> rejected with InvalidProofOfRegistration.
        let psbt_b64 = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAJqgrDKRos0I/UumLXE7d5tvVkt7zHndvnarnKUN1Ge9HJhmQuQMoaf/vKtO65UgQ455M/uN77Q1CWn7Wb9AfsQABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";
        let psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();
        let result = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ));
        assert_eq!(result, Err(Error::InvalidProofOfRegistration));

        // Case 2: valid PoR, but the Schnorr signature over the output script is invalid ==> rejected with InvalidIdentitySignature.
        let psbt_b64 = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvuFIxVHknuLpQ/zP3rTZie8gIyZjCHfUXcOEGSDcFFboAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAEREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";
        let psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();
        let result = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ));
        assert_eq!(result, Err(Error::InvalidIdentitySignature));
    }

    #[test]
    fn test_handle_sign_psbt_identity_key_success() {
        let psbt_b64 = "cHNidP8BALICAAAAApcjbJiptnVfVZ8u5lEDOmwWO4ApbFXQk50KhPXeVqToAAAAAAAAAAAAEJQv9ZdQMi/KhGbkBskfsaZyegiwfV/RH6oVl8cepNsAAAAAAAAAAAACmDoAAAAAAAAiUSDcH+P34kHoc+fctxVKmO/RlrwtgevDkXfwxtAqCZC8tZc6AAAAAAAAIlEggbusbuk6g0dnZIj5nEgvlGnGQVr4D4co77xvtNkr8LsAAAAATwEENYfPBKvvuwaAAAACOY8+nsIJJTr+nBUK0w+kGCzGKmiDRLGAxsafRuEXptYDZ6wvQTRA5DwRKy2x9lLQtiisFFZKuk1+qQFl+B1SdgoU9azC/TAAAIABAACAAAAAgAIAAIAO/AdBQ0NPVU5UAAAAAABwAAl0cihAMC8qKikBAfWswv0EMAAAgAEAAIAAAACAAgAAgAQ1h88Eq++7BoAAAAI5jz6ewgklOv6cFQrTD6QYLMYqaINEsYDGxp9G4Rem1gNnrC9BNEDkPBErLbH2UtC2KKwUVkq6TX6pAWX4HVJ2Cg78B0FDQ09VTlQBAAAAAAxUZXN0IGFjY291bnQO/AdBQ0NPVU5UAgAAAAAgTWldX2utrybjCRhpakIzoHUrVchEgs+aWCRAhe2qRVsq/AZJREFVVEgAAtCUts85qNnC53vT1fTs3ax/bTfvwlYvRYIqTtecWjV0MRBTYXRvc2hpIE5ha2Ftb3RvuFIxVHknuLpQ/zP3rTZie8gIyZjCHfUXcOEGSDcFFboAAQErECcAAAAAAAAiUSA1AkRxB/U8hQVW+E3Rw5yQDdY00QZ3TGdCwzwyEpy1RCEWCFne76qAVgdNCn1scuOxZQlP4K4FV9Zy4yrf+wkueaYdAPWswv0wAACAAQAAgAAAAIACAACAAAAAAAESAAABFyAIWd7vqoBWB00KfWxy47FlCU/grgVX1nLjKt/7CS55pgr8B0FDQ09VTlQABwAAAAESAAAAAQErIE4AAAAAAAAiUSA5DqSH1RNHbf/kpCTKALEGzw4iUkyo7SIz62lJA2gY5yEWUD3ScUW1Ylc9FIKs8E46QWstkJTux5wf4mQ1eb7Y3v8dAPWswv0wAACAAQAAgAAAAIACAACAAQAAAGMMAAABFyBQPdJxRbViVz0UgqzwTjpBay2QlO7HnB/iZDV5vtje/wr8B0FDQ09VTlQABwAAAWMMAAAAK/wGSURBVVRIAAAC0JS2zzmo2cLne9PV9OzdrH9tN+/CVi9FgipO15xaNXRAR5l6X7yUsuUpkyekIKx81HNmEE3mnqVB7/5A1UpjtZuvx0c2N93OOf6HvpNKpvounBUpNoOYTRJvVhKqqrl/KgABBSADwo/+2nrTysZIeuSJ6nFcsooKPHueSPFCWAvjS977NSEHA8KP/tp608rGSHrkiepxXLKKCjx7nkjxQlgL40ve+zUdAPWswv0wAACAAQAAgAAAAIACAACAAQAAADIgAAAK/AdBQ0NPVU5UAAcAAAEyIAAAAA==";
        let psbt = Psbt::deserialize(&STANDARD.decode(psbt_b64).unwrap()).unwrap();
        let result = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ));

        assert!(result.is_ok(), "Expected Ok result, got {:?}", result);
    }

    /// A PSBT for `tr(musig(@0,@1)/**)` whose participant xpubs the device
    /// doesn't control. The musig branch should fire (no longer silently
    /// skipped) and produce no output — empty `signatures`, `musig_pubnonces`
    /// and `musig_partial_sigs`.
    ///
    /// The cosigner xpubs match the C reference app's
    /// `tests/test_musig2.py::test_musig2_hotsigner_keypath`; the witness UTXO
    /// scriptPubKey at `(is_change=false, address_index=3)` is taken verbatim
    /// from the same test.
    #[test]
    fn test_handle_sign_psbt_musig_no_local_participant() {
        use bitcoin::{
            absolute, secp256k1::XOnlyPublicKey, transaction, Amount, OutPoint, ScriptBuf,
            Sequence, Transaction, TxIn, TxOut, Txid, Witness,
        };
        use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};

        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                // P2WPKH to a dummy address — must be an addressable script.
                script_pubkey: ScriptBuf::from_bytes(
                    hex!("0014" "00112233445566778899aabbccddeeff00112233").to_vec(),
                ),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        // The previous output: a P2TR locked to the musig aggregate at
        // (is_change=false, address_index=3). The scriptPubKey is the value
        // independently re-derived in `common::script::tests::tr_musig_keypath_to_script`.
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: ScriptBuf::from_bytes(
                hex!("5120c1fdfebed063aa148340c45132e6718d8de81466ae2b90929e3d9328364cd6ed")
                    .to_vec(),
            ),
        });
        // BIP-373 tap_bip32_derivation: keyed by the BIP-32-tweaked aggregate
        // x-only key; fingerprint is the synthetic BIP-388 aggregate xpub's
        // BIP-32 fingerprint.
        let agg_xonly = XOnlyPublicKey::from_slice(&hex!(
            "9066461650209f8bbc59b05af5d1615c50f5f79c188d7be742fd932252f68f0c"
        ))
        .unwrap();
        let agg_fpr = Fingerprint::from(hex!("5b8fbc93"));
        let path = DerivationPath::from(vec![
            ChildNumber::Normal { index: 0 },
            ChildNumber::Normal { index: 3 },
        ]);
        psbt.inputs[0]
            .tap_key_origins
            .insert(agg_xonly, (vec![], (agg_fpr, path)));

        let wallet_policy = WalletPolicy::new(
            "tr(musig(@0,@1)/**)",
            vec![
                "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
                    .try_into()
                    .unwrap(),
                "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"
                    .try_into()
                    .unwrap(),
            ],
        )
        .unwrap();

        let account_name = "Musig for my ears";
        let por = ProofOfRegistration::new(&wallet_policy.registration_id(account_name))
            .dangerous_as_bytes();
        prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        match response {
            Response::PsbtSigned {
                signatures,
                musig_pubnonces,
                musig_partial_sigs,
            } => {
                assert!(signatures.is_empty(), "no plain placeholders ⇒ no signatures");
                assert!(
                    musig_pubnonces.is_empty(),
                    "no local participants ⇒ no pubnonces"
                );
                assert!(
                    musig_partial_sigs.is_empty(),
                    "no local participants ⇒ no partial sigs"
                );
            }
            _ => panic!("Expected PsbtSigned response"),
        }
    }
}
