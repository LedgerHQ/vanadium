use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use common::{
    account::{Account, ProofOfRegistration},
    bip388::{DescriptorTemplate, SegwitVersion},
    errors::Error,
    message::{PartialSignature, Response},
    psbt::{
        PsbtAccount, PsbtAccountCoordinates, PsbtAccountGlobalRead, PsbtAccountInputRead,
        PsbtAccountOutputRead,
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
    curve::{Curve, EcfpPrivateKey, HDPrivNode, ToPublicKey},
    ux::TagValue,
};

use crate::constants::COIN_TICKER;
use crate::resident_key;

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

/// Identifies how the signing private key should be obtained.
enum KeySource<'a> {
    /// Derive from the master seed via the BIP32 ECALL using the full derivation path.
    MasterSeed(Vec<ChildNumber>),
    /// Derive from the resident private key using the given synthetic chaincode
    /// and a two-step non-hardened derivation (`change_step / address_index`).
    ResidentKey {
        chaincode: &'a [u8; 32],
        change_step: ChildNumber,
        address_index: ChildNumber,
    },
}

/// Resolves a `KeySource` into an `HDPrivNode` containing the final private key.
fn resolve_private_key(
    key_source: &KeySource,
) -> Result<HDPrivNode<sdk::curve::Secp256k1, 32>, Error> {
    match key_source {
        KeySource::MasterSeed(path) => {
            let path: Vec<u32> = path.iter().map(|&x| x.into()).collect();
            sdk::curve::Secp256k1::derive_hd_node(&path)
                .map_err(|_| Error::KeyDerivationFailed)
        }
        KeySource::ResidentKey {
            chaincode,
            change_step,
            address_index,
        } => {
            let root = resident_key::get_or_init_resident_private_key()?.into_hd_node(chaincode);
            let intermediate = root
                .ckd_priv(u32::from(*change_step))
                .map_err(|_| Error::KeyDerivationFailed)?;
            intermediate
                .ckd_priv(u32::from(*address_index))
                .map_err(|_| Error::KeyDerivationFailed)
        }
    }
}

fn sign_input_ecdsa(
    psbt: &fastpsbt::Psbt,
    input_index: usize,
    sighash_cache: &mut SighashCache<Transaction>,
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
    sighash_cache: &mut SighashCache<Transaction>,
    prevouts: &[TxOut],
    key_source: &KeySource,
    taptree_hash: Option<[u8; 32]>,
    leaf_hash: Option<TapLeafHash>,
) -> Result<PartialSignature, Error> {
    let sighash_type = TapSighashType::Default; // TODO: only DEFAULT is supported for now

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
        Vec<ProofOfRegistration>,
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

    let mut account_spent_amounts: Vec<i64> = vec![0; accounts.len()];
    let mut external_outputs_indexes = Vec::new();
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
            external_outputs_indexes.push(output_index);
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
    account_proofs: &[ProofOfRegistration],
    script_checks: &[ScriptCheck],
) -> Result<(), Error> {
    // Verify proof-of-registration for each account
    for (account_id, account) in accounts.iter().enumerate() {
        let PsbtAccount::WalletPolicy(wallet_policy) = account;
        let account_name = account_names[account_id].as_deref().unwrap_or("");
        let id = wallet_policy.get_id(account_name);
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

    // External outputs (show address)
    for &output_index in &summary.external_outputs_indexes {
        let output = &psbt.outputs[output_index];
        let out_script_pubkey = output.script.ok_or(Error::OutputScriptMissing)?;
        let out_script_pubkey = ScriptBuf::from_bytes(out_script_pubkey.to_vec());
        let amount = output.amount.ok_or(Error::OutputAmountMissing)?;
        let address = Address::from_script(&out_script_pubkey, bitcoin::Network::Testnet)
            .map_err(|_| Error::AddressFromScriptFailed)?;

        pairs.push(TagValue {
            tag: format!("Output {}", output_index),
            value: format!("{}", address),
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

/// Sign all inputs of the PSBT, producing one `PartialSignature` per signing key per input.
fn sign_all_inputs(
    psbt: &fastpsbt::Psbt,
    summary: &TransactionSummary,
) -> Result<Vec<PartialSignature>, Error> {
    let unsigned_tx = psbt
        .unsigned_tx()
        .map_err(|_| Error::FailedUnsignedTransaction)?;
    let mut sighash_cache = SighashCache::new(unsigned_tx.clone());

    let mut prevouts: Option<Vec<TxOut>> = None;
    let master_fingerprint = sdk::curve::Secp256k1::get_master_fingerprint();
    let mut partial_signatures = Vec::with_capacity(psbt.inputs.len());

    // Cache the resident compressed pubkey to avoid repeated storage reads.
    // Lazily initialised on first use.
    let mut cached_resident_pubkey: Option<Option<[u8; 33]>> = None;

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let (account_id, ref coords) = summary.input_coordinates[input_index];
        let PsbtAccountCoordinates::WalletPolicy(coords) = coords;
        let PsbtAccount::WalletPolicy(wallet_policy) = &summary.accounts[account_id as usize];

        for (kp, tapleaf_desc) in wallet_policy.descriptor_template.placeholders() {
            let key_info = wallet_policy.key_information[kp.key_index as usize].clone();

            // Determine the key source: either the master seed (fingerprint match)
            // or the resident key (compressed pubkey + synthetic chaincode match).
            let change_step: ChildNumber = if !coords.is_change {
                kp.num1.into()
            } else {
                kp.num2.into()
            };
            let address_index: ChildNumber = coords.address_index.into();

            let key_source = if key_info
                .origin_info
                .as_ref()
                .is_some_and(|x| x.fingerprint == master_fingerprint)
            {
                // Master seed key: build the full BIP32 derivation path
                let key_origin = key_info.origin_info.as_ref().unwrap();

                // TODO: in principle, there could be collisions on the fingerprint;
                // we shouldn't sign in that case

                let mut path = Vec::with_capacity(key_origin.derivation_path.len() + 2);
                path.extend_from_slice(&key_origin.derivation_path);
                path.push(change_step);
                path.push(address_index);
                KeySource::MasterSeed(path)
            } else {
                // Check if this is a resident key
                let resident_pubkey = cached_resident_pubkey.get_or_insert_with(|| {
                    resident_key::get_resident_compressed_pubkey().ok()
                });
                let Some(resident_pubkey) = resident_pubkey else {
                    continue;
                };

                let xpub_pubkey = key_info.pubkey.public_key.serialize();
                if *resident_pubkey != xpub_pubkey {
                    continue;
                }

                let chain_code: &[u8; 32] = key_info.pubkey.chain_code.as_ref();
                // First 30 bytes of chaincode must be zero for it to be a resident key
                if chain_code[..30].iter().any(|&b| b != 0) {
                    continue;
                }

                KeySource::ResidentKey {
                    chaincode: chain_code,
                    change_step,
                    address_index,
                }
            };

            if input.witness_utxo.is_some() {
                match wallet_policy.get_segwit_version() {
                    Ok(SegwitVersion::SegwitV0) => {
                        let partial_signature =
                            sign_input_ecdsa(psbt, input_index, &mut sighash_cache, &key_source)?;
                        partial_signatures.push(partial_signature);
                    }
                    Ok(SegwitVersion::Taproot) => {
                        let taptree_hash = match &wallet_policy.descriptor_template {
                            DescriptorTemplate::Tr(_, tree) => tree
                                .as_ref()
                                .map(|t| {
                                    t.get_taptree_hash(
                                        &wallet_policy.key_information,
                                        coords.is_change,
                                        coords.address_index,
                                    )
                                })
                                .transpose()
                                .map_err(|_| Error::InvalidWalletPolicy),
                            _ => return Err(Error::UnexpectedTaprootPolicy),
                        }?;

                        let leaf_hash = tapleaf_desc
                            .map(|desc| {
                                desc.get_tapleaf_hash(
                                    &wallet_policy.key_information,
                                    coords.is_change,
                                    coords.address_index,
                                )
                            })
                            .transpose()
                            .map_err(|_| Error::InvalidWalletPolicy)?;

                        let prevouts = prevouts.get_or_insert_with(|| {
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
                        });
                        let partial_signature = sign_input_schnorr(
                            input_index,
                            &mut sighash_cache,
                            prevouts,
                            &key_source,
                            taptree_hash,
                            leaf_hash,
                        )?;
                        partial_signatures.push(partial_signature);
                    }
                    _ => return Err(Error::UnexpectedSegwitVersion),
                }
            } else {
                partial_signatures.push(sign_input_ecdsa(
                    psbt,
                    input_index,
                    &mut sighash_cache,
                    &key_source,
                )?);
            }
        }
    }

    Ok(partial_signatures)
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
    let partial_signatures = sign_all_inputs(&psbt, &summary)?;

    #[cfg(not(any(test, feature = "autoapprove")))]
    app.show_info(Icon::Success, "Transaction signed");

    Ok(Response::PsbtSigned(partial_signatures))
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
        let por =
            ProofOfRegistration::new(&wallet_policy.get_id(account_name)).dangerous_as_bytes();

        prepare_psbt(&mut psbt, &[(&wallet_policy, account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        assert_eq!(response, Response::PsbtSigned(vec![
            PartialSignature {
                input_index: 0,
                signature: hex!("3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401").to_vec(),
                pubkey: hex!("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718").to_vec(),
                leaf_hash: None
            }
        ]));
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
        let por =
            ProofOfRegistration::new(&wallet_policy.get_id(account_name)).dangerous_as_bytes();
        prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        assert_eq!(response, Response::PsbtSigned(vec![
            PartialSignature {
                input_index: 0,
                signature: hex!("3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01").to_vec(),
                pubkey: hex!("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068").to_vec(),
                leaf_hash: None
            }
        ]));
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
        let por =
            ProofOfRegistration::new(&wallet_policy.get_id(account_name)).dangerous_as_bytes();
        prepare_psbt(&mut psbt, &[(&wallet_policy, &account_name, &por)]).unwrap();

        let response = sdk::executor::block_on(handle_sign_psbt(
            &mut sdk::App::singleton(),
            &serialize_as_psbtv2(&psbt),
        ))
        .unwrap();

        let Response::PsbtSigned(partial_signatures) = response else {
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
}
