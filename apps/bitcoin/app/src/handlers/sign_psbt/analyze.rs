//! PSBT structural analysis and deferred cryptographic verification.
//!
//! [`analyze_transaction`] performs cheap structural validation of the PSBT and
//! extracts the data needed both for UI display ([`TransactionSummary`]) and for the
//! more expensive checks in [`verify_transaction`] (proof-of-registration and script
//! derivation), which the caller runs concurrently with the approval UI via
//! `app.spawn_task`.
//!
//! One check is *not* deferred despite looking similarly expensive: identity-key
//! output-auth-proof verification (the Schnorr signature over an external output's
//! scriptPubKey) happens eagerly inside [`analyze_transaction`]. That's because the
//! resolved identity name feeds directly into the transaction-review screen — if it
//! were deferred like the account proof-of-registration / script-derivation checks,
//! the user could be shown an unverified name before the check that validates it has
//! even run. This is intentional, not an inconsistency.

use alloc::{string::String, vec, vec::Vec};

use common::{
    bip388::SegwitVersion,
    errors::Error,
    fastpsbt,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_OUTPUT},
    por::{ProofOfRegistration, Registerable},
    psbt::{
        PsbtAccount, PsbtAccountCoordinates, PsbtAccountGlobalRead, PsbtAccountInputRead,
        PsbtAccountOutputRead, PsbtIdAuthGlobalRead, PsbtOutputAuthRead,
    },
    script::ToScript,
};

use bitcoin::{hashes::Hash, ScriptBuf, TxOut};
use sdk::curve::EcfpPublicKey;

/// A script derivation check to be verified in the background task.
pub(super) struct ScriptCheck {
    account_id: u32,
    is_change: bool,
    address_index: u32,
    expected_script: ScriptBuf,
    is_input: bool,
}

/// The result of analyzing a PSBT: lightweight data needed for UI display and signing.
pub(super) struct TransactionSummary {
    pub(super) accounts: Vec<PsbtAccount>,
    pub(super) account_names: Vec<Option<String>>,
    pub(super) input_coordinates: Vec<(u32, PsbtAccountCoordinates)>,
    pub(super) account_spent_amounts: Vec<i64>,
    pub(super) external_outputs_indexes: Vec<usize>,
    /// Parallel to `external_outputs_indexes`: `Some(name)` if the output carries a valid
    /// id_auth proof from a registered identity key, `None` otherwise.
    pub(super) external_output_auth_names: Vec<Option<String>>,
    pub(super) inputs_total_amount: u64,
    pub(super) outputs_total_amount: u64,
    pub(super) warn_unverified_inputs: bool,
}

impl TransactionSummary {
    pub(super) fn fee(&self) -> u64 {
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
pub(super) fn analyze_transaction(
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
pub(super) async fn verify_transaction(
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
