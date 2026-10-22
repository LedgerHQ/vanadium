//! PSBT structural analysis and deferred cryptographic verification.
//!
//! [`analyze_transaction`] performs cheap structural validation of the PSBT and
//! extracts the data needed both for UI display ([`TransactionSummary`]) and for the
//! expensive checks in [`DeferredChecks::verify`] (proof-of-registration and script
//! derivation), which the caller runs concurrently with the approval UI via
//! `app.spawn_task`.
//!
//! It also owns [`input_prevout`], the single definition of what an input's prevout is,
//! which the signing paths reach through [`ensure_prevouts`].

use alloc::{string::String, vec, vec::Vec};

use common::{
    account::{Account, Destination},
    bip388::{SegwitVersion, WalletPolicy},
    errors::Error,
    fastpsbt,
    identity::{build_identity_message, IdentityKey, MSG_TYPE_OUTPUT},
    message::WalletPolicyCoordinates,
    por::{ProofOfRegistration, Registerable},
    psbt::{
        PsbtAccount, PsbtAccountCoordinates, PsbtAccountGlobalRead, PsbtAccountInputRead,
        PsbtAccountOutputRead, PsbtIdAuthGlobalRead, PsbtOutputAuthRead,
    },
    silent_payments::{SilentPaymentAccount, SilentPaymentCode, SilentPaymentCoordinates},
};

use bitcoin::{hashes::Hash, ScriptBuf, TxOut};
use sdk::curve::EcfpPublicKey;

/// A check, verified in the background task, that an input or an output belongs to the account
/// it claims: the account's destination at its coordinates must be the input's or output's.
struct OwnershipCheck {
    account_id: u32,
    coords: PsbtAccountCoordinates,
    expected: Destination,
    is_input: bool,
}

/// The checks [`analyze_transaction`] hands to the background task: proof of
/// registration for every account, and ownership for every input and every
/// output that belongs to one of them.
pub(super) struct DeferredChecks {
    account_proofs: Vec<[u8; 32]>,
    ownership_checks: Vec<OwnershipCheck>,
}

/// An output that pays to none of the PSBT's accounts.
pub(super) struct ExternalOutput {
    pub(super) output_index: usize,
    pub(super) destination: Destination,
    /// `Some(name)` if the output carries a valid id_auth proof from a registered identity key.
    pub(super) auth_name: Option<String>,
}

/// The result of analyzing a PSBT: lightweight data needed for UI display and signing.
pub(super) struct TransactionSummary {
    pub(super) accounts: Vec<PsbtAccount>,
    pub(super) account_names: Vec<Option<String>>,
    pub(super) input_coordinates: Vec<(u32, PsbtAccountCoordinates)>,
    pub(super) account_spent_amounts: Vec<i64>,
    pub(super) external_outputs: Vec<ExternalOutput>,
    pub(super) inputs_total_amount: u64,
    pub(super) outputs_total_amount: u64,
    pub(super) warn_unverified_inputs: bool,
}

impl TransactionSummary {
    pub(super) fn fee(&self) -> u64 {
        self.inputs_total_amount - self.outputs_total_amount
    }

    /// The account that input `input_index` spends from, with the input's coordinates in it.
    pub(super) fn input_account(&self, input_index: usize) -> InputAccount<'_> {
        let (account_id, ref coords) = self.input_coordinates[input_index];
        match (&self.accounts[account_id as usize], coords) {
            (
                PsbtAccount::WalletPolicy(wallet_policy),
                PsbtAccountCoordinates::WalletPolicy(coords),
            ) => InputAccount::WalletPolicy {
                account_id,
                wallet_policy,
                coords,
            },
            (
                PsbtAccount::SilentPayment(account),
                PsbtAccountCoordinates::SilentPayment(SilentPaymentCoordinates::Tweak(tweak)),
            ) => InputAccount::SilentPayment { account, tweak },
            _ => unreachable!("the analysis checks the coordinates of the inputs"),
        }
    }
}

/// The account that an input spends from, with the input's coordinates in it.
pub(super) enum InputAccount<'a> {
    WalletPolicy {
        account_id: u32,
        wallet_policy: &'a WalletPolicy,
        coords: &'a WalletPolicyCoordinates,
    },
    /// A silent payment account, and the tweak of the output that the input spends (BIP-376).
    SilentPayment {
        account: &'a SilentPaymentAccount,
        tweak: &'a [u8; 32],
    },
}

/// The accounts a PSBT declares in its global section, with their names and the raw
/// proofs of registration whose validation is deferred.
struct Accounts {
    accounts: Vec<PsbtAccount>,
    names: Vec<Option<String>>,
    proofs: Vec<[u8; 32]>,
}

/// Whether `por` is the proof of registration of `account` with the name `name`.
fn is_registered(account: &PsbtAccount, name: &str, por: &[u8; 32]) -> bool {
    fn check<T: Account>(account: &T, name: &str, por: &[u8; 32]) -> bool {
        ProofOfRegistration::<T>::from_bytes(*por)
            == ProofOfRegistration::new(&account.registration_id(name))
    }
    match account {
        PsbtAccount::WalletPolicy(wallet_policy) => check(wallet_policy, name, por),
        PsbtAccount::SilentPayment(account) => check(account, name, por),
    }
}

/// Fails unless `coords` are coordinates of `account` that an input (if `is_input`) or an output
/// can have. An input of a silent payment account spends an output that the account received, by
/// its tweak; an output pays to one of its codes. An output with a tweak would pay to the account,
/// but scanning with its scan key would never find it.
fn check_coordinates(
    account: &PsbtAccount,
    coords: &PsbtAccountCoordinates,
    is_input: bool,
) -> Result<(), Error> {
    match (account, coords) {
        (PsbtAccount::WalletPolicy(_), PsbtAccountCoordinates::WalletPolicy(_)) => Ok(()),
        (
            PsbtAccount::SilentPayment(_),
            PsbtAccountCoordinates::SilentPayment(SilentPaymentCoordinates::Tweak(_)),
        ) if is_input => Ok(()),
        (
            PsbtAccount::SilentPayment(_),
            PsbtAccountCoordinates::SilentPayment(SilentPaymentCoordinates::Code { .. }),
        ) if !is_input => Ok(()),
        _ => Err(Error::AccountCoordinatesMismatch),
    }
}

fn read_accounts(psbt: &fastpsbt::Psbt) -> Result<Accounts, Error> {
    let accounts = psbt
        .get_accounts()
        .map_err(|_| Error::InvalidWalletPolicy)?;

    let mut names = Vec::with_capacity(accounts.len());
    let mut proofs = Vec::with_capacity(accounts.len());
    for account_id in 0..accounts.len() {
        let name = psbt
            .get_account_name(account_id as u32)
            .map_err(|_| Error::InvalidWalletPolicy)?;
        names.push(name);

        let por = psbt
            .get_account_proof_of_registration(account_id as u32)
            .map_err(|_| Error::InvalidWalletPolicy)?;
        let por = por.ok_or(Error::DefaultAccountsNotSupported)?;
        proofs.push(
            por.try_into()
                .map_err(|_| Error::InvalidProofOfRegistrationLength)?,
        );
    }

    Ok(Accounts {
        accounts,
        names,
        proofs,
    })
}

/// Reads the identity keys registered in the PSBT's global section, checking each
/// one's proof of registration, and returns the compressed-pubkey → name lookup that
/// output auth proofs resolve against.
fn read_identity_keys(psbt: &fastpsbt::Psbt) -> Result<Vec<([u8; 33], String)>, Error> {
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

    Ok(identity_key_names)
}

/// Resolves an input's prevout: its witness UTXO if it has one, otherwise the output
/// that `output_index` selects in its non-witness UTXO.
///
/// This is the single definition of "the prevout of input *i*", shared by the analysis
/// below and the taproot sighash paths via [`ensure_prevouts`]. Two independent
/// definitions is what produced the out-of-range `output_index` panic and the same bug
/// before it.
///
/// `output_index` comes straight from the PSBT and is attacker-controlled, so it is
/// bounds-checked against the referenced transaction rather than used to index.
pub(super) fn input_prevout<'i>(input: &'i fastpsbt::Input<'_>) -> Result<&'i TxOut, Error> {
    if let Some(witness_utxo) = input
        .get_witness_utxo()
        .map_err(|_| Error::InvalidWitnessUtxo)?
    {
        return Ok(witness_utxo);
    }

    let non_witness_utxo = input
        .get_non_witness_utxo()
        .map_err(|_| Error::InvalidNonWitnessUtxo)?
        .ok_or(Error::MissingInputUtxo)?;
    let output_index = input
        .output_index
        .ok_or(Error::MissingPreviousOutputIndex)? as usize;
    non_witness_utxo
        .output
        .get(output_index)
        .ok_or(Error::InvalidNonWitnessUtxo)
}

/// Lazily materializes the prevouts list shared by all taproot sighashes in
/// input order. SegWit inputs use their witness UTXO; legacy inputs fall back to
/// the referenced output in their non-witness UTXO.
pub(super) fn ensure_prevouts<'a>(
    cache: &'a mut Option<Vec<TxOut>>,
    psbt: &fastpsbt::Psbt,
) -> Result<&'a [TxOut], Error> {
    if cache.is_none() {
        *cache = Some(
            psbt.inputs
                .iter()
                .map(|input| input_prevout(input).cloned())
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    cache.as_deref().ok_or(Error::MissingInputUtxo)
}

/// What one input contributes to the analysis.
struct AnalyzedInput<'i> {
    prevout: &'i TxOut,
    /// A SegWit v0 input with no non-witness UTXO: its amount can't be checked against
    /// the transaction that funded it, so the user gets warned.
    amount_unverified: bool,
}

/// Structural validation of a single input against the account it claims to belong to:
/// the UTXO kinds its segwit version permits, the non-witness UTXO's txid, and the
/// redeem/witness scripts, and for an input of a silent payment account its tweak. Checking that
/// the account's destination is the spent script is deferred.
fn analyze_input<'i>(
    input: &'i fastpsbt::Input<'_>,
    account: &PsbtAccount,
    coords: &PsbtAccountCoordinates,
) -> Result<AnalyzedInput<'i>, Error> {
    let segwit_version = match (account, coords) {
        (PsbtAccount::WalletPolicy(wallet_policy), PsbtAccountCoordinates::WalletPolicy(_)) => {
            wallet_policy
                .get_segwit_version()
                .map_err(|_| Error::InvalidWalletPolicy)?
        }
        // BIP-376: the input spends a taproot output with the tweak of its coordinates, which other
        // signers find in its PSBT_IN_SP_TWEAK
        (
            PsbtAccount::SilentPayment(_),
            PsbtAccountCoordinates::SilentPayment(SilentPaymentCoordinates::Tweak(tweak)),
        ) => {
            if input.sp_tweak != Some(tweak) {
                return Err(Error::SilentPaymentTweakMismatch);
            }
            SegwitVersion::Taproot
        }
        _ => return Err(Error::AccountCoordinatesMismatch),
    };

    // Only SIGHASH_ALL is supported, and its taproot equivalent SIGHASH_DEFAULT. Without a
    // sighash type, the device signs with SIGHASH_ALL (SIGHASH_DEFAULT for taproot).
    match (input.sighash_type, segwit_version) {
        (None | Some(0x01), _) | (Some(0x00), SegwitVersion::Taproot) => {}
        _ => return Err(Error::UnsupportedSighashType),
    }

    if segwit_version == SegwitVersion::Legacy && input.witness_utxo.is_some() {
        return Err(Error::WitnessUtxoNotAllowedForLegacy);
    }

    let mut amount_unverified = false;
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
                    amount_unverified = true;
                }
            }
        }
    }

    if segwit_version.is_segwit() && input.witness_utxo.is_none() {
        return Err(Error::WitnessUtxoRequiredForSegwit);
    }

    // Resolving the prevout first bounds-checks the attacker-controlled `output_index`
    // before the redeem-script checks below read the referenced output. The two checks
    // above pin down which UTXO it came from: a segwit input has a witness UTXO and a
    // legacy one is forbidden from carrying one, so `prevout` is the witness UTXO in the
    // first branch and the non-witness one in the second.
    let prevout = input_prevout(input)?;

    if segwit_version.is_segwit() {
        let script = if let Some(redeem_script) = input.redeem_script {
            let redeem_script = ScriptBuf::from_bytes(redeem_script.to_vec());
            if prevout.script_pubkey != redeem_script.to_p2sh() {
                return Err(Error::RedeemScriptMismatchWitness);
            }
            redeem_script
        } else {
            prevout.script_pubkey.clone()
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
    } else if let Some(redeem_script) = input.redeem_script {
        let redeem_script = ScriptBuf::from_bytes(redeem_script.to_vec());
        if prevout.script_pubkey != redeem_script.to_p2sh() {
            return Err(Error::RedeemScriptMismatch);
        }
    }

    Ok(AnalyzedInput {
        prevout,
        amount_unverified,
    })
}

/// What one output turns out to be.
enum AnalyzedOutput {
    /// Pays back to one of the PSBT's own accounts; its destination goes to the deferred
    /// ownership check.
    Internal(OwnershipCheck),
    /// Pays elsewhere: to a destination, and `Some(name)` if it carries a valid id_auth proof
    /// from an identity key registered in this PSBT.
    External(Destination, Option<String>),
}

/// Classifies one output and, when it is external, verifies any identity-key auth
/// proofs it carries.
///
/// That verification is *not* deferred, even though it looks as expensive as the
/// account checks that are. The resolved identity name feeds straight into the
/// transaction-review screen: deferring it would let the user see an unverified name
/// before the check that validates it had run. This is intentional.
fn analyze_output(
    output: &fastpsbt::Output<'_>,
    coordinates: Option<&(u32, PsbtAccountCoordinates)>,
    accounts: &[PsbtAccount],
    identity_key_names: &[([u8; 33], String)],
) -> Result<AnalyzedOutput, Error> {
    // An output to a silent payment code is external: its script, if the PSBT has one, is only
    // checked against the code after the review. Identity keys sign scripts, and the coordinates
    // of a wallet policy derive one, so neither can apply to it.
    if let Some(sp_v0_info) = output.sp_v0_info {
        let has_auth_proofs = !output
            .get_auth_proofs()
            .map_err(|_| Error::InvalidIdentitySignature)?
            .is_empty();
        if coordinates.is_some() || has_auth_proofs {
            return Err(Error::UnsupportedSilentPayment);
        }
        let code =
            SilentPaymentCode::from_bytes(sp_v0_info).map_err(|_| Error::InvalidSilentPayment)?;
        return Ok(AnalyzedOutput::External(
            Destination::SilentPaymentCode(code),
            None,
        ));
    }

    let Some((account_id, coords)) = coordinates else {
        let proofs = output
            .get_auth_proofs()
            .map_err(|_| Error::InvalidIdentitySignature)?;
        let out_script = output.script.ok_or(Error::OutputScriptMissing)?;

        let mut first_auth_name: Option<String> = None;
        for proof in proofs {
            match proof {
                common::psbt::OutputAuthProof::IdentitySignature { pubkey, sig } => {
                    // Verify the Schnorr signature against the output scriptPubKey.
                    let ecfp_pubkey =
                        EcfpPublicKey::<sdk::curve::Secp256k1, 32>::from_compressed(&pubkey)
                            .map_err(|_| Error::InvalidIdentitySignature)?;
                    let msg = build_identity_message(MSG_TYPE_OUTPUT, out_script)
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
        return Ok(AnalyzedOutput::External(
            Destination::Script(ScriptBuf::from_bytes(out_script.to_vec())),
            first_auth_name,
        ));
    };

    let account = accounts
        .get(*account_id as usize)
        .ok_or(Error::InvalidAccountId)?;
    check_coordinates(account, coords, false)?;

    let out_script_pubkey = output.script.ok_or(Error::OutputScriptMissing)?;

    Ok(AnalyzedOutput::Internal(OwnershipCheck {
        account_id: *account_id,
        coords: coords.clone(),
        expected: Destination::Script(ScriptBuf::from_bytes(out_script_pubkey.to_vec())),
        is_input: false,
    }))
}

/// Perform cheap structural validation of the PSBT and extract the data needed for
/// UI display ([`TransactionSummary`]) and deferred cryptographic verification
/// ([`DeferredChecks`]).
///
/// Expensive operations (proof-of-registration validation, script derivation) are NOT
/// performed here — they are deferred to [`DeferredChecks::verify`].
pub(super) fn analyze_transaction(
    psbt: &fastpsbt::Psbt,
) -> Result<(TransactionSummary, DeferredChecks), Error> {
    let Accounts {
        accounts,
        names: account_names,
        proofs: account_proofs,
    } = read_accounts(psbt)?;
    let identity_key_names = read_identity_keys(psbt)?;

    let mut account_spent_amounts: Vec<i64> = vec![0; accounts.len()];
    let mut external_outputs = Vec::new();
    let mut inputs_total_amount: u64 = 0;
    let mut outputs_total_amount: u64 = 0;
    let mut warn_unverified_inputs = false;
    let mut ownership_checks = Vec::new();

    /***** input checks (structural only — script derivation is deferred) *****/

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

    for (input_index, input) in psbt.inputs.iter().enumerate() {
        let (account_id, ref coords) = input_coordinates[input_index];

        if account_id as usize >= accounts.len() {
            return Err(Error::InvalidAccountId);
        }

        let account = &accounts[account_id as usize];
        check_coordinates(account, coords, true)?;

        let analyzed = analyze_input(input, account, coords)?;
        warn_unverified_inputs |= analyzed.amount_unverified;

        ownership_checks.push(OwnershipCheck {
            account_id,
            coords: coords.clone(),
            expected: Destination::Script(analyzed.prevout.script_pubkey.clone()),
            is_input: true,
        });

        let value = analyzed.prevout.value.to_sat();
        account_spent_amounts[account_id as usize] += value as i64;
        inputs_total_amount += value;
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

        match analyze_output(
            output,
            output_coordinates[output_index].as_ref(),
            &accounts,
            &identity_key_names,
        )? {
            AnalyzedOutput::Internal(check) => {
                account_spent_amounts[check.account_id as usize] -= amount as i64;
                ownership_checks.push(check);
            }
            AnalyzedOutput::External(destination, auth_name) => {
                external_outputs.push(ExternalOutput {
                    output_index,
                    destination,
                    auth_name,
                });
            }
        }

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
        external_outputs,
        inputs_total_amount,
        outputs_total_amount,
        warn_unverified_inputs,
    };

    Ok((
        summary,
        DeferredChecks {
            account_proofs,
            ownership_checks,
        },
    ))
}

impl DeferredChecks {
    /// Runs the expensive checks. The caller drives this on a background task so it
    /// overlaps with the approval UI, yielding between checks to stay responsive.
    pub(super) async fn verify(&self, summary: &TransactionSummary) -> Result<(), Error> {
        let accounts = &summary.accounts;

        // Verify proof-of-registration for each account
        for (account_id, account) in accounts.iter().enumerate() {
            let account_name = summary.account_names[account_id].as_deref().unwrap_or("");
            if !is_registered(account, account_name, &self.account_proofs[account_id]) {
                return Err(Error::InvalidProofOfRegistration);
            }
            sdk::executor::yield_now().await;
        }

        // Verify that each input/output has the account's destination at its coordinates
        for check in &self.ownership_checks {
            let destination = accounts[check.account_id as usize].destination(&check.coords)?;
            if destination != check.expected {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::{
        consensus::serialize, hashes::Hash, Amount, ScriptBuf, Transaction, TxOut, Txid,
    };
    use common::{fastpsbt::*, psbt::PsbtV2};

    use super::super::test_utils::{legacy_pkh_psbt, segwit_wpkh_psbt, serialize_as_psbtv2};

    /// Runs the analysis over a PSBT fixture, serialized the way the handler receives it.
    fn analyze(psbt: &PsbtV2) -> Result<(TransactionSummary, DeferredChecks), Error> {
        let serialized = psbt.serialize();
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        analyze_transaction(&parsed)
    }

    /// A scriptPubKey that is not the P2SH of anything the fixtures carry.
    fn bogus_redeem_script() -> ScriptBuf {
        ScriptBuf::from_bytes(
            hex_literal::hex!("0014 00112233445566778899aabbccddeeff00112233").to_vec(),
        )
    }

    /// Both fixtures must analyze cleanly, so every rejection below can be attributed
    /// to the one thing that test changes.
    #[test]
    fn unmodified_fixtures_are_accepted() {
        let (summary, checks) = analyze(&legacy_pkh_psbt()).unwrap();
        assert_eq!(summary.inputs_total_amount, 1_000_000);
        // One input belonging to the account; the single output is external.
        assert_eq!(checks.ownership_checks.len(), 1);
        assert!(checks.ownership_checks[0].is_input);
        assert_eq!(summary.external_outputs.len(), 1);
        assert_eq!(summary.external_outputs[0].output_index, 0);
        assert!(!summary.warn_unverified_inputs);

        assert!(analyze(&segwit_wpkh_psbt()).is_ok());
    }

    /// `PSBT_IN_OUTPUT_INDEX` is attacker-controlled and must be bounds-checked against
    /// the non-witness UTXO it selects into: pointing it past the end used to panic.
    #[test]
    fn out_of_range_output_index_is_rejected() {
        let mut psbt = legacy_pkh_psbt();
        // The referenced transaction has 2 outputs; select a nonexistent one. The txid
        // still matches, so the non-witness-UTXO check ahead of this one passes.
        psbt.inputs[0].insert(PSBT_IN_OUTPUT_INDEX, &[], 5u32.to_le_bytes().to_vec());

        assert_eq!(analyze(&psbt).err(), Some(Error::InvalidNonWitnessUtxo));
    }

    #[test]
    fn legacy_input_may_not_carry_a_witness_utxo() {
        let mut psbt = legacy_pkh_psbt();
        let utxo = TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::new(),
        };
        psbt.inputs[0].insert(PSBT_IN_WITNESS_UTXO, &[], serialize(&utxo));

        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::WitnessUtxoNotAllowedForLegacy)
        );
    }

    #[test]
    fn legacy_input_requires_a_non_witness_utxo() {
        let mut psbt = legacy_pkh_psbt();
        psbt.inputs[0].remove(PSBT_IN_NON_WITNESS_UTXO, &[]);

        assert_eq!(analyze(&psbt).err(), Some(Error::NonWitnessUtxoRequired));
    }

    #[test]
    fn non_witness_utxo_must_hash_to_the_spent_txid() {
        let mut psbt = legacy_pkh_psbt();
        // Keep the UTXO, point the input somewhere else.
        psbt.inputs[0].insert(PSBT_IN_PREVIOUS_TXID, &[], vec![0x42; 32]);

        assert_eq!(analyze(&psbt).err(), Some(Error::NonWitnessUtxoMismatch));
    }

    #[test]
    fn legacy_redeem_script_must_hash_to_the_prevout_script() {
        let mut psbt = legacy_pkh_psbt();
        psbt.inputs[0].insert(PSBT_IN_REDEEM_SCRIPT, &[], bogus_redeem_script().to_bytes());

        assert_eq!(analyze(&psbt).err(), Some(Error::RedeemScriptMismatch));
    }

    #[test]
    fn segwit_input_requires_a_witness_utxo() {
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].remove(PSBT_IN_WITNESS_UTXO, &[]);

        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::WitnessUtxoRequiredForSegwit)
        );
    }

    #[test]
    fn segwit_redeem_script_must_hash_to_the_witness_utxo_script() {
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].insert(PSBT_IN_REDEEM_SCRIPT, &[], bogus_redeem_script().to_bytes());

        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::RedeemScriptMismatchWitness)
        );
    }

    #[test]
    fn outputs_may_not_exceed_inputs() {
        let mut psbt = legacy_pkh_psbt();
        // The single input is worth 1_000_000 sat.
        psbt.outputs[0].insert(PSBT_OUT_AMOUNT, &[], 1_000_001u64.to_le_bytes().to_vec());

        assert_eq!(analyze(&psbt).err(), Some(Error::InputsLessThanOutputs));
    }

    /// The coordinates of an input or an output must be those of its account's type.
    #[test]
    fn coordinates_must_fit_the_account() {
        use common::psbt::{PsbtAccountInputWrite, PsbtAccountOutputWrite};

        let coords = || {
            PsbtAccountCoordinates::SilentPayment(SilentPaymentCoordinates::Code { label: None })
        };
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].set_account_coordinates(0, coords()).unwrap();
        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::AccountCoordinatesMismatch)
        );

        let mut psbt = segwit_wpkh_psbt();
        psbt.outputs[0]
            .set_account_coordinates(0, coords())
            .unwrap();
        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::AccountCoordinatesMismatch)
        );
    }

    /// A SegWit v0 input with no non-witness UTXO is accepted, but its amount can't be
    /// checked against the funding transaction, so the user must be warned.
    #[test]
    fn segwit_input_without_non_witness_utxo_warns() {
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].remove(PSBT_IN_NON_WITNESS_UTXO, &[]);

        let (summary, _) = analyze(&psbt).unwrap();
        assert!(summary.warn_unverified_inputs);
    }

    #[test]
    fn ensure_prevouts_supports_mixed_utxo_types() {
        let witness_prevout = TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: ScriptBuf::new(),
        };
        let legacy_prevout = TxOut {
            value: Amount::from_sat(70_000),
            script_pubkey: ScriptBuf::new(),
        };
        let legacy_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![legacy_prevout.clone()],
        };
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: Txid::from_byte_array([0x42; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: legacy_tx.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![],
        };
        let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(witness_prevout.clone());
        psbt.inputs[1].non_witness_utxo = Some(legacy_tx);

        let serialized = serialize_as_psbtv2(&psbt);
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        let mut cache = None;
        assert_eq!(
            ensure_prevouts(&mut cache, &parsed).unwrap(),
            &[witness_prevout, legacy_prevout]
        );
    }
}
