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

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use common::{
    bip388::SegwitVersion,
    dns_identity::{verify_dnssec_identity_key, MAX_DNSSEC_IDENTITY_KEYS},
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

/// How trust in an identity key was established.
///
/// This is shown to the user, because the two are not interchangeable: a registered name is one the
/// user typed during a ceremony they took part in, while a DNS name is a claim by whoever controls
/// the zone. See `docs/identity.md`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum TrustSource {
    /// Registered on this device, under a name chosen by the user.
    Registered,
    /// Proven by a DNSSEC chain to be published by a human-readable name.
    Dnssec,
}

/// The name of an identity key, together with how it came to be trusted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct AuthLabel {
    pub(super) name: String,
    pub(super) source: TrustSource,
}

impl AuthLabel {
    /// The name as it should appear on screen.
    ///
    /// BIP-353 asks that a DNSSEC-verified name be prefixed with `₿`. The prefix is not load-bearing
    /// here: the provenance is also stated in the tag of the review row, so a device whose font
    /// cannot render U+20BF still distinguishes the two sources.
    pub(super) fn display_name(&self) -> String {
        match self.source {
            TrustSource::Registered => self.name.clone(),
            TrustSource::Dnssec => format!("₿{}", self.name),
        }
    }
}

/// A script derivation check to be verified in the background task.
struct ScriptCheck {
    account_id: u32,
    is_change: bool,
    address_index: u32,
    expected_script: ScriptBuf,
    is_input: bool,
}

/// The checks [`analyze_transaction`] hands to the background task: proof of
/// registration for every account, and script derivation for every input and every
/// output that belongs to one of them.
pub(super) struct DeferredChecks {
    account_proofs: Vec<ProofOfRegistration<common::bip388::WalletPolicy>>,
    script_checks: Vec<ScriptCheck>,
}

/// The result of analyzing a PSBT: lightweight data needed for UI display and signing.
pub(super) struct TransactionSummary {
    pub(super) accounts: Vec<PsbtAccount>,
    pub(super) account_names: Vec<Option<String>>,
    pub(super) input_coordinates: Vec<(u32, PsbtAccountCoordinates)>,
    pub(super) account_spent_amounts: Vec<i64>,
    pub(super) external_outputs_indexes: Vec<usize>,
    /// Parallel to `external_outputs_indexes`: `Some(label)` if the output carries a valid
    /// id_auth proof from a trusted identity key, `None` otherwise.
    pub(super) external_output_auth_names: Vec<Option<AuthLabel>>,
    /// The time a DNSSEC proof was validated against, if the PSBT carried any. Shown to the user,
    /// since it comes from the untrusted host.
    pub(super) dnssec_validation_time: Option<u64>,
    pub(super) inputs_total_amount: u64,
    pub(super) outputs_total_amount: u64,
    pub(super) warn_unverified_inputs: bool,
}

impl TransactionSummary {
    pub(super) fn fee(&self) -> u64 {
        self.inputs_total_amount - self.outputs_total_amount
    }
}

/// The accounts a PSBT declares in its global section, with their names and the raw
/// proofs of registration whose validation is deferred.
struct Accounts {
    accounts: Vec<PsbtAccount>,
    names: Vec<Option<String>>,
    proofs: Vec<ProofOfRegistration<common::bip388::WalletPolicy>>,
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
        let por = ProofOfRegistration::from_bytes(
            por.try_into()
                .map_err(|_| Error::InvalidProofOfRegistrationLength)?,
        );
        proofs.push(por);
    }

    Ok(Accounts {
        accounts,
        names,
        proofs,
    })
}

/// Reads the identity keys trusted for this PSBT — both registered on this device and
/// DNSSEC-authenticated — checking each one's proof, and returns the compressed-pubkey → label
/// lookup that output auth proofs resolve against.
///
/// Validating any DNSSEC proofs happens here too, and is the one expensive part: the names it
/// yields are needed before the review screens can be built, so it is deliberately eager rather
/// than deferred to [`DeferredChecks::verify`].
fn read_identity_keys(
    psbt: &fastpsbt::Psbt,
    current_time: Option<u64>,
) -> Result<(Vec<([u8; 33], AuthLabel)>, Option<u64>), Error> {
    let registered_identity_keys = psbt
        .get_registered_identity_keys()
        .map_err(|_| Error::InvalidIdentitySignature)?;

    let mut identity_key_names: Vec<([u8; 33], AuthLabel)> =
        Vec::with_capacity(registered_identity_keys.len());
    for rik in &registered_identity_keys {
        let ik = IdentityKey::new(rik.pubkey).map_err(|_| Error::InvalidIdentitySignature)?;
        let expected_por = ProofOfRegistration::<IdentityKey>::new(&ik.registration_id(&rik.name));
        let actual_por = ProofOfRegistration::<IdentityKey>::from_bytes(rik.por);
        if actual_por != expected_por {
            return Err(Error::InvalidProofOfRegistration);
        }
        identity_key_names.push((
            rik.pubkey,
            AuthLabel {
                name: rik.name.clone(),
                source: TrustSource::Registered,
            },
        ));
    }

    // Identity keys published in the DNS: validate each authentication chain, which proves that a
    // human-readable name publishes that public key.
    let dnssec_identity_keys = psbt
        .get_dnssec_identity_keys()
        .map_err(|_| Error::InvalidIdentitySignature)?;
    let mut dnssec_validation_time = None;
    if !dnssec_identity_keys.is_empty() {
        // Bound the work a host can ask for before the user sees anything.
        if dnssec_identity_keys.len() > MAX_DNSSEC_IDENTITY_KEYS {
            return Err(Error::DnssecValidationFailed);
        }
        let now = current_time.ok_or(Error::MissingCurrentTime)?;
        for dik in &dnssec_identity_keys {
            // A key trusted for two different reasons would leave it ambiguous which name to show,
            // and a coordinator has no reason to send both.
            if identity_key_names.iter().any(|(pk, _)| pk == &dik.pubkey) {
                return Err(Error::DuplicateIdentityKey);
            }
            IdentityKey::new(dik.pubkey).map_err(|_| Error::InvalidIdentitySignature)?;
            verify_dnssec_identity_key(dik.name, dik.chain, &dik.pubkey, now)?;
            identity_key_names.push((
                dik.pubkey,
                AuthLabel {
                    name: dik.name.to_string(),
                    source: TrustSource::Dnssec,
                },
            ));
        }
        dnssec_validation_time = Some(now);
    }

    Ok((identity_key_names, dnssec_validation_time))
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
fn input_prevout<'i>(input: &'i fastpsbt::Input<'_>) -> Result<&'i TxOut, Error> {
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
/// redeem/witness scripts. Script *derivation* is deferred.
fn analyze_input<'i>(
    input: &'i fastpsbt::Input<'_>,
    wallet_policy: &common::bip388::WalletPolicy,
) -> Result<AnalyzedInput<'i>, Error> {
    let segwit_version = wallet_policy
        .get_segwit_version()
        .map_err(|_| Error::InvalidWalletPolicy)?;

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
    /// Pays back to one of the PSBT's own accounts; its script goes to the deferred
    /// derivation check.
    Internal(ScriptCheck),
    /// Pays elsewhere. `Some(label)` if it carries a valid id_auth proof from a trusted
    /// identity key.
    External(Option<AuthLabel>),
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
    n_accounts: usize,
    identity_key_names: &[([u8; 33], AuthLabel)],
) -> Result<AnalyzedOutput, Error> {
    let Some((account_id, coords)) = coordinates else {
        let proofs = output
            .get_auth_proofs()
            .map_err(|_| Error::InvalidIdentitySignature)?;
        let out_script_bytes = output.script.ok_or(Error::OutputScriptMissing)?.to_vec();

        let mut first_auth_name: Option<AuthLabel> = None;
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
                    // Look up the name of this pubkey, if it is one we trust
                    if first_auth_name.is_none() {
                        first_auth_name = identity_key_names
                            .iter()
                            .find(|(pk, _)| *pk == pubkey)
                            .map(|(_, label)| label.clone());
                    }
                }
            }
        }
        return Ok(AnalyzedOutput::External(first_auth_name));
    };

    if *account_id as usize >= n_accounts {
        return Err(Error::InvalidAccountId);
    }
    let PsbtAccountCoordinates::WalletPolicy(coords) = coords;

    let out_script_pubkey = output.script.ok_or(Error::OutputScriptMissing)?;
    let out_script_pubkey = ScriptBuf::from_bytes(out_script_pubkey.to_vec());

    Ok(AnalyzedOutput::Internal(ScriptCheck {
        account_id: *account_id,
        is_change: coords.is_change,
        address_index: coords.address_index,
        expected_script: out_script_pubkey,
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
    current_time: Option<u64>,
) -> Result<(TransactionSummary, DeferredChecks), Error> {
    let Accounts {
        accounts,
        names: account_names,
        proofs: account_proofs,
    } = read_accounts(psbt)?;
    let (identity_key_names, dnssec_validation_time) = read_identity_keys(psbt, current_time)?;

    let mut account_spent_amounts: Vec<i64> = vec![0; accounts.len()];
    let mut external_outputs_indexes = Vec::new();
    let mut external_output_auth_names: Vec<Option<AuthLabel>> = Vec::new();
    let mut inputs_total_amount: u64 = 0;
    let mut outputs_total_amount: u64 = 0;
    let mut warn_unverified_inputs = false;
    let mut script_checks = Vec::new();

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

        let PsbtAccount::WalletPolicy(wallet_policy) = &accounts[account_id as usize];
        let PsbtAccountCoordinates::WalletPolicy(coords) = coords;

        let analyzed = analyze_input(input, wallet_policy)?;
        warn_unverified_inputs |= analyzed.amount_unverified;

        script_checks.push(ScriptCheck {
            account_id,
            is_change: coords.is_change,
            address_index: coords.address_index,
            expected_script: analyzed.prevout.script_pubkey.clone(),
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
            accounts.len(),
            &identity_key_names,
        )? {
            AnalyzedOutput::Internal(check) => {
                account_spent_amounts[check.account_id as usize] -= amount as i64;
                script_checks.push(check);
            }
            AnalyzedOutput::External(auth_name) => {
                external_outputs_indexes.push(output_index);
                external_output_auth_names.push(auth_name);
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
        external_outputs_indexes,
        external_output_auth_names,
        dnssec_validation_time,
        inputs_total_amount,
        outputs_total_amount,
        warn_unverified_inputs,
    };

    Ok((
        summary,
        DeferredChecks {
            account_proofs,
            script_checks,
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
            let PsbtAccount::WalletPolicy(wallet_policy) = account;
            let account_name = summary.account_names[account_id].as_deref().unwrap_or("");
            let id = wallet_policy.registration_id(account_name);
            if self.account_proofs[account_id] != ProofOfRegistration::new(&id) {
                return Err(Error::InvalidProofOfRegistration);
            }
            sdk::executor::yield_now().await;
        }

        // Verify that each input/output script matches the account derivation
        for check in &self.script_checks {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::{hashes::Hash, Amount, ScriptBuf, Transaction, TxOut, Txid};

    use super::super::test_utils::{legacy_pkh_psbt, segwit_wpkh_psbt, serialize_as_psbtv2};

    /// Runs the analysis over a `bitcoin::psbt::Psbt` fixture, re-encoding it as PSBTv2
    /// the way the handler receives it.
    fn analyze(psbt: &bitcoin::psbt::Psbt) -> Result<(TransactionSummary, DeferredChecks), Error> {
        let serialized = serialize_as_psbtv2(psbt);
        let parsed = fastpsbt::Psbt::parse(&serialized).unwrap();
        analyze_transaction(&parsed, None)
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
        assert_eq!(checks.script_checks.len(), 1);
        assert!(checks.script_checks[0].is_input);
        assert_eq!(summary.external_outputs_indexes, vec![0]);
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
        psbt.unsigned_tx.input[0].previous_output.vout = 5;

        assert_eq!(analyze(&psbt).err(), Some(Error::InvalidNonWitnessUtxo));
    }

    #[test]
    fn legacy_input_may_not_carry_a_witness_utxo() {
        let mut psbt = legacy_pkh_psbt();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::new(),
        });

        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::WitnessUtxoNotAllowedForLegacy)
        );
    }

    #[test]
    fn legacy_input_requires_a_non_witness_utxo() {
        let mut psbt = legacy_pkh_psbt();
        psbt.inputs[0].non_witness_utxo = None;

        assert_eq!(analyze(&psbt).err(), Some(Error::NonWitnessUtxoRequired));
    }

    #[test]
    fn non_witness_utxo_must_hash_to_the_spent_txid() {
        let mut psbt = legacy_pkh_psbt();
        // Keep the UTXO, point the input somewhere else.
        psbt.unsigned_tx.input[0].previous_output.txid = Txid::from_byte_array([0x42; 32]);

        assert_eq!(analyze(&psbt).err(), Some(Error::NonWitnessUtxoMismatch));
    }

    #[test]
    fn legacy_redeem_script_must_hash_to_the_prevout_script() {
        let mut psbt = legacy_pkh_psbt();
        psbt.inputs[0].redeem_script = Some(bogus_redeem_script());

        assert_eq!(analyze(&psbt).err(), Some(Error::RedeemScriptMismatch));
    }

    #[test]
    fn segwit_input_requires_a_witness_utxo() {
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].witness_utxo = None;

        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::WitnessUtxoRequiredForSegwit)
        );
    }

    #[test]
    fn segwit_redeem_script_must_hash_to_the_witness_utxo_script() {
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].redeem_script = Some(bogus_redeem_script());

        assert_eq!(
            analyze(&psbt).err(),
            Some(Error::RedeemScriptMismatchWitness)
        );
    }

    #[test]
    fn outputs_may_not_exceed_inputs() {
        let mut psbt = legacy_pkh_psbt();
        // The single input is worth 1_000_000 sat.
        psbt.unsigned_tx.output[0].value = Amount::from_sat(1_000_001);

        assert_eq!(analyze(&psbt).err(), Some(Error::InputsLessThanOutputs));
    }

    /// A SegWit v0 input with no non-witness UTXO is accepted, but its amount can't be
    /// checked against the funding transaction, so the user must be warned.
    #[test]
    fn segwit_input_without_non_witness_utxo_warns() {
        let mut psbt = segwit_wpkh_psbt();
        psbt.inputs[0].non_witness_utxo = None;

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

    #[test]
    fn auth_label_display_name_marks_dnssec_sourced_names() {
        let registered = AuthLabel {
            name: "Satoshi Nakamoto".to_string(),
            source: TrustSource::Registered,
        };
        assert_eq!(registered.display_name(), "Satoshi Nakamoto");

        let dnssec = AuthLabel {
            name: "alice@example.com".to_string(),
            source: TrustSource::Dnssec,
        };
        assert_eq!(dnssec.display_name(), "₿alice@example.com");
    }
}
