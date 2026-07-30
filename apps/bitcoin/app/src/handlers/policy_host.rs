//! Binds a parsed PSBT and its analysis to the [`PolicyHost`] interface.
//!
//! Everything a policy can read is precomputed here, so the ecall path never has to
//! parse or derive: it only copies. Per-input prevouts are the one genuinely
//! expensive part, and they are gathered once at construction.

use alloc::{string::String, vec::Vec};

use bitcoin::ScriptBuf;
use common::{
    account::DescriptorTemplate,
    errors::Error,
    fastpsbt,
    message::WalletPolicyCoordinates,
    psbt::{account::PsbtAccountOutputRead, PsbtAccount, PsbtAccountCoordinates},
};

use crate::policy::{
    host::{
        PolicyAttempt, PolicyCoords, PolicyHost, INPUT_FLAG_AMOUNT_VERIFIED,
        INPUT_FLAG_HAS_WITNESS_UTXO, INPUT_FLAG_IN_ACCOUNT, INPUT_FLAG_SEGWIT_SHIFT,
        OUTPUT_FLAG_IS_AUTHENTICATED, OUTPUT_FLAG_IS_INTERNAL,
    },
};

struct HostInput {
    amount: u64,
    script_pubkey: ScriptBuf,
    prevout: [u8; 36],
    sequence: u32,
    flags: u32,
    coords: Option<PolicyCoords>,
    taptree: Option<[u8; 32]>,
}

struct HostOutput {
    amount: u64,
    script_pubkey: Vec<u8>,
    flags: u32,
    coords: Option<PolicyCoords>,
}

/// Everything one policy sees for one transaction.
pub struct PsbtPolicyHost<'a> {
    raw_psbt: &'a [u8],
    tx_version: u32,
    locktime: u32,
    inputs_total: u64,
    outputs_total: u64,
    inputs: Vec<HostInput>,
    outputs: Vec<HostOutput>,
    policy_hash: [u8; 32],
    attempts: Vec<PolicyAttempt>,
    /// Compressed pubkey per attempt, parallel to `attempts`.
    self_pubkeys: Vec<[u8; 33]>,
}

/// The per-transaction facts the host needs that `TransactionSummary` owns.
pub struct HostSummary<'s> {
    pub accounts: &'s [PsbtAccount],
    pub input_coordinates: &'s [(u32, PsbtAccountCoordinates)],
    pub external_outputs_indexes: &'s [usize],
    pub external_output_auth_names: &'s [Option<String>],
    pub inputs_total_amount: u64,
    pub outputs_total_amount: u64,
}

impl<'a> PsbtPolicyHost<'a> {
    pub fn new(
        psbt: &'a fastpsbt::Psbt<'a>,
        summary: &HostSummary<'_>,
        policy_hash: [u8; 32],
        attempts: Vec<PolicyAttempt>,
        self_pubkeys: Vec<[u8; 33]>,
    ) -> Result<Self, Error> {
        let locktime = psbt
            .unsigned_tx()
            .map_err(|_| Error::FailedUnsignedTransaction)?
            .lock_time
            .to_consensus_u32();

        let mut inputs = Vec::with_capacity(psbt.inputs.len());
        for (i, input) in psbt.inputs.iter().enumerate() {
            let prevout_txout = super::sign_psbt::input_prevout(input)?;

            let mut flags = 0u32;
            if input.witness_utxo.is_some() {
                flags |= INPUT_FLAG_HAS_WITNESS_UTXO;
            }
            // `analyze_transaction` has already rejected a non-witness UTXO whose
            // txid does not match, so its presence is exactly the verified case.
            if input.non_witness_utxo.is_some() {
                flags |= INPUT_FLAG_AMOUNT_VERIFIED;
            }

            let coords = summary.input_coordinates.get(i).map(|(account_id, c)| {
                flags |= INPUT_FLAG_IN_ACCOUNT;
                let PsbtAccountCoordinates::WalletPolicy(c) = c;
                PolicyCoords {
                    account_index: *account_id,
                    is_change: c.is_change,
                    address_index: c.address_index,
                }
            });

            let mut taptree = None;
            if let Some((account_id, PsbtAccountCoordinates::WalletPolicy(c))) =
                summary.input_coordinates.get(i)
            {
                let PsbtAccount::WalletPolicy(wallet_policy) =
                    &summary.accounts[*account_id as usize];
                if let Some(version) = wallet_policy.get_segwit_version().ok() {
                    // Encoded as version + 1 so that 0 means "not segwit".
                    flags |= ((version as u32) + 1) << INPUT_FLAG_SEGWIT_SHIFT;
                }
                if matches!(wallet_policy.descriptor_template(), DescriptorTemplate::Tr(..)) {
                    taptree = super::sign_psbt::taptree_hash_for(wallet_policy, c)?;
                }
            }

            let mut prevout = [0u8; 36];
            if let Some(txid) = input.previous_txid {
                prevout[..32].copy_from_slice(txid);
            }
            prevout[32..].copy_from_slice(&input.output_index.unwrap_or(0).to_le_bytes());

            inputs.push(HostInput {
                amount: prevout_txout.value.to_sat(),
                script_pubkey: prevout_txout.script_pubkey,
                prevout,
                sequence: input.sequence.unwrap_or(0xFFFF_FFFF),
                flags,
                coords,
                taptree,
            });
        }

        let mut outputs = Vec::with_capacity(psbt.outputs.len());
        for (j, output) in psbt.outputs.iter().enumerate() {
            let mut flags = 0u32;

            let coords = output
                .get_account_coordinates()
                .map_err(|_| Error::FailedToGetAccounts)?
                .map(|(account_id, PsbtAccountCoordinates::WalletPolicy(c))| {
                    flags |= OUTPUT_FLAG_IS_INTERNAL;
                    PolicyCoords {
                        account_index: account_id,
                        is_change: c.is_change,
                        address_index: c.address_index,
                    }
                });

            // `external_output_auth_names` is parallel to `external_outputs_indexes`.
            if let Some(pos) = summary.external_outputs_indexes.iter().position(|&x| x == j) {
                if summary
                    .external_output_auth_names
                    .get(pos)
                    .and_then(Option::as_ref)
                    .is_some()
                {
                    flags |= OUTPUT_FLAG_IS_AUTHENTICATED;
                }
            }

            outputs.push(HostOutput {
                amount: output.amount.ok_or(Error::OutputAmountMissing)?,
                script_pubkey: output.script.ok_or(Error::OutputScriptMissing)?.to_vec(),
                flags,
                coords,
            });
        }

        Ok(Self {
            raw_psbt: psbt.raw_psbt,
            tx_version: psbt.tx_version as u32,
            locktime,
            inputs_total: summary.inputs_total_amount,
            outputs_total: summary.outputs_total_amount,
            inputs,
            outputs,
            policy_hash,
            attempts,
            self_pubkeys,
        })
    }
}

impl<'a> PolicyHost for PsbtPolicyHost<'a> {
    fn tx_version(&self) -> u32 {
        self.tx_version
    }
    fn locktime(&self) -> u32 {
        self.locktime
    }
    fn input_count(&self) -> u32 {
        self.inputs.len() as u32
    }
    fn output_count(&self) -> u32 {
        self.outputs.len() as u32
    }
    fn inputs_total(&self) -> u64 {
        self.inputs_total
    }
    fn outputs_total(&self) -> u64 {
        self.outputs_total
    }
    fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }
    fn attempts(&self) -> &[PolicyAttempt] {
        &self.attempts
    }
    fn self_pubkey(&self, k: u32) -> Option<[u8; 33]> {
        self.self_pubkeys.get(k as usize).copied()
    }
    fn input_amount(&self, i: u32) -> Option<u64> {
        self.inputs.get(i as usize).map(|x| x.amount)
    }
    fn input_prevout(&self, i: u32) -> Option<[u8; 36]> {
        self.inputs.get(i as usize).map(|x| x.prevout)
    }
    fn input_sequence(&self, i: u32) -> Option<u32> {
        self.inputs.get(i as usize).map(|x| x.sequence)
    }
    fn input_script_pubkey(&self, i: u32) -> Option<&[u8]> {
        self.inputs.get(i as usize).map(|x| x.script_pubkey.as_bytes())
    }
    fn input_flags(&self, i: u32) -> Option<u32> {
        self.inputs.get(i as usize).map(|x| x.flags)
    }
    fn input_account(&self, i: u32) -> Option<Option<PolicyCoords>> {
        self.inputs.get(i as usize).map(|x| x.coords)
    }
    fn input_taptree_hash(&self, i: u32) -> Option<Option<[u8; 32]>> {
        self.inputs.get(i as usize).map(|x| x.taptree)
    }
    fn output_amount(&self, i: u32) -> Option<u64> {
        self.outputs.get(i as usize).map(|x| x.amount)
    }
    fn output_script_pubkey(&self, i: u32) -> Option<&[u8]> {
        self.outputs.get(i as usize).map(|x| x.script_pubkey.as_slice())
    }
    fn output_flags(&self, i: u32) -> Option<u32> {
        self.outputs.get(i as usize).map(|x| x.flags)
    }
    fn output_account(&self, i: u32) -> Option<Option<PolicyCoords>> {
        self.outputs.get(i as usize).map(|x| x.coords)
    }
    fn raw_psbt(&self) -> &[u8] {
        self.raw_psbt
    }
}

/// Marker so the unused-import lint does not fire on the coordinate type alias.
const _: Option<WalletPolicyCoordinates> = None;
