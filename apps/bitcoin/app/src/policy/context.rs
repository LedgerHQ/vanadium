//! Engine-agnostic, read-only view of the PSBT that a policy script can inspect.
//!
//! `PolicyContext` is built once per evaluation and lives only for the duration of
//! the script. It holds a borrowed reference to the parsed PSBT plus pre-computed
//! summaries that are cheap to expose (totals, sorted derivation iterators, …).
//!
//! Anything Rhai-specific lives in [`crate::policy::engine::rhai`]; this module
//! must remain free of engine internals so it can be reused by future engines.

use alloc::vec::Vec;

use common::fastpsbt;

/// Read-only snapshot exposed to a signing-policy script.
pub struct PolicyContext<'a> {
    psbt: &'a fastpsbt::Psbt<'a>,
}

impl<'a> PolicyContext<'a> {
    pub fn new(psbt: &'a fastpsbt::Psbt<'a>) -> Self {
        Self { psbt }
    }

    pub fn tx_version(&self) -> i32 {
        self.psbt.tx_version
    }

    pub fn psbt_version(&self) -> u32 {
        self.psbt.version
    }

    pub fn input_count(&self) -> usize {
        self.psbt.inputs.len()
    }

    pub fn output_count(&self) -> usize {
        self.psbt.outputs.len()
    }

    pub fn input(&self, index: usize) -> Option<PolicyInput<'_>> {
        self.psbt.inputs.get(index).map(|i| PolicyInput { input: i })
    }

    pub fn output(&self, index: usize) -> Option<PolicyOutput<'_>> {
        self.psbt
            .outputs
            .get(index)
            .map(|o| PolicyOutput { output: o })
    }

    /// Total amount across all inputs whose witness UTXO is present, in satoshis.
    ///
    /// Inputs without a witness UTXO contribute 0 — for legacy inputs the policy
    /// must reach in via `input(i)` and parse the non-witness UTXO itself if it
    /// needs the value.
    pub fn inputs_total_value(&self) -> u64 {
        let mut total: u64 = 0;
        for input in &self.psbt.inputs {
            if let Ok(Some(utxo)) = input.get_witness_utxo() {
                total = total.saturating_add(utxo.value.to_sat());
            }
        }
        total
    }

    /// Total amount across all outputs, in satoshis.
    pub fn outputs_total_value(&self) -> u64 {
        let mut total: u64 = 0;
        for output in &self.psbt.outputs {
            if let Some(v) = output.amount {
                total = total.saturating_add(v);
            }
        }
        total
    }
}

/// Read-only view of a single PSBT input exposed to policy scripts.
pub struct PolicyInput<'a> {
    input: &'a fastpsbt::Input<'a>,
}

impl<'a> PolicyInput<'a> {
    pub fn sequence(&self) -> Option<u32> {
        self.input.sequence
    }

    pub fn prev_txid(&self) -> Option<[u8; 32]> {
        self.input.previous_txid.copied()
    }

    pub fn prev_vout(&self) -> Option<u32> {
        self.input.output_index
    }

    pub fn sighash_type(&self) -> Option<u32> {
        self.input.sighash_type
    }

    pub fn redeem_script(&self) -> Option<&'a [u8]> {
        self.input.redeem_script
    }

    pub fn witness_script(&self) -> Option<&'a [u8]> {
        self.input.witness_script
    }

    /// Returns the input value in satoshis if a witness UTXO is present.
    pub fn value_sats(&self) -> Option<u64> {
        self.input
            .get_witness_utxo()
            .ok()
            .flatten()
            .map(|u| u.value.to_sat())
    }

    /// Returns the spending scriptPubKey if a witness UTXO is present.
    pub fn script_pubkey(&self) -> Option<Vec<u8>> {
        self.input
            .get_witness_utxo()
            .ok()
            .flatten()
            .map(|u| u.script_pubkey.as_bytes().to_vec())
    }
}

/// Read-only view of a single PSBT output exposed to policy scripts.
pub struct PolicyOutput<'a> {
    output: &'a fastpsbt::Output<'a>,
}

impl<'a> PolicyOutput<'a> {
    pub fn value_sats(&self) -> Option<u64> {
        self.output.amount
    }

    pub fn script_pubkey(&self) -> Option<&'a [u8]> {
        self.output.script
    }
}
