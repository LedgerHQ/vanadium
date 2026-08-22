//! Engine-agnostic, read-only context that a signing program can inspect.
//!
//! A [`PolicyContext`] is a flat bag of pre-computed aggregates derived from the
//! transaction being signed. It intentionally exposes *only* aggregate data (no
//! per-input / per-output access) — this keeps the language small and its data
//! model trivial to reason about.
//!
//! The [`Field`] enum is the single, typed schema of everything a program can
//! read via `context.<name>`. Adding a new readable quantity is a matter of
//! adding a variant here, mapping its name in [`Field::from_name`], and
//! returning its value in [`PolicyContext::get`]. This module must stay free of
//! any engine internals so it can be reused by future engines.

/// A value produced while evaluating a signing program.
///
/// The language is dynamically typed over this tiny set; there is no byte-string
/// type in v1 because there is no per-output script access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bool(bool),
}

/// The typed schema of readable `context.<name>` fields.
///
/// All monetary quantities are in satoshis. Amounts comfortably fit in `i64`
/// (21e6 BTC ≈ 2.1e15 sat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// Sum of all input amounts.
    InputsTotal,
    /// Sum of all output amounts.
    OutputsTotal,
    /// Sum of input amounts belonging to a recognized account (currently equals
    /// `InputsTotal`, since every input must belong to an account; kept for
    /// forward-compatibility with external inputs).
    InternalInTotal,
    /// Sum of amounts of outputs that do NOT belong to a recognized account
    /// (external recipients).
    ExternalOutTotal,
    /// Sum of amounts of outputs that belong to a recognized account (change /
    /// internal outputs).
    ChangeTotal,
    /// Transaction fee (`InputsTotal - OutputsTotal`).
    Fee,
    /// Fee as an integer percentage of `InputsTotal`, floored; `0` when there are
    /// no inputs.
    FeePercent,
    /// Number of inputs.
    InputCount,
    /// Number of outputs.
    OutputCount,
    /// Number of external (non-change) outputs.
    ExternalOutCount,
    /// Number of change / internal outputs.
    ChangeCount,
    /// Transaction version.
    TxVersion,
    /// Transaction locktime (the PSBT fallback locktime; `0` if unset).
    Locktime,
}

impl Field {
    /// Resolve a `context.<name>` field name. Returns `None` for unknown names
    /// (the engine turns this into a compile-time error).
    pub fn from_name(name: &str) -> Option<Field> {
        Some(match name {
            "inputs_total" => Field::InputsTotal,
            "outputs_total" => Field::OutputsTotal,
            "internal_in_total" => Field::InternalInTotal,
            "external_out_total" => Field::ExternalOutTotal,
            "change_total" => Field::ChangeTotal,
            "fee" => Field::Fee,
            "fee_percent" => Field::FeePercent,
            "input_count" => Field::InputCount,
            "output_count" => Field::OutputCount,
            "external_out_count" => Field::ExternalOutCount,
            "change_count" => Field::ChangeCount,
            "tx_version" => Field::TxVersion,
            "locktime" => Field::Locktime,
            _ => return None,
        })
    }
}

/// Read-only aggregate snapshot exposed to a signing program.
///
/// Built once per signing operation from the transaction analysis. All fields
/// are trustworthy only after the transaction's account-coordinate script checks
/// have been verified (see the signing handler).
#[derive(Debug, Clone, Copy)]
pub struct PolicyContext {
    pub inputs_total: i64,
    pub outputs_total: i64,
    pub internal_in_total: i64,
    pub external_out_total: i64,
    pub change_total: i64,
    pub fee: i64,
    pub fee_percent: i64,
    pub input_count: i64,
    pub output_count: i64,
    pub external_out_count: i64,
    pub change_count: i64,
    pub tx_version: i64,
    pub locktime: i64,
}

impl PolicyContext {
    /// Read a field's value. This is the only way a program observes the
    /// transaction.
    pub fn get(&self, field: Field) -> Value {
        match field {
            Field::InputsTotal => Value::Int(self.inputs_total),
            Field::OutputsTotal => Value::Int(self.outputs_total),
            Field::InternalInTotal => Value::Int(self.internal_in_total),
            Field::ExternalOutTotal => Value::Int(self.external_out_total),
            Field::ChangeTotal => Value::Int(self.change_total),
            Field::Fee => Value::Int(self.fee),
            Field::FeePercent => Value::Int(self.fee_percent),
            Field::InputCount => Value::Int(self.input_count),
            Field::OutputCount => Value::Int(self.output_count),
            Field::ExternalOutCount => Value::Int(self.external_out_count),
            Field::ChangeCount => Value::Int(self.change_count),
            Field::TxVersion => Value::Int(self.tx_version),
            Field::Locktime => Value::Int(self.locktime),
        }
    }
}
