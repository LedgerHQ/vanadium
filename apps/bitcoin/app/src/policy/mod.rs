//! Signing-policy evaluation.
//!
//! A *signing program* is a tiny script whose SHA-256 is committed in an xpub used
//! in a wallet policy. When a transaction is signed with such a key, the device
//! retrieves the program from the PSBT, evaluates it against a [`PolicyContext`]
//! built from the transaction, and uses the resulting [`SigningDecision`] to decide
//! whether to sign — and whether to do so without user confirmation.
//!
//! The engine is abstracted behind the [`PolicyEngine`] trait so alternative
//! languages can be plugged in without changing the call site.

use common::{
    errors::Error,
    fastpsbt,
    psbt::signing_policy::{PsbtSigningPolicyGlobalRead, SigningPolicyEntry},
};

pub mod context;
pub mod engine;

pub use context::PolicyContext;

/// Outcome of evaluating a signing program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningDecision {
    /// The program called `fail()`: refuse to sign with the bound key.
    Deny,
    /// The program fell through without calling an action: sign, but require the
    /// standard user-confirmation flow.
    ApproveWithUserConfirmation,
    /// The program called `approve()`: sign without user confirmation.
    ///
    /// Only honored when every signing key authorizes silent signing.
    ApproveSilently,
}

/// Error type for engine compilation / execution. Engine adapters convert their
/// own errors into this enum; the caller surfaces it as
/// [`Error::PolicyExecutionFailed`], i.e. it always fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The program source exceeded a configured limit (size, depth, …).
    ProgramTooLarge,
    /// The program could not be parsed / compiled.
    CompilationFailed,
    /// Execution hit a runtime error (type mismatch, overflow, divide-by-zero).
    ExecutionFailed,
}

/// Engine-agnostic abstraction over a language backend used for signing programs.
///
/// A single implementation handles a fixed `(ENGINE_ID, ENGINE_VERSION)` pair.
/// Supporting another version of the same language requires a separate engine
/// type and an explicit dispatcher entry.
pub trait PolicyEngine {
    const ENGINE_ID: u8;
    const ENGINE_VERSION: u8;

    /// Compiled form of a program. Implementations should reject programs that
    /// exceed configured size or complexity limits during [`compile`].
    type Compiled;

    fn compile(source: &[u8]) -> Result<Self::Compiled, PolicyError>;

    /// Evaluate a compiled program against a transaction context.
    fn evaluate(
        program: &Self::Compiled,
        ctx: &PolicyContext,
    ) -> Result<SigningDecision, PolicyError>;
}

fn evaluate_with<E: PolicyEngine>(
    entry: &SigningPolicyEntry<'_>,
    ctx: &PolicyContext,
) -> Result<SigningDecision, Error> {
    let compiled = validate_with::<E>(entry)?;
    E::evaluate(&compiled, ctx).map_err(|_| Error::PolicyExecutionFailed)
}

fn validate_with<E: PolicyEngine>(entry: &SigningPolicyEntry<'_>) -> Result<E::Compiled, Error> {
    if entry.engine_version != E::ENGINE_VERSION {
        return Err(Error::UnsupportedPolicyEngine);
    }
    E::compile(entry.script).map_err(|_| Error::PolicyExecutionFailed)
}

/// Validate that a signing program uses a supported engine/version and compiles.
pub fn validate_policy(entry: &SigningPolicyEntry<'_>) -> Result<(), Error> {
    use engine::program::ProgramEngine;

    match entry.engine_id {
        ProgramEngine::ENGINE_ID => validate_with::<ProgramEngine>(entry).map(drop),
        _ => Err(Error::UnsupportedPolicyEngine),
    }
}

/// Dispatch by `engine_id` and evaluate the program described by `entry`.
fn dispatch_evaluate(
    entry: &SigningPolicyEntry<'_>,
    ctx: &PolicyContext,
) -> Result<SigningDecision, Error> {
    use engine::program::ProgramEngine;

    match entry.engine_id {
        ProgramEngine::ENGINE_ID => evaluate_with::<ProgramEngine>(entry, ctx),
        _ => Err(Error::UnsupportedPolicyEngine),
    }
}

/// Evaluate the signing program identified by `hash` against `ctx`.
pub fn evaluate_policy(
    psbt: &fastpsbt::Psbt,
    ctx: &PolicyContext,
    hash: &[u8; 32],
) -> Result<SigningDecision, Error> {
    let entry = psbt
        .get_signing_policy(hash)
        .map_err(|_| Error::InvalidSigningPolicy)?
        .ok_or(Error::SigningPolicyMissing)?;
    dispatch_evaluate(&entry, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::psbt::signing_policy::ENGINE_ID_PROGRAM;

    fn ctx() -> PolicyContext {
        PolicyContext {
            inputs_total: 1_000,
            outputs_total: 900,
            internal_in_total: 1_000,
            external_out_total: 900,
            change_total: 0,
            fee: 100,
            fee_percent: 10,
            input_count: 1,
            output_count: 1,
            external_out_count: 1,
            change_count: 0,
            tx_version: 2,
            locktime: 0,
        }
    }

    fn entry(engine_id: u8, engine_version: u8, script: &[u8]) -> SigningPolicyEntry<'_> {
        SigningPolicyEntry {
            hash: [0; 32],
            engine_id,
            engine_version,
            script,
        }
    }

    #[test]
    fn dispatch_rejects_unknown_engine() {
        assert_eq!(
            dispatch_evaluate(&entry(0xff, 0, b"approve();"), &ctx()),
            Err(Error::UnsupportedPolicyEngine)
        );
    }

    #[test]
    fn dispatch_rejects_unsupported_version() {
        assert_eq!(
            dispatch_evaluate(&entry(ENGINE_ID_PROGRAM, 1, b"approve();"), &ctx()),
            Err(Error::UnsupportedPolicyEngine)
        );
    }

    #[test]
    fn dispatch_maps_compilation_failure() {
        assert_eq!(
            dispatch_evaluate(&entry(ENGINE_ID_PROGRAM, 0, b"if { fail(); }"), &ctx()),
            Err(Error::PolicyExecutionFailed)
        );
    }

    #[test]
    fn dispatch_maps_execution_failure() {
        let script = b"if context.fee / context.locktime > 0 { fail(); }";
        assert_eq!(
            dispatch_evaluate(&entry(ENGINE_ID_PROGRAM, 0, script), &ctx()),
            Err(Error::PolicyExecutionFailed)
        );
    }

    #[test]
    fn registration_validation_compiles_without_evaluating() {
        assert_eq!(
            validate_policy(&entry(ENGINE_ID_PROGRAM, 0, b"approve();")),
            Ok(())
        );
        assert_eq!(
            validate_policy(&entry(ENGINE_ID_PROGRAM, 0, b"if { fail(); }")),
            Err(Error::PolicyExecutionFailed)
        );
    }
}
