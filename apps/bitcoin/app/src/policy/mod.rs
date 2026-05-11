//! Signing-policy evaluation.
//!
//! A signing policy is a script, written in some embedded engine (currently
//! Rhai), whose hash is committed in the chaincode of a resident-key xpub. When
//! a transaction is signed with such an xpub, the device retrieves the
//! corresponding script from the PSBT, executes it against the transaction, and
//! uses its [`SigningDecision`] to decide whether to sign — and whether to do
//! so without user confirmation.
//!
//! The engine is abstracted behind the [`PolicyEngine`] trait so that
//! alternatives to Rhai can be plugged in without changes to the call site.

use alloc::vec::Vec;

use common::{
    errors::Error,
    fastpsbt,
    psbt::signing_policy::{PsbtSigningPolicyGlobalRead, SigningPolicyEntry},
};

pub mod context;
pub mod engine;

pub use context::PolicyContext;

/// Outcome of evaluating a signing-policy script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningDecision {
    /// Refuse to sign with the bound key.
    Deny,
    /// Allow signing, but require the standard user confirmation flow.
    ApproveWithUserConfirmation,
    /// Allow signing without requiring user confirmation.
    ///
    /// Only honored when every input being signed authorizes silent signing.
    ApproveSilently,
}

/// Error type for engine compilation / execution. Engine adapters convert their
/// own errors into this enum; the caller surfaces it as [`Error::PolicyExecutionFailed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The script source exceeded a configured limit (size, parse depth, …).
    ScriptTooLarge,
    /// The script could not be parsed / compiled.
    CompilationFailed,
    /// Execution panicked, timed out, or exceeded an operation/memory limit.
    ExecutionFailed,
    /// The script returned a value that is not a recognized [`SigningDecision`].
    InvalidReturnValue,
}

/// Engine-agnostic abstraction over a scripting backend used for signing policies.
///
/// Implementations are stateless registries: a single engine implementation
/// handles a fixed `(ENGINE_ID, ENGINE_VERSION)` pair.
pub trait PolicyEngine {
    const ENGINE_ID: u8;
    const ENGINE_VERSION: u8;

    /// Compile the script source into a runnable form. Implementations should
    /// reject scripts that exceed configured size or complexity limits here.
    type CompiledScript;

    fn compile(source: &[u8]) -> Result<Self::CompiledScript, PolicyError>;

    /// Evaluate a compiled script against a transaction context.
    fn evaluate(
        script: &Self::CompiledScript,
        ctx: &PolicyContext<'_>,
    ) -> Result<SigningDecision, PolicyError>;
}

/// Dispatch by `engine_id` and evaluate the policy described by `entry`.
fn dispatch_evaluate(
    entry: &SigningPolicyEntry<'_>,
    ctx: &PolicyContext<'_>,
) -> Result<SigningDecision, Error> {
    use engine::rhai::RhaiEngine;
    if entry.engine_id == RhaiEngine::ENGINE_ID {
        if entry.engine_version != RhaiEngine::ENGINE_VERSION {
            return Err(Error::UnsupportedPolicyEngine);
        }
        let compiled =
            RhaiEngine::compile(entry.script).map_err(|_| Error::PolicyExecutionFailed)?;
        return RhaiEngine::evaluate(&compiled, ctx).map_err(|_| Error::PolicyExecutionFailed);
    }
    Err(Error::UnsupportedPolicyEngine)
}

/// Resolve the signing decisions for the given set of policy hashes against the PSBT.
///
/// Returns a vector parallel to `hashes` with one [`SigningDecision`] each. Returns
/// an error if any referenced policy is missing or malformed, or if any engine
/// dispatch fails.
pub fn evaluate_policies(
    psbt: &fastpsbt::Psbt,
    hashes: &[[u8; 32]],
) -> Result<Vec<SigningDecision>, Error> {
    if hashes.is_empty() {
        return Ok(Vec::new());
    }

    // Validate the full set up front to catch duplicate-hash and hash-mismatch errors
    // even when only a subset of policies is queried.
    psbt.get_signing_policies()
        .map_err(|_| Error::InvalidSigningPolicy)?;

    let ctx = PolicyContext::new(psbt);
    let mut decisions = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let entry = psbt
            .get_signing_policy(hash)
            .map_err(|_| Error::InvalidSigningPolicy)?
            .ok_or(Error::SigningPolicyMissing)?;
        decisions.push(dispatch_evaluate(&entry, &ctx)?);
    }
    Ok(decisions)
}
