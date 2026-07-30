//! Signing-policy evaluation.
//!
//! A *signing policy* is a riscv32imac program image whose SHA-256 is committed in
//! the derivation path of the key it encumbers. When a transaction is signed with
//! such a key, the device retrieves the program from the PSBT and evaluates it once
//! per signing attempt, plus once more for deferred checks, and uses the resulting
//! [`SigningDecision`] to decide whether to sign at all — and whether to do so
//! without user confirmation.
//!
//! See `apps/bitcoin/docs/SIGNING_POLICIES.md` for the full specification.

use common::{
    errors::Error,
    psbt::signing_policy::{SigningPolicyEntry, ENGINE_ID_RISCV},
};

pub mod engine;
pub mod host;

pub use host::{PolicyCoords, PolicyHost};

/// The outcome of evaluating a signing policy.
///
/// The variants form an ordered lattice, so verdicts combine with `min`: first over
/// every invocation of one policy, then over every policy the transaction invokes.
/// A single refusal anywhere therefore suppresses every signature, and silent
/// approval requires unanimity. `Ord` is derived to make that fold the obvious
/// operation rather than a hand-written match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningDecision {
    /// Refuse to sign.
    Deny = 0,
    /// Sign, using the standard user-confirmation flow.
    ApproveWithUserConfirmation = 1,
    /// Sign without user confirmation. Honored only when every policy agrees.
    ApproveSilently = 2,
}

impl SigningDecision {
    /// Decode the value a program passes to `EXIT`. Anything else is a fatal
    /// engine error, not a refusal.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(SigningDecision::Deny),
            1 => Some(SigningDecision::ApproveWithUserConfirmation),
            2 => Some(SigningDecision::ApproveSilently),
            _ => None,
        }
    }
}

/// Engine-level failure. Every variant is fatal and fails closed; the caller
/// collapses them all into [`Error::PolicyExecutionFailed`] so that the device does
/// not become an oracle for debugging a program against a live PSBT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The program image is malformed, or declares an inconsistent layout.
    InvalidImage,
    /// The image exceeds a size or budget cap.
    ProgramTooLarge,
    /// A trap: bad instruction, bad memory access, bad ecall, or an out-of-range
    /// decision value.
    ExecutionFailed,
    /// The instruction budget ran out.
    BudgetExhausted,
}

/// A language backend for signing policies, handling one fixed
/// `(ENGINE_ID, ENGINE_VERSION)` pair.
pub trait PolicyEngine {
    const ENGINE_ID: u8;
    const ENGINE_VERSION: u8;

    /// Validate a program without executing it. Used at account registration.
    fn validate(program: &[u8]) -> Result<(), PolicyError>;

    /// Evaluate a program against the transaction, returning the policy's verdict:
    /// the `min` over its per-attempt invocations and its final call.
    fn evaluate(
        program: &[u8],
        host: &mut dyn PolicyHost,
    ) -> Result<SigningDecision, PolicyError>;
}

fn check_version<E: PolicyEngine>(entry: &SigningPolicyEntry<'_>) -> Result<(), Error> {
    if entry.engine_version != E::ENGINE_VERSION {
        return Err(Error::UnsupportedPolicyEngine);
    }
    Ok(())
}

/// Validate that a signing policy uses a supported engine and version, and that its
/// program is well-formed. Never executes it.
pub fn validate_policy(entry: &SigningPolicyEntry<'_>) -> Result<(), Error> {
    use engine::riscv::RiscvEngine;

    match entry.engine_id {
        RiscvEngine::ENGINE_ID => {
            check_version::<RiscvEngine>(entry)?;
            RiscvEngine::validate(entry.program).map_err(|_| Error::PolicyExecutionFailed)
        }
        _ => Err(Error::UnsupportedPolicyEngine),
    }
}

/// Evaluate a signing policy against the transaction described by `host`.
pub fn evaluate_policy(
    entry: &SigningPolicyEntry<'_>,
    host: &mut dyn PolicyHost,
) -> Result<SigningDecision, Error> {
    use engine::riscv::RiscvEngine;

    match entry.engine_id {
        RiscvEngine::ENGINE_ID => {
            check_version::<RiscvEngine>(entry)?;
            RiscvEngine::evaluate(entry.program, host).map_err(|_| Error::PolicyExecutionFailed)
        }
        _ => Err(Error::UnsupportedPolicyEngine),
    }
}

/// Sanity check that the dispatcher's engine id matches the transport constant.
const _: () = assert!(engine::riscv::RiscvEngine::ENGINE_ID == ENGINE_ID_RISCV);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_form_an_ordered_lattice() {
        assert!(SigningDecision::Deny < SigningDecision::ApproveWithUserConfirmation);
        assert!(SigningDecision::ApproveWithUserConfirmation < SigningDecision::ApproveSilently);

        // The fold used to combine verdicts: any refusal wins, and silent approval
        // survives only if nothing weaker is present.
        let all = [
            SigningDecision::ApproveSilently,
            SigningDecision::ApproveWithUserConfirmation,
            SigningDecision::Deny,
        ];
        assert_eq!(all.iter().copied().min(), Some(SigningDecision::Deny));
        assert_eq!(
            [
                SigningDecision::ApproveSilently,
                SigningDecision::ApproveSilently
            ]
            .iter()
            .copied()
            .min(),
            Some(SigningDecision::ApproveSilently)
        );
        assert_eq!(
            [
                SigningDecision::ApproveSilently,
                SigningDecision::ApproveWithUserConfirmation
            ]
            .iter()
            .copied()
            .min(),
            Some(SigningDecision::ApproveWithUserConfirmation)
        );
    }

    #[test]
    fn decision_encoding_roundtrips_and_rejects_junk() {
        for d in [
            SigningDecision::Deny,
            SigningDecision::ApproveWithUserConfirmation,
            SigningDecision::ApproveSilently,
        ] {
            assert_eq!(SigningDecision::from_u32(d as u32), Some(d));
        }
        assert_eq!(SigningDecision::from_u32(3), None);
        assert_eq!(SigningDecision::from_u32(u32::MAX), None);
    }

    #[test]
    fn dispatch_rejects_unknown_engine_and_version() {
        let entry = SigningPolicyEntry {
            hash: [0; 32],
            engine_id: 0xFF,
            engine_version: 0,
            program: b"",
        };
        assert_eq!(validate_policy(&entry), Err(Error::UnsupportedPolicyEngine));

        let entry = SigningPolicyEntry {
            hash: [0; 32],
            engine_id: ENGINE_ID_RISCV,
            engine_version: 1,
            program: b"",
        };
        assert_eq!(validate_policy(&entry), Err(Error::UnsupportedPolicyEngine));
    }

    #[test]
    fn dispatch_maps_a_malformed_image_to_execution_failed() {
        let entry = SigningPolicyEntry {
            hash: [0; 32],
            engine_id: ENGINE_ID_RISCV,
            engine_version: 0,
            program: b"not an image",
        };
        assert_eq!(validate_policy(&entry), Err(Error::PolicyExecutionFailed));
    }
}
