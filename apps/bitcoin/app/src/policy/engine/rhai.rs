//! Rhai-backed implementation of [`PolicyEngine`].
//!
//! The script is compiled with a sandboxed [`rhai::Engine`] (no modules, no I/O,
//! no floats, conservative resource limits) and evaluated against a Rhai-friendly
//! materialization of [`PolicyContext`]. The script's final expression is mapped
//! to a [`SigningDecision`] via three injected constants (`DENY`, `APPROVE`,
//! `APPROVE_SILENT`).
//!
//! Engine version bumps invalidate every previously-registered policy under
//! engine id [`ENGINE_ID_RHAI`].

use rhai::{Array, Blob, Dynamic, Engine, Map, Scope, AST, INT};

use crate::policy::{PolicyContext, PolicyEngine, PolicyError, SigningDecision};

/// Maximum length of a Rhai script source, in bytes.
pub const MAX_SCRIPT_BYTES: usize = 8 * 1024;

/// Maximum number of Rhai operations a script may execute.
pub const MAX_OPERATIONS: u64 = 32_000;

/// Maximum nesting depth of expressions / statements.
pub const MAX_EXPR_DEPTH: usize = 16;

/// Maximum function call nesting.
pub const MAX_CALL_LEVELS: usize = 8;

/// Maximum size of a Rhai string (bytes).
pub const MAX_STRING_SIZE: usize = 8 * 1024;

/// Maximum size of a Rhai array.
pub const MAX_ARRAY_SIZE: usize = 512;

/// Maximum size of a Rhai object map.
pub const MAX_MAP_SIZE: usize = 256;

/// Sentinel values mapping a script's final expression to a [`SigningDecision`].
const RET_DENY: INT = 0;
const RET_APPROVE: INT = 1;
const RET_APPROVE_SILENT: INT = 2;

pub struct RhaiEngine;

impl PolicyEngine for RhaiEngine {
    const ENGINE_ID: u8 = 0x00;
    const ENGINE_VERSION: u8 = 0x00;

    type CompiledScript = CompiledScript;

    fn compile(source: &[u8]) -> Result<Self::CompiledScript, PolicyError> {
        if source.len() > MAX_SCRIPT_BYTES {
            return Err(PolicyError::ScriptTooLarge);
        }
        let src = core::str::from_utf8(source).map_err(|_| PolicyError::CompilationFailed)?;

        let engine = make_engine();
        let ast = engine
            .compile(src)
            .map_err(|_| PolicyError::CompilationFailed)?;
        Ok(CompiledScript { ast })
    }

    fn evaluate(
        script: &Self::CompiledScript,
        ctx: &PolicyContext<'_>,
    ) -> Result<SigningDecision, PolicyError> {
        let engine = make_engine();

        let mut scope = Scope::new();
        scope.push_constant("DENY", RET_DENY);
        scope.push_constant("APPROVE", RET_APPROVE);
        scope.push_constant("APPROVE_SILENT", RET_APPROVE_SILENT);
        scope.push_constant("psbt", build_psbt_map(ctx));

        let result: Dynamic = engine
            .eval_ast_with_scope(&mut scope, &script.ast)
            .map_err(|_| PolicyError::ExecutionFailed)?;

        if let Some(b) = result.clone().try_cast::<bool>() {
            return Ok(if b {
                SigningDecision::ApproveWithUserConfirmation
            } else {
                SigningDecision::Deny
            });
        }

        let v: INT = result
            .try_cast::<INT>()
            .ok_or(PolicyError::InvalidReturnValue)?;
        match v {
            RET_DENY => Ok(SigningDecision::Deny),
            RET_APPROVE => Ok(SigningDecision::ApproveWithUserConfirmation),
            RET_APPROVE_SILENT => Ok(SigningDecision::ApproveSilently),
            _ => Err(PolicyError::InvalidReturnValue),
        }
    }
}

/// Pre-compiled Rhai script ready for evaluation.
pub struct CompiledScript {
    ast: AST,
}

fn make_engine() -> Engine {
    let mut engine = Engine::new_raw();
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_EXPR_DEPTH);
    engine.set_max_call_levels(MAX_CALL_LEVELS);
    engine.set_max_string_size(MAX_STRING_SIZE);
    engine.set_max_array_size(MAX_ARRAY_SIZE);
    engine.set_max_map_size(MAX_MAP_SIZE);
    engine.set_max_modules(0);
    // Disable the `eval` built-in to prevent runtime script construction.
    engine.disable_symbol("eval");
    engine
}

fn build_psbt_map(ctx: &PolicyContext<'_>) -> Map {
    let mut map = Map::new();
    map.insert("tx_version".into(), Dynamic::from(ctx.tx_version() as INT));
    map.insert(
        "psbt_version".into(),
        Dynamic::from(ctx.psbt_version() as INT),
    );
    map.insert(
        "inputs_total_sats".into(),
        Dynamic::from(ctx.inputs_total_value() as INT),
    );
    map.insert(
        "outputs_total_sats".into(),
        Dynamic::from(ctx.outputs_total_value() as INT),
    );
    map.insert(
        "input_count".into(),
        Dynamic::from(ctx.input_count() as INT),
    );
    map.insert(
        "output_count".into(),
        Dynamic::from(ctx.output_count() as INT),
    );

    let mut inputs = Array::new();
    for i in 0..ctx.input_count() {
        let input = ctx.input(i).expect("index within range");
        let mut m = Map::new();
        m.insert("index".into(), Dynamic::from(i as INT));
        if let Some(v) = input.value_sats() {
            m.insert("value_sats".into(), Dynamic::from(v as INT));
        }
        if let Some(seq) = input.sequence() {
            m.insert("sequence".into(), Dynamic::from(seq as INT));
        }
        if let Some(vout) = input.prev_vout() {
            m.insert("prev_vout".into(), Dynamic::from(vout as INT));
        }
        if let Some(txid) = input.prev_txid() {
            m.insert("prev_txid".into(), Dynamic::from(Blob::from(txid.to_vec())));
        }
        if let Some(sht) = input.sighash_type() {
            m.insert("sighash_type".into(), Dynamic::from(sht as INT));
        }
        if let Some(spk) = input.script_pubkey() {
            m.insert("script_pubkey".into(), Dynamic::from(Blob::from(spk)));
        }
        if let Some(rs) = input.redeem_script() {
            m.insert(
                "redeem_script".into(),
                Dynamic::from(Blob::from(rs.to_vec())),
            );
        }
        if let Some(ws) = input.witness_script() {
            m.insert(
                "witness_script".into(),
                Dynamic::from(Blob::from(ws.to_vec())),
            );
        }
        inputs.push(Dynamic::from(m));
    }
    map.insert("inputs".into(), Dynamic::from(inputs));

    let mut outputs = Array::new();
    for i in 0..ctx.output_count() {
        let output = ctx.output(i).expect("index within range");
        let mut m = Map::new();
        m.insert("index".into(), Dynamic::from(i as INT));
        if let Some(v) = output.value_sats() {
            m.insert("value_sats".into(), Dynamic::from(v as INT));
        }
        if let Some(spk) = output.script_pubkey() {
            m.insert(
                "script_pubkey".into(),
                Dynamic::from(Blob::from(spk.to_vec())),
            );
        }
        outputs.push(Dynamic::from(m));
    }
    map.insert("outputs".into(), Dynamic::from(outputs));

    map
}

#[cfg(test)]
mod tests {
    // Build a tiny fake PSBT context using empty inputs/outputs for testing the
    // return-value mapping.
    use super::*;

    fn eval(source: &str) -> Result<SigningDecision, PolicyError> {
        // We can't easily build a PolicyContext without a real PSBT, so we evaluate
        // scripts that don't depend on `psbt`. Stub it with an empty Map via a
        // synthesised Scope.
        let engine = make_engine();
        let ast = engine.compile(source).map_err(|_| PolicyError::CompilationFailed)?;

        let mut scope = Scope::new();
        scope.push_constant("DENY", RET_DENY);
        scope.push_constant("APPROVE", RET_APPROVE);
        scope.push_constant("APPROVE_SILENT", RET_APPROVE_SILENT);
        scope.push_constant("psbt", Map::new());

        let result: Dynamic = engine
            .eval_ast_with_scope(&mut scope, &ast)
            .map_err(|_| PolicyError::ExecutionFailed)?;

        if let Some(b) = result.clone().try_cast::<bool>() {
            return Ok(if b {
                SigningDecision::ApproveWithUserConfirmation
            } else {
                SigningDecision::Deny
            });
        }
        let v: INT = result
            .try_cast::<INT>()
            .ok_or(PolicyError::InvalidReturnValue)?;
        match v {
            RET_DENY => Ok(SigningDecision::Deny),
            RET_APPROVE => Ok(SigningDecision::ApproveWithUserConfirmation),
            RET_APPROVE_SILENT => Ok(SigningDecision::ApproveSilently),
            _ => Err(PolicyError::InvalidReturnValue),
        }
    }

    #[test]
    fn returns_approve() {
        assert_eq!(eval("APPROVE"), Ok(SigningDecision::ApproveWithUserConfirmation));
    }

    #[test]
    fn returns_deny() {
        assert_eq!(eval("DENY"), Ok(SigningDecision::Deny));
    }

    #[test]
    fn returns_approve_silent() {
        assert_eq!(eval("APPROVE_SILENT"), Ok(SigningDecision::ApproveSilently));
    }

    #[test]
    fn rejects_bad_return_value() {
        assert_eq!(eval("99"), Err(PolicyError::InvalidReturnValue));
        assert_eq!(eval("\"hello\""), Err(PolicyError::InvalidReturnValue));
    }

    #[test]
    fn rejects_too_large_script() {
        let huge = alloc::vec![b' '; MAX_SCRIPT_BYTES + 1];
        assert!(matches!(
            RhaiEngine::compile(&huge),
            Err(PolicyError::ScriptTooLarge)
        ));
    }

    #[test]
    fn rejects_runaway_loop() {
        let source = "let i = 0; loop { i += 1; }";
        assert_eq!(eval(source), Err(PolicyError::ExecutionFailed));
    }

    #[test]
    fn evaluates_expression() {
        let source = "if 2 + 2 == 4 { APPROVE } else { DENY }";
        assert_eq!(eval(source), Ok(SigningDecision::ApproveWithUserConfirmation));
    }

    #[test]
    fn bool_true_maps_to_approve_with_confirmation() {
        assert_eq!(eval("true"), Ok(SigningDecision::ApproveWithUserConfirmation));
    }

    #[test]
    fn bool_false_maps_to_deny() {
        assert_eq!(eval("false"), Ok(SigningDecision::Deny));
    }
}
