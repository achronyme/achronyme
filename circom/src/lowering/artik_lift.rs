//! Lift a circom function body into Artik witness bytecode.
//!
//! This is the Fase 2 replacement for the E212 "cannot be
//! circuit-inlined" diagnostic at [`expressions::calls`]: instead of
//! rejecting every function call with runtime-signal arguments and a
//! non-trivial body, we attempt to compile the body to Artik bytecode
//! and return a [`CircuitNode::WitnessCall`] to the caller.
//!
//! ## Supported surface (v1)
//!
//! The lift is intentionally minimal in this release — the goal is to
//! close the simplest E212 cases cleanly, with the complex ones (for
//! loops over signals, if/else, nested calls, array indexing) landing
//! in follow-up commits. Today:
//!
//! - **Statements**: `var name [= expr];`, assignments to a previously
//!   declared local `name = expr;`, and `return expr;`.
//! - **Expressions**: `Ident` (parameter → signal, or local var →
//!   register), decimal / hex `Number`, and `BinOp` of `Add`, `Sub`,
//!   `Mul`, `Div` over field-typed operands.
//!
//! Anything else returns `None`, and the caller falls back to E212.
//! Failures are silent (no diagnostic) to preserve the existing E212
//! contract: until the lift covers the full surface, the user's error
//! budget is unchanged.
//!
//! ## Non-goals
//!
//! - Soundness: the lift emits witness-hint-style outputs; the caller
//!   is responsible for pairing them with `===` downstream constraints
//!   if they want binding (same rule as circom's `<--`).
//! - Cross-backend: Artik bytecode is family-tagged `BnLike256` today.
//!   Multi-family support lands when the lowering pipeline itself is
//!   generic over `FieldBackend` in a later release.
//! - Loop / branch unrolling: these need the Artik executor's
//!   control-flow primitives (`Jump`, `JumpIf`) which are wired but
//!   not yet driven by lifted AST.

use std::collections::HashMap;

use diagnostics::Span;
use witness::{FieldFamily, ProgramBuilder, Reg};

use crate::ast::{BinOp, Expr, Stmt};
use crate::lowering::context::LoweringContext;

/// Result of a successful lift: the serialized Artik program + the
/// names of the witness slots the caller should bind to. The `outputs`
/// list always has length 1 for v1 (single `return` value).
pub struct LiftedWitnessCall {
    pub program_bytes: Vec<u8>,
    pub outputs: Vec<String>,
}

/// Attempt to compile `body` — the statements of a circom function —
/// into an Artik program. Parameters are provided as signal ids in
/// the order they appear in the function's `params` list; the caller
/// will bind each `arg` expression to the corresponding signal slot
/// at prove time.
///
/// Returns `None` for unsupported forms. The caller should fall back
/// to E212 in that case.
pub fn lift_function_to_artik(
    function_name: &str,
    params: &[String],
    body: &[Stmt],
    ctx: &mut LoweringContext<'_>,
    span: &Span,
) -> Option<LiftedWitnessCall> {
    let mut b = ProgramBuilder::new(FieldFamily::BnLike256);

    // Each parameter gets its own signal; we stash the register that
    // holds the signal's loaded value so the body can refer to it by
    // parameter name.
    let mut locals: HashMap<String, Reg> = HashMap::new();
    for name in params {
        let sig = b.alloc_signal();
        let reg = b.read_signal(sig);
        locals.insert(name.clone(), reg);
    }

    // The single output slot receives whatever the function returns.
    let out_slot = b.alloc_witness_slot();

    for stmt in body {
        match stmt {
            Stmt::VarDecl { names, init, .. } => {
                // Only single-name vars are supported; `var (a, b) = ...`
                // (tuple destructuring) is out of scope for v1.
                if names.len() != 1 {
                    return None;
                }
                let name = &names[0];
                // Uninitialized `var x;` declares the name without a
                // backing register — the body must assign to it later
                // via a Substitution. Defer allocation until that
                // assignment runs.
                let Some(expr) = init else {
                    continue;
                };
                let r = lift_expr(expr, &mut b, &locals)?;
                locals.insert(name.clone(), r);
            }
            Stmt::Substitution { target, value, .. } => {
                // Accept simple `ident = expr` assignments to a
                // previously declared local.
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                let r = lift_expr(value, &mut b, &locals)?;
                locals.insert(name.clone(), r);
            }
            Stmt::Return { value, .. } => {
                let r = lift_expr(value, &mut b, &locals)?;
                b.write_witness(out_slot, r);
                b.ret();
                break;
            }
            // Control flow, arrays, and nested calls are deferred.
            _ => return None,
        }
    }

    let program = b.finish().ok()?;
    let program_bytes = witness::bytecode::encode(&program);

    // Allocate a fresh, uniquely-named binding so multiple calls to
    // the same function in the same template don't collide.
    let anon_id = ctx.next_anon_id();
    let _ = span; // preserved for future diagnostic plumbing
    let out_name = format!("__artik_{function_name}_{anon_id}_out");

    Some(LiftedWitnessCall {
        program_bytes,
        outputs: vec![out_name],
    })
}

/// Lift an expression into Artik register assignments. Returns the
/// register that holds the final value, or `None` for unsupported
/// forms.
fn lift_expr(expr: &Expr, b: &mut ProgramBuilder, locals: &HashMap<String, Reg>) -> Option<Reg> {
    match expr {
        Expr::Ident { name, .. } => locals.get(name).copied(),
        Expr::Number { value, .. } => lift_const(b, value, 10),
        Expr::HexNumber { value, .. } => {
            // Strip a leading "0x" if present; the parser retains it.
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            lift_const(b, trimmed, 16)
        }
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = lift_expr(lhs, b, locals)?;
            let c = lift_expr(rhs, b, locals)?;
            match op {
                BinOp::Add => Some(b.fadd(a, c)),
                BinOp::Sub => Some(b.fsub(a, c)),
                BinOp::Mul => Some(b.fmul(a, c)),
                BinOp::Div => Some(b.fdiv(a, c)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Emit `PushConst` for a numeric literal. The parser hands us the
/// token text; we parse it as a non-negative integer and intern it
/// as little-endian bytes.
fn lift_const(b: &mut ProgramBuilder, text: &str, radix: u32) -> Option<Reg> {
    // The arbitrary-precision case lives in a BigInt pathway that the
    // current minimum viable lift does not need: circom witness
    // functions most often do small arithmetic on signal values, and
    // the constants they fold in are small enough to fit in a u128.
    // Anything larger than u128 can be added when a real circomlib
    // function requires it.
    let v = u128::from_str_radix(text, radix).ok()?;

    let mut bytes: Vec<u8> = v.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) && bytes.len() > 1 {
        bytes.pop();
    }

    let cid = b.intern_const(bytes);
    Some(b.push_const(cid))
}
