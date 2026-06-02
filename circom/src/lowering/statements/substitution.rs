//! Substitution lowering: signal assignments, component wiring, tuple destructuring.
//!
//! Handles all forms of `target op value` statements:
//! - `<==` (constraint assign) → Let + AssertEq
//! - `<--` (signal assign) → WitnessHint
//! - `=` (variable assign) → Let (SSA shadowing)
//! - `==>`, `-->` (reverse operators) → desugared to `<==`, `<--`
//! - Tuple destructuring and anonymous component multi-output

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir_forge::types::{CircuitBinOp, CircuitExpr, CircuitNode, FieldConst};

use crate::ast::{self, AnonSignalArg, AssignOp, CompoundOp, Expr};

use super::super::components::{
    inline_component_body, inline_component_body_with_arrays, register_component_locals,
};
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::signals::collect_signal_names;
use super::super::utils::{extract_ident_name, BigVal, EvalValue};
use super::targets::{
    extract_assign_target_ctx, extract_target_name, linearize_multi_index,
    try_resolve_component_array_target, AssignTarget,
};
use super::wiring::{extract_component_wiring_with_env, maybe_trigger_inline, PendingComponent};

mod component_calls;
mod local_arrays;
mod ops;
mod tuples;
mod var_assign;

pub(super) use self::component_calls::extract_component_call;
#[allow(unused_imports)]
pub(super) use self::component_calls::ComponentCall;
pub(super) use self::local_arrays::resolve_local_array_element_name;
pub(super) use self::ops::compound_to_binop;

use self::tuples::lower_tuple_substitution;
use self::var_assign::lower_var_assign;

/// Lower a substitution statement (`target op value`).
///
/// Handles both simple identifiers and dot access targets (component
/// signal wirings like `c.a <== expr`).
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_substitution<'a>(
    target: &Expr,
    op: AssignOp,
    value: &Expr,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Desugar reverse operators: `expr ==> target` → `target <== expr`
    //                            `expr --> target` → `target <-- expr`
    let (target, op, value) = match op {
        AssignOp::RConstraintAssign => (value, AssignOp::ConstraintAssign, target),
        AssignOp::RSignalAssign => (value, AssignOp::SignalAssign, target),
        other => (target, other, value),
    };

    let sr = Some(SpanRange::from_span(span));

    // ── Tuple destructuring ────────────────────────────────────────
    if let Expr::Tuple {
        elements: targets, ..
    } = target
    {
        return lower_tuple_substitution(targets, op, value, span, &sr, env, nodes, ctx, pending);
    }

    match op {
        // `target <== expr` → Let + AssertEq (or LetIndexed + AssertEq for arrays)
        AssignOp::ConstraintAssign => {
            let assign_target = extract_assign_target_ctx(target, ctx, env).ok_or_else(|| {
                LoweringError::new(
                    "constraint assignment target must be an identifier, \
                     component signal, or array element",
                    span,
                )
            })?;
            let lowered = lower_expr(value, env, ctx)?;
            // Snapshot the lowered value for constant tracking before it moves
            let lowered_ref = lowered.clone();
            match assign_target {
                // `<==` only needs a Let (or LetIndexed). The expression's Mul
                // instructions generate R1CS constraints, and the Let binds the
                // result in the env. No separate AssertEq is needed because:
                // - For Mul: the R1CS constraint comes from the Mul instruction
                // - For Add/Sub: the signal is an LC alias, no wire to constrain
                // - For outputs: the Let handler emits AssertEq(pub_wire, value)
                // Emitting AssertEq here would re-emit the entire expression tree
                // a second time, creating duplicate Mul constraints.
                AssignTarget::Scalar(name) => {
                    // Track constant signal for intra-template propagation
                    if let Some(fc) = super::super::const_fold::try_fold_const(&lowered) {
                        env.known_constants.insert(name.clone(), fc);
                    }
                    nodes.push(CircuitNode::Let {
                        name,
                        value: lowered,
                        span: sr,
                    });
                }
                AssignTarget::Indexed { array, index } => {
                    let idx_expr = lower_expr(&index, env, ctx)?;
                    // Track constant indexed signal for intra-template propagation
                    if let (Some(idx_fc), Some(val_fc)) = (
                        super::super::const_fold::try_fold_const(&idx_expr),
                        super::super::const_fold::try_fold_const(&lowered),
                    ) {
                        if let Some(idx) = idx_fc.to_u64() {
                            env.known_constants.insert(format!("{array}_{idx}"), val_fc);
                            propagate_indexed_const_to_pending(
                                target, idx, val_fc, env, ctx, pending,
                            );
                        }
                    }
                    nodes.push(CircuitNode::LetIndexed {
                        array,
                        index: idx_expr,
                        value: lowered,
                        span: sr,
                    });
                }
                AssignTarget::MultiIndexed { array, indices } => {
                    let idx_expr = linearize_multi_index(&array, &indices, env, ctx)?;
                    nodes.push(CircuitNode::LetIndexed {
                        array,
                        index: idx_expr,
                        value: lowered,
                        span: sr,
                    });
                }
            }
            maybe_trigger_inline(target, nodes, ctx, pending, span, env, Some(&lowered_ref))?;
        }

        // `target <-- expr` → WitnessHint or WitnessHintIndexed
        AssignOp::SignalAssign => {
            let assign_target = extract_assign_target_ctx(target, ctx, env).ok_or_else(|| {
                LoweringError::new(
                    "signal assignment target must be an identifier, \
                     component signal, or array element",
                    span,
                )
            })?;
            let lowered = lower_expr(value, env, ctx)?;
            let lowered_ref = lowered.clone();
            match assign_target {
                AssignTarget::Scalar(name) => {
                    // Track constant witness for intra-template propagation
                    if let Some(fc) = super::super::const_fold::try_fold_const(&lowered) {
                        env.known_constants.insert(name.clone(), fc);
                    }
                    nodes.push(CircuitNode::WitnessHint {
                        name,
                        hint: lowered,
                        span: sr,
                    });
                }
                AssignTarget::Indexed { array, index } => {
                    let idx_expr = lower_expr(&index, env, ctx)?;
                    // Track constant indexed witness for intra-template propagation
                    if let (Some(idx_fc), Some(val_fc)) = (
                        super::super::const_fold::try_fold_const(&idx_expr),
                        super::super::const_fold::try_fold_const(&lowered),
                    ) {
                        if let Some(idx) = idx_fc.to_u64() {
                            env.known_constants.insert(format!("{array}_{idx}"), val_fc);
                            propagate_indexed_const_to_pending(
                                target, idx, val_fc, env, ctx, pending,
                            );
                        }
                    }
                    nodes.push(CircuitNode::WitnessHintIndexed {
                        array,
                        index: idx_expr,
                        hint: lowered,
                        span: sr,
                    });
                }
                AssignTarget::MultiIndexed { array, indices } => {
                    let idx_expr = linearize_multi_index(&array, &indices, env, ctx)?;
                    nodes.push(CircuitNode::WitnessHintIndexed {
                        array,
                        index: idx_expr,
                        hint: lowered,
                        span: sr,
                    });
                }
            }
            maybe_trigger_inline(target, nodes, ctx, pending, span, env, Some(&lowered_ref))?;
        }

        // RConstraintAssign (==>) and RSignalAssign (-->) are desugared
        // to ConstraintAssign (<==) and SignalAssign (<--) above.
        AssignOp::RConstraintAssign | AssignOp::RSignalAssign => {
            unreachable!("reverse operators desugared at function entry")
        }

        // `target = expr` → variable reassignment, component array instantiation, or SSA shadowing
        AssignOp::Assign => {
            lower_var_assign(target, value, span, &sr, env, nodes, ctx, pending)?;
        }
    }

    Ok(())
}

/// If `target` resolves to a pending component's indexed signal input
/// and the index + value are compile-time constants, record
/// `(signal_base, idx, fc)` directly in the component's `const_wired`
/// map so the sub-template body sees the constant during inlining.
///
/// This is the indexed counterpart of the scalar path `mark_wired`
/// already covers. Without this, the only way for a sub-template to
/// see indexed constants would be a post-hoc scan of the parent's
/// `nodes` accumulator, which is quadratic in the parent template's
/// size when components are long-lived (e.g. SHA-256's per-block
/// `sha256compression[i]`).
fn propagate_indexed_const_to_pending(
    target: &Expr,
    idx: u64,
    val_fc: FieldConst,
    env: &LoweringEnv,
    ctx: &LoweringContext<'_>,
    pending: &mut HashMap<String, PendingComponent<'_>>,
) {
    if let Some((comp_name, signal_base)) = extract_component_wiring_with_env(target, env, ctx) {
        if let Some(comp) = pending.get_mut(&comp_name) {
            comp.record_indexed_const(&signal_base, idx, val_fc);
        }
    }
}
