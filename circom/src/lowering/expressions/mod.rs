//! Expression lowering: Circom expressions → ProveIR `CircuitExpr`.
//!
//! Maps the Circom expression tree to ProveIR's circuit expression tree.
//! Key mappings:
//! - Number/HexNumber literals → `CircuitExpr::Const(FieldConst)`
//! - Identifiers → `Var`, `Input`, or `Capture` (resolved by environment)
//! - Arithmetic `+,-,*,/` → `CircuitExpr::BinOp`
//! - Integer division `\`, modulo `%` → `CircuitExpr::IntDiv`, `CircuitExpr::IntMod`
//! - Power `**` → `CircuitExpr::Pow`
//! - Comparisons → `CircuitExpr::Comparison`
//! - Boolean `&&, ||` → `CircuitExpr::BoolOp`
//! - Ternary `? :` → `CircuitExpr::Mux`
//! - Array index → `CircuitExpr::ArrayIndex`
//! - Unary `-`, `!` → `CircuitExpr::UnaryOp`

mod calls;
pub(in crate::lowering) mod indexing;
pub(crate) mod operators;

use ir_forge::types::{CircuitExpr, CircuitUnaryOp, FieldConst};

use crate::ast::{self, Expr};

use super::context::LoweringContext;
use super::env::{LoweringEnv, VarKind};
use super::error::LoweringError;
use super::suggest::find_similar;
use super::utils::{const_eval_u64, extract_ident_name};

use calls::lower_call;
use indexing::{
    eval_index_expr, lower_multi_index, resolve_component_array_expr_full,
    try_resolve_known_array_index,
};
use operators::lower_binop;

/// The default max bits for IntDiv/IntMod. Circom operates over BN254 (~254 bits).
/// BN254 scalar field prime is ~2^253.85, requiring 254 bits for full range.
const DEFAULT_MAX_BITS: u32 = 254;

/// Lower a Circom expression to a ProveIR `CircuitExpr`.
pub fn lower_expr(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<CircuitExpr, LoweringError> {
    match expr {
        // ── Literals ────────────────────────────────────────────────
        Expr::Number { value, span } => {
            if let Ok(n) = value.parse::<u64>() {
                Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
            } else {
                FieldConst::from_decimal_str(value)
                    .map(CircuitExpr::Const)
                    .ok_or_else(|| {
                        LoweringError::new(
                            format!("number literal `{value}` exceeds 256-bit field range"),
                            span,
                        )
                    })
            }
        }

        Expr::HexNumber { value, span } => {
            let hex_str = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            if let Ok(n) = u64::from_str_radix(hex_str, 16) {
                Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
            } else {
                FieldConst::from_hex_str(value)
                    .map(CircuitExpr::Const)
                    .ok_or_else(|| {
                        LoweringError::new(
                            format!("hex literal `{value}` exceeds 256-bit field range"),
                            span,
                        )
                    })
            }
        }

        // ── Identifiers ─────────────────────────────────────────────
        Expr::Ident { name, span } => {
            // Memoization placeholder. When the lowering is inside
            // an iter-0 capture window, the loop variable is emitted
            // as a `LoopVar(token)` placeholder so the captured node
            // slice can be cloned + substituted for each remaining
            // iteration. This branch fires *before* the
            // `known_constants` lookup so the unroll path that drives
            // the placeholder doesn't have to also delete the loop
            // variable from `env.known_constants` to suppress a const
            // fold — keeping the two regimes' state-management
            // symmetric makes the integration in `lower_for_loop`
            // simpler.
            if let Some(token) = ctx.placeholder_token_for(name) {
                return Ok(CircuitExpr::LoopVar(token));
            }
            if let Some(&val) = env.known_constants.get(name.as_str()) {
                return Ok(CircuitExpr::Const(val));
            }
            match env.resolve(name) {
                Some(VarKind::Input) => Ok(CircuitExpr::Input(name.clone())),
                Some(VarKind::Local) => Ok(CircuitExpr::Var(name.clone())),
                Some(VarKind::Capture) => Ok(CircuitExpr::Capture(name.clone())),
                None => {
                    let candidates = env.all_names();
                    let mut err = LoweringError::with_code(
                        format!("undefined variable `{name}` in circuit context"),
                        "E200",
                        span,
                    );
                    if let Some(similar) = find_similar(name, candidates.iter().map(|s| s.as_str()))
                    {
                        err.add_suggestion(
                            diagnostics::SpanRange::from_span(span),
                            similar,
                            "a similar name exists in scope",
                        );
                    }
                    Err(err)
                }
            }
        }

        // ── Binary operations ───────────────────────────────────────
        Expr::BinOp { op, lhs, rhs, span } => {
            let l = lower_expr(lhs, env, ctx)?;
            let r = lower_expr(rhs, env, ctx)?;
            lower_binop(*op, l, r, span)
        }

        // ── Unary operations ────────────────────────────────────────
        Expr::UnaryOp { op, operand, .. } => {
            let inner = lower_expr(operand, env, ctx)?;
            match op {
                ast::UnaryOp::Neg => {
                    let expr = CircuitExpr::UnaryOp {
                        op: CircuitUnaryOp::Neg,
                        operand: Box::new(inner),
                    };
                    Ok(super::const_fold::try_fold_const(&expr)
                        .map(CircuitExpr::Const)
                        .unwrap_or(expr))
                }
                ast::UnaryOp::Not => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Not,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::BitNot => Ok(CircuitExpr::BitNot {
                    operand: Box::new(inner),
                    num_bits: DEFAULT_MAX_BITS,
                }),
            }
        }

        // ── Ternary → Mux ───────────────────────────────────────────
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            // Constant-fold: if the condition is a compile-time constant,
            // select the branch directly (avoids lowering dead branches
            // that may contain invalid array accesses like xL[-1]).
            if let Some(cond_val) = super::utils::const_eval_ctx(condition, ctx, env) {
                return if !cond_val.is_zero() {
                    lower_expr(if_true, env, ctx)
                } else {
                    lower_expr(if_false, env, ctx)
                };
            }
            let cond = lower_expr(condition, env, ctx)?;
            let t = lower_expr(if_true, env, ctx)?;
            let f = lower_expr(if_false, env, ctx)?;
            Ok(CircuitExpr::Mux {
                cond: Box::new(cond),
                if_true: Box::new(t),
                if_false: Box::new(f),
            })
        }

        // ── Array index ─────────────────────────────────────────────
        Expr::Index {
            object,
            index,
            span,
        } => lower_index(object, index, span, env, ctx),

        // ── Function calls ──────────────────────────────────────────
        Expr::Call { callee, args, span } => lower_call(callee, args, env, ctx, span),

        // ── Array literals ──────────────────────────────────────────
        Expr::ArrayLit { span, .. } => Err(LoweringError::new(
            "array literal is not supported as a circuit expression; \
             use signal array declarations instead",
            span,
        )),

        // ── Dot access (component output) ───────────────────────────
        Expr::DotAccess {
            object,
            field,
            span,
        } => {
            let obj_name = if let Some(name) = extract_ident_name(object) {
                name
            } else if let Some(comp) = resolve_component_array_expr_full(object, env, ctx) {
                comp
            } else if matches!(object.as_ref(), Expr::Index { .. }) {
                // Circom-compatible: if a component array index is invalid
                // (e.g., bits[n-2] where n=1 → negative index), treat the
                // access as 0. This matches Circom's behavior where
                // nonexistent component signals have value 0.
                return Ok(CircuitExpr::Const(FieldConst::zero()));
            } else {
                return Err(LoweringError::new(
                    "dot access target must be a simple identifier or indexed component array",
                    span,
                ));
            };
            let mangled = format!("{obj_name}.{field}");
            match env.resolve(&mangled) {
                Some(VarKind::Input) => Ok(CircuitExpr::Input(mangled)),
                Some(VarKind::Local) => Ok(CircuitExpr::Var(mangled)),
                Some(VarKind::Capture) => Ok(CircuitExpr::Capture(mangled)),
                None => Ok(CircuitExpr::Var(mangled)),
            }
        }

        // ── Unsupported in circuit context ──────────────────────────
        Expr::PostfixOp { span, .. } | Expr::PrefixOp { span, .. } => Err(LoweringError::new(
            "increment/decrement is not supported in circuit expressions",
            span,
        )),

        Expr::AnonComponent { span, .. } => Err(LoweringError::new(
            "anonymous component instantiation will be handled at statement level",
            span,
        )),

        Expr::Tuple { span, .. } => Err(LoweringError::new(
            "tuples are not supported in circuit expressions",
            span,
        )),

        Expr::ParallelOp { operand, .. } => lower_expr(operand, env, ctx),

        Expr::Underscore { span } => Err(LoweringError::new(
            "underscore `_` is not a valid circuit expression",
            span,
        )),

        Expr::Error { span } => Err(LoweringError::new("cannot lower an error expression", span)),
    }
}

/// Lower an array index expression.
fn lower_index(
    object: &Expr,
    index: &Expr,
    _span: &diagnostics::Span,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<CircuitExpr, LoweringError> {
    // Case 0: Known compile-time array (e.g. `C[i+r]` where C = POSEIDON_C(t))
    if let Some(fc) = try_resolve_known_array_index(object, index, env, ctx) {
        return Ok(CircuitExpr::Const(fc));
    }

    // Case 1: Simple ident `arr[i]`, DotAccess `comp.signal[i]`,
    // or component array signal `comp[i].signal[j]`
    if let Some(array_name) = extract_ident_name(object).or_else(|| {
        if let Expr::DotAccess {
            object: inner_obj,
            field,
            ..
        } = object
        {
            extract_ident_name(inner_obj)
                .or_else(|| resolve_component_array_expr_full(inner_obj, env, ctx))
                .map(|obj_name| format!("{obj_name}.{field}"))
        } else {
            None
        }
    }) {
        if let Some(idx_val) = const_eval_u64(index)
            .map(|v| v as usize)
            .or_else(|| eval_index_expr(index, env, ctx))
        {
            if let Some(elem_name) = env.resolve_array_element(&array_name, idx_val) {
                // Check if the element is a known constant (e.g., base[0]
                // where base_0 was injected via constant propagation).
                if let Some(&fc) = env.known_constants.get(&elem_name) {
                    return Ok(CircuitExpr::Const(fc));
                }
                return Ok(CircuitExpr::Var(elem_name));
            }
            // Circom-compatible: out-of-bounds access on a known-size signal
            // array returns 0 (uninitialized signal). This occurs in templates
            // like SegmentMulAny(1) where e[1] is accessed on a size-1 array.
            if let Some(&size) = env.arrays.get(&array_name) {
                if idx_val >= size {
                    return Ok(CircuitExpr::Const(FieldConst::zero()));
                }
            }
        }

        // placeholder index handling: previously this site
        // emitted E213 when `ctx.placeholder_appears_in(index)` AND the
        // base lived only in `known_array_values` (kav). Option II
        // accepts that shape — the IR carries `ArrayIndex { array:
        // <kav-name>, index: <symbolic-with-LoopVar> }` through iter-0
        // capture, then `memoize_loop` invokes
        // `known_array_fold::fold_known_array_indices` after each
        // `substitute_loop_var` pass to collapse the now-foldable node
        // to `CircuitExpr::Const(fc)`. The post-substitute fold mirrors
        // what legacy `try_resolve_known_array_index` (Case 0 above)
        // produces for non-placeholder shapes. If the fold pass
        // doesn't collapse the node (placeholder leaked, multi-dim kav
        // shape unreachable today, etc.) the residual reaches
        // instantiate and fails loudly there — preserving the original
        // safety net's intent without rejecting the legitimate Option
        // II Ark / MixS-loop shapes.
        let idx = lower_expr(index, env, ctx)?;
        return Ok(CircuitExpr::ArrayIndex {
            array: array_name,
            index: Box::new(idx),
        });
    }

    // Case 2: Multi-dim index: arr[i][j]...[k]
    {
        let mut indices: Vec<&Expr> = vec![index];
        let mut current: &Expr = object;
        loop {
            match current {
                Expr::Ident { name, .. } => {
                    indices.reverse();
                    return lower_multi_index(name, &indices, env, ctx);
                }
                Expr::DotAccess {
                    object: da_obj,
                    field,
                    ..
                } => {
                    if let Some(obj) = extract_ident_name(da_obj)
                        .or_else(|| resolve_component_array_expr_full(da_obj, env, ctx))
                    {
                        let base = format!("{obj}.{field}");
                        indices.reverse();
                        return lower_multi_index(&base, &indices, env, ctx);
                    }
                    break;
                }
                Expr::Index {
                    object: inner_obj,
                    index: inner_idx,
                    ..
                } => {
                    indices.push(inner_idx.as_ref());
                    current = inner_obj.as_ref();
                }
                _ => break,
            }
        }
    }

    // Circom-compatible: if the index target couldn't be resolved (e.g.,
    // component array with a negative index like bits[n-2] where n=1),
    // treat the access as 0. This matches Circom's behavior where
    // nonexistent signals have value 0.
    Ok(CircuitExpr::Const(FieldConst::zero()))
}

#[cfg(test)]
mod tests;
