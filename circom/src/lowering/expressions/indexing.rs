//! Array indexing and component array resolution.
//!
//! Handles multi-dimensional array indexing with stride linearization,
//! known compile-time array resolution, and component array name mangling.

use std::collections::HashMap;

use ir_forge::types::{CircuitBinOp, CircuitExpr, FieldConst};

use crate::ast::Expr;

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::utils::{const_eval_u64, extract_ident_name, EvalValue};
use super::lower_expr;

/// Lower a multi-dimensional array index, linearizing with strides.
///
/// `arr[i][j]` with strides [2] → `ArrayIndex { array: "arr", index: i*2+j }`
/// `arr[i][j][k]` with strides [8, 4] → `ArrayIndex { array: "arr", index: i*8+j*4+k }`
pub(super) fn lower_multi_index(
    base_name: &str,
    indices: &[&Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext<'_>,
) -> Result<CircuitExpr, LoweringError> {
    // Defensive: callers unwrap a chain of `Index` AST nodes, so `indices` is
    // always at least one element. Guard anyway so a future refactor cannot
    // trigger the `.expect()` below.
    if indices.is_empty() {
        return Err(LoweringError::without_span(format!(
            "internal: lower_multi_index called with empty indices on `{base_name}`"
        )));
    }

    // R1″ Phase 6 / Follow-up A: hard-skip both const-resolve fast paths
    // when the active memoization placeholder loop variable appears in any
    // index slot. The loop var must stay symbolic (as `LoopVar(token)`)
    // until `substitute_loop_var` rewrites it per iteration; either fast
    // path would either fail (placeholder absent from params/known_consts)
    // or, in a hypothetical scope leak, bake iter-0 into the IR.
    let any_slot_has_placeholder = indices.iter().any(|idx| ctx.placeholder_appears_in(idx));

    // Check known compile-time arrays first (e.g. M[j][i] where M = POSEIDON_M(t))
    if !any_slot_has_placeholder {
        if let Some(arr_val) = env.known_array_values.get(base_name) {
            if let Some(fc) = resolve_multi_dim_array(arr_val, indices, env, ctx) {
                return Ok(CircuitExpr::Const(fc));
            }
        }
    } else if env.known_array_values.contains_key(base_name) && !env.arrays.contains_key(base_name)
    {
        // Phantom-ArrayIndex guard: the symbolic linearisation below would
        // emit `ArrayIndex { array: base_name, index: <symbolic> }` against
        // a name that has no signal-array binding, dangling at instantiate.
        // The `is_memoizable` classifier's `KnownArrayRefs` strategy gate
        // is supposed to reject such bodies upstream — this is defence in
        // depth in case that gate ever loosens.
        return Err(LoweringError::with_code(
            format!(
                "internal: cannot symbolically index `{base_name}` against the \
                 R1″ memoization placeholder loop variable; `{base_name}` lives \
                 only in known_array_values (no signal binding). The \
                 is_memoizable classifier should have rejected this body via \
                 the KnownArrayRefs strategy gate."
            ),
            "E213",
            indices[0].span(),
        ));
    }

    let strides = env.strides.get(base_name);
    let n = indices.len();

    // Strides guard for symbolic placeholder paths: when the placeholder is
    // present and we have multi-dim shape, missing strides would silently
    // default to 1 below and produce wrong constraints. The `is_memoizable`
    // classifier should reject such bodies via the existing gates; defence
    // in depth in case Edit 4 (or a future loosening) lets one slip through.
    if any_slot_has_placeholder && n > 1 && strides.is_none() {
        return Err(LoweringError::with_code(
            format!(
                "internal: cannot symbolically index `{base_name}` (multi-dim) \
                 against the R1″ memoization placeholder loop variable; \
                 `{base_name}` has no strides registered, so symbolic \
                 linearisation would default to stride=1 and produce wrong \
                 constraints."
            ),
            "E213",
            indices[0].span(),
        ));
    }

    // Try full constant evaluation for direct resolution (using known_constants for loop vars).
    // Skip entirely when the placeholder is in any slot — see comment above.
    if !any_slot_has_placeholder {
        let const_vals: Option<Vec<usize>> = indices
            .iter()
            .map(|idx| {
                const_eval_u64(idx)
                    .map(|v| v as usize)
                    .or_else(|| eval_index_expr(idx, env, ctx))
            })
            .collect();
        if let Some(vals) = const_vals {
            let mut linear: usize = 0;
            for (dim, &val) in vals.iter().enumerate() {
                let stride = if dim < n - 1 {
                    strides.and_then(|s| s.get(dim)).copied().unwrap_or(1)
                } else {
                    1
                };
                linear += val * stride;
            }
            if let Some(elem_name) = env.resolve_array_element(base_name, linear) {
                return Ok(CircuitExpr::Var(elem_name));
            }
        }
    }

    // Build symbolic linearized expression
    let mut result: Option<CircuitExpr> = None;
    for (dim, idx) in indices.iter().enumerate() {
        let lowered = lower_expr(idx, env, ctx)?;
        let stride = if dim < n - 1 {
            strides.and_then(|s| s.get(dim)).copied().unwrap_or(1)
        } else {
            1
        };

        let term = if stride == 1 {
            lowered
        } else {
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(lowered),
                rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(stride as u64))),
            }
        };

        result = Some(match result {
            None => term,
            Some(acc) => CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(acc),
                rhs: Box::new(term),
            },
        });
    }

    // `indices` non-empty check at function entry ensures the loop ran at
    // least once, so `result` is always Some here. Guard with `ok_or_else`
    // instead of `.expect()` so clippy and reviewers see explicit error flow.
    let index = result.ok_or_else(|| {
        LoweringError::without_span(format!(
            "internal: lower_multi_index produced no index for `{base_name}`"
        ))
    })?;
    Ok(CircuitExpr::ArrayIndex {
        array: base_name.to_string(),
        index: Box::new(index),
    })
}

/// Resolve a component array expression to a mangled name.
///
/// Handles 1D (`comp[i]` → `comp_0`) and multi-dim (`comp[i][j]` → `comp_0_1`).
/// Merges `env.known_constants` + `ctx.param_values` for full resolution.
///
/// Used on the *expression* (read) side. R1″ Phase 6 / Option D: when
/// the active memoization placeholder matches an index slot, the
/// segment is emitted as `loop_var_placeholder(token)` so the resulting
/// `Var` reference can be rewritten by `substitute_loop_var` per
/// iteration. The READ side intentionally embeds the placeholder
/// because the consumer is IR emission; the wiring.rs lookup path
/// uses the legacy non-placeholder `resolve_component_array_name` to
/// preserve `pending` HashMap key matching against the real iter-0
/// component name.
pub(super) fn resolve_component_array_expr_full(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<String> {
    let all = ctx.all_constants(env);
    resolve_component_array_expr_with_constants(expr, &all, Some(ctx))
}

/// Resolve a component array expression with explicit known constants.
///
/// Returns `None` for negative indices (e.g., `bits[n-2]` where `n=1`),
/// which prevents generating invalid component names.
///
/// `placeholder_ctx` carries the optional R1″ memoization context;
/// `Some(ctx)` enables the per-index placeholder check, `None` keeps
/// the legacy numeric-only resolution. Recursive calls propagate the
/// same option so multi-dim indices like `comp[0][i]` mix literals and
/// placeholders correctly.
fn resolve_component_array_expr_with_constants(
    expr: &Expr,
    known_constants: &HashMap<String, FieldConst>,
    placeholder_ctx: Option<&LoweringContext>,
) -> Option<String> {
    match expr {
        Expr::Index { object, index, .. } => {
            let idx_segment = placeholder_ctx
                .and_then(|c| c.placeholder_index_segment(index))
                .or_else(|| {
                    let idx = const_eval_u64(index).or_else(|| {
                        // Evaluate using BigVal to detect negative values
                        let vars = super::super::utils::fc_map_to_bigval(known_constants);
                        let empty_fns = HashMap::new();
                        let empty_arrays: HashMap<String, crate::lowering::utils::EvalValue> =
                            HashMap::new();
                        let result = super::super::utils::eval_expr(
                            index,
                            &vars,
                            &empty_arrays,
                            &empty_fns,
                            0,
                        )?;
                        if result.is_negative() {
                            None
                        } else {
                            result.to_u64()
                        }
                    })?;
                    Some(idx.to_string())
                })?;
            if let Some(arr_name) = extract_ident_name(object) {
                Some(format!("{arr_name}_{idx_segment}"))
            } else {
                let inner = resolve_component_array_expr_with_constants(
                    object,
                    known_constants,
                    placeholder_ctx,
                )?;
                Some(format!("{inner}_{idx_segment}"))
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Known array resolution helpers
// ---------------------------------------------------------------------------

/// Try to resolve a 1-D known array index `arr[expr]` to a `FieldConst`.
///
/// R1″ Phase 6 / Follow-up A: returns `None` when the active memoization
/// placeholder loop variable appears in `index`. The placeholder loop var
/// must stay symbolic (`LoopVar(token)`) until late substitution; the
/// fall-back symbolic emission in `lower_index` handles this correctly
/// when the base is registered in `env.arrays`. Callers that emit
/// `CircuitExpr::ArrayIndex` against a `known_array_values`-only name
/// after this returns `None` must add their own phantom-ArrayIndex guard
/// (see `expressions/mod.rs::lower_index` and `lower_multi_index` above).
pub(super) fn try_resolve_known_array_index(
    object: &Expr,
    index: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<FieldConst> {
    let base_name = extract_ident_name(object)?;
    let arr_val = env.known_array_values.get(&base_name)?;
    if ctx.placeholder_appears_in(index) {
        return None;
    }
    let idx = eval_index_expr(index, env, ctx)?;
    eval_value_to_field_const(arr_val.index(idx)?)
}

/// Resolve a multi-dimensional known array access `M[i][j]…` to a `FieldConst`.
pub(super) fn resolve_multi_dim_array(
    val: &EvalValue,
    indices: &[&Expr],
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<FieldConst> {
    let mut current = val;
    for idx_expr in indices {
        let idx = eval_index_expr(idx_expr, env, ctx)?;
        current = current.index(idx)?;
    }
    eval_value_to_field_const(current)
}

/// Evaluate an index expression to a usize using all available compile-time context.
pub(super) fn eval_index_expr(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<usize> {
    let params = ctx.all_constants(env);
    let fc = super::super::utils::const_eval_with_params(expr, &params)?;
    Some(fc.to_u64()? as usize)
}

/// Convert an [`EvalValue`] leaf to a `FieldConst`.
fn eval_value_to_field_const(val: &EvalValue) -> Option<FieldConst> {
    match val {
        EvalValue::Scalar(v) => Some(v.to_field_const()),
        EvalValue::Expr(expr) => match expr.as_ref() {
            Expr::Number { value, .. } => FieldConst::from_decimal_str(value),
            Expr::HexNumber { value, .. } => FieldConst::from_hex_str(value),
            _ => None,
        },
        EvalValue::Array(_) => None,
    }
}
