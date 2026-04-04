//! Array indexing and component array resolution.
//!
//! Handles multi-dimensional array indexing with stride linearization,
//! known compile-time array resolution, and component array name mangling.

use std::collections::HashMap;

use ir::prove_ir::types::{CircuitBinOp, CircuitExpr, FieldConst};

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
    // Check known compile-time arrays first (e.g. M[j][i] where M = POSEIDON_M(t))
    if let Some(arr_val) = env.known_array_values.get(base_name) {
        if let Some(fc) = resolve_multi_dim_array(arr_val, indices, env, ctx) {
            return Ok(CircuitExpr::Const(fc));
        }
    }

    let strides = env.strides.get(base_name);
    let n = indices.len();

    // Try full constant evaluation for direct resolution (using known_constants for loop vars)
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

    // SAFETY: `indices` is non-empty (caller unwraps a chain of Index AST nodes),
    // so the loop runs at least once and `result` is always Some.
    Ok(CircuitExpr::ArrayIndex {
        array: base_name.to_string(),
        index: Box::new(result.expect("lower_multi_index called with empty indices")),
    })
}

/// Resolve a component array expression to a mangled name.
///
/// Handles 1D (`comp[i]` → `comp_0`) and multi-dim (`comp[i][j]` → `comp_0_1`).
/// Merges `env.known_constants` + `ctx.param_values` for full resolution.
pub(super) fn resolve_component_array_expr_full(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<String> {
    let all = ctx.all_constants(env);
    resolve_component_array_expr_with_constants(expr, &all)
}

/// Resolve a component array expression with explicit known constants.
///
/// Returns `None` for negative indices (e.g., `bits[n-2]` where `n=1`),
/// which prevents generating invalid component names.
fn resolve_component_array_expr_with_constants(
    expr: &Expr,
    known_constants: &HashMap<String, u64>,
) -> Option<String> {
    match expr {
        Expr::Index { object, index, .. } => {
            let idx = const_eval_u64(index).or_else(|| {
                // Evaluate as i64 first to detect negative values
                let vars: HashMap<String, i64> = known_constants
                    .iter()
                    .map(|(k, &v)| (k.clone(), v as i64))
                    .collect();
                let empty_fns = HashMap::new();
                let result = super::super::utils::eval_expr_i64_raw(index, &vars, &empty_fns, 0)?;
                if result < 0 {
                    None
                } else {
                    Some(result as u64)
                }
            })?;
            if let Some(arr_name) = extract_ident_name(object) {
                Some(format!("{arr_name}_{idx}"))
            } else {
                let inner = resolve_component_array_expr_with_constants(object, known_constants)?;
                Some(format!("{inner}_{idx}"))
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Known array resolution helpers
// ---------------------------------------------------------------------------

/// Try to resolve a 1-D known array index `arr[expr]` to a `FieldConst`.
pub(super) fn try_resolve_known_array_index(
    object: &Expr,
    index: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<FieldConst> {
    let base_name = extract_ident_name(object)?;
    let arr_val = env.known_array_values.get(&base_name)?;
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
    super::super::utils::const_eval_with_params(expr, &params).map(|v| v as usize)
}

/// Convert an [`EvalValue`] leaf to a `FieldConst`.
fn eval_value_to_field_const(val: &EvalValue) -> Option<FieldConst> {
    match val {
        EvalValue::Scalar(v) => Some(FieldConst::from_u64(*v as u64)),
        EvalValue::Expr(expr) => match expr.as_ref() {
            Expr::Number { value, .. } => FieldConst::from_decimal_str(value),
            Expr::HexNumber { value, .. } => FieldConst::from_hex_str(value),
            _ => None,
        },
        EvalValue::Array(_) => None,
    }
}
