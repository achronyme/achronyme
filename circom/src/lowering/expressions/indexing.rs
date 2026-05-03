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

    // placeholder index handling: hard-skip both const-resolve fast paths
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
    }
    // placeholder index handling: the previous E213 guard
    // here rejected `ArrayIndex { array: <kav-only name>, index:
    // <symbolic> }` emissions because they would dangle at instantiate.
    // Option II accepts that shape: the symbolic linearisation below
    // emits the node, `memoize_loop` substitutes the placeholder per
    // iteration, then `known_array_fold::fold_known_array_indices`
    // collapses the now-foldable index. For multi-dim kav values
    // (`EvalValue::Array(EvalValue::Array(_))`), the fold pass returns
    // the node unchanged (its leaf converter rejects nested arrays);
    // such residuals reach instantiate and fail loudly there. The
    // upstream classifier (`body_has_state_carrying_var_mutation`)
    // currently blocks Mix-shaped multi-dim bodies (Mix's `M[j][i]`),
    // so this path is unreachable today through real code; the
    // strides guard below still catches the n>1+missing-strides case.

    let env_strides = env.strides.get(base_name);
    let n = indices.len();

    // memoization admit/soundness check: derive strides from a 2-D
    // `known_array_values` entry when `env.strides` is missing.
    // Compile-time arrays (Mix's `M`, `POSEIDON_M`, BabyJubjub coefficient
    // tables, …) live in `env.known_array_values` and never get registered
    // in `env.strides` (that map is signal-only — `extract_signal_strides`
    // populates it from template signal decls). The R1″ symbolic-
    // linearisation path below needs strides to produce the correct
    // `j*inner_len + i` shape for `M[j][i]`; without them, the strides
    // guard would fire (defence-in-depth below). Derive strides from the
    // kav structure when env.strides is absent — the shape's `outer_len`
    // and uniform `inner_len` are the ground truth.
    let derived_strides: Option<Vec<usize>> = if env_strides.is_none() {
        env.known_array_values
            .get(base_name)
            .and_then(|arr| derive_strides_from_kav(arr, n))
    } else {
        None
    };
    let strides_slice: Option<&[usize]> = env_strides
        .map(Vec::as_slice)
        .or(derived_strides.as_deref());

    // Strides guard for symbolic placeholder paths: when the placeholder is
    // present and we have multi-dim shape, missing strides would silently
    // default to 1 below and produce wrong constraints. The `is_memoizable`
    // classifier should reject such bodies via the existing gates; defence
    // in depth in case Edit 4 (or a future loosening) lets one slip through.
    if any_slot_has_placeholder && n > 1 && strides_slice.is_none() {
        return Err(LoweringError::with_code(
            format!(
                "internal: cannot symbolically index `{base_name}` (multi-dim) \
                 against the R1″ memoization placeholder loop variable; \
                 `{base_name}` has no strides registered (neither in \
                 `env.strides` nor derivable from a uniform `EvalValue::Array` \
                 in `env.known_array_values`), so symbolic linearisation \
                 would default to stride=1 and produce wrong constraints."
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
                    strides_slice.and_then(|s| s.get(dim)).copied().unwrap_or(1)
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
            strides_slice.and_then(|s| s.get(dim)).copied().unwrap_or(1)
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
/// Used on the *expression* (read) side. memoized unroll: when
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
    let lookup = super::super::utils::CtxEnvLookup::new(ctx, env);
    resolve_component_array_expr_with_constants(expr, &lookup, Some(ctx))
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
fn resolve_component_array_expr_with_constants<L: super::super::utils::VarLookup>(
    expr: &Expr,
    known_constants: &L,
    placeholder_ctx: Option<&LoweringContext>,
) -> Option<String> {
    match expr {
        Expr::Index { object, index, .. } => {
            let idx_segment = placeholder_ctx
                .and_then(|c| c.placeholder_index_segment(index))
                .or_else(|| {
                    let idx = const_eval_u64(index).or_else(|| {
                        // Evaluate using BigVal to detect negative values
                        let empty_fns = HashMap::new();
                        let empty_arrays: HashMap<String, crate::lowering::utils::EvalValue> =
                            HashMap::new();
                        let result = super::super::utils::eval_expr(
                            index,
                            known_constants,
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
/// placeholder index handling: returns `None` when the
/// active memoization placeholder loop variable appears in `index`.
/// The placeholder loop var must stay symbolic (`LoopVar(token)`) until
/// late substitution; the symbolic-fallthrough in `lower_index` /
/// `lower_multi_index` emits the `CircuitExpr::ArrayIndex { array:
/// <kav-name>, index: <symbolic-with-LoopVar> }` shape, which Option
/// II's [`crate::lowering::known_array_fold::fold_known_array_indices`]
/// pass collapses to `Const(fc)` after each per-iter
/// `substitute_loop_var` call in `memoize_loop`. The previous E213
/// phantom-`ArrayIndex` guards in `lower_index` and `lower_multi_index`
/// have been relaxed to accept this shape — the post-substitute fold
/// is now the authoritative resolution path for kav-only ArrayIndex
/// nodes produced under iter-0 capture.
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
    let fc = super::super::utils::const_eval_ctx(expr, ctx, env)?;
    Some(fc.to_u64()? as usize)
}

/// Derive row-major strides for an `n_dims`-dimensional access against
/// a uniformly-shaped `EvalValue::Array(...)` value.
///
/// memoization admit/soundness check: compile-time arrays in
/// `env.known_array_values` (Mix's `M`, `POSEIDON_M`, BabyJubjub
/// coefficient tables, …) never get registered in `env.strides` because
/// strides are populated only for SIGNAL arrays via
/// `extract_signal_strides`. The R1″ symbolic-linearisation path needs
/// strides to produce the correct `j*inner_len + i` shape for `M[j][i]`;
/// this helper synthesises them from the kav structure on demand.
///
/// Returns `Some(strides)` of length `n_dims - 1` where `strides[i]` is
/// the product of dimensions `i+1..n_dims` (matching
/// `extract_signal_strides`'s row-major convention). Returns `None` if:
///   - `n_dims < 2` (no strides needed for 1-D),
///   - the value is not deeply enough nested for `n_dims`,
///   - any sibling row at any level has a different length than the
///     first (uniformity defence — a ragged shape's strides would be
///     wrong, and rejecting closes the soundness gap that would
///     otherwise let the strides guard be bypassed).
///
/// Layered with the strides guard above: this helper is the only path
/// that can satisfy the guard for kav-only multi-dim names; if it
/// returns `None`, the guard fires and the caller hits E213 cleanly.
pub(in crate::lowering) fn derive_strides_from_kav(
    arr: &EvalValue,
    n_dims: usize,
) -> Option<Vec<usize>> {
    if n_dims < 2 {
        return None;
    }
    let mut dims: Vec<usize> = Vec::with_capacity(n_dims);
    let mut current: &EvalValue = arr;
    for _ in 0..n_dims {
        let elems = match current {
            EvalValue::Array(elems) => elems,
            _ => return None,
        };
        if elems.is_empty() {
            return None;
        }
        dims.push(elems.len());
        let first = elems.first()?;
        // Uniformity defence: every sibling row must match `first`'s
        // arrayness/length so the row-major linearisation is sound.
        for sibling in elems.iter() {
            match (sibling, first) {
                (EvalValue::Array(s), EvalValue::Array(f)) if s.len() == f.len() => {}
                (EvalValue::Scalar(_), EvalValue::Scalar(_)) => {}
                (EvalValue::Expr(_), EvalValue::Expr(_)) => {}
                (EvalValue::Scalar(_), EvalValue::Expr(_))
                | (EvalValue::Expr(_), EvalValue::Scalar(_)) => {
                    // Mixed scalar/expr leaves are still scalar-shaped
                    // for indexing purposes; uniformity holds.
                }
                _ => return None,
            }
        }
        current = first;
    }
    if dims.len() < n_dims {
        return None;
    }
    let mut strides = Vec::with_capacity(n_dims - 1);
    for i in 0..n_dims - 1 {
        let s: usize = dims[i + 1..].iter().product();
        strides.push(s);
    }
    Some(strides)
}

/// Convert an [`EvalValue`] leaf to a `FieldConst`.
///
/// Visible to sibling lowering modules (e.g. `known_array_fold`) so the
/// post-substitute fold pass can resolve `EvalValue::Scalar` /
/// `EvalValue::Expr(Number|HexNumber)` leaves uniformly with the
/// lowering-time path. `EvalValue::Array(_)` returns `None` — multi-dim
/// shapes are not foldable through this entry point.
pub(in crate::lowering) fn eval_value_to_field_const(val: &EvalValue) -> Option<FieldConst> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lowering::utils::bigval::BigVal;

    fn scalar(v: u64) -> EvalValue {
        EvalValue::Scalar(BigVal::from_u64(v))
    }

    fn array_1d(values: &[u64]) -> EvalValue {
        EvalValue::Array(values.iter().map(|&v| scalar(v)).collect())
    }

    /// Mix's `M[j][i]` with `t=6`: a 6×6 uniform matrix derives strides
    /// `[6]` (row-major: stride for outer dim is the inner row length).
    #[test]
    fn derive_strides_from_uniform_2d_returns_inner_len() {
        let row = array_1d(&[1, 2, 3, 4, 5, 6]);
        let m = EvalValue::Array(vec![
            row.clone(),
            row.clone(),
            row.clone(),
            row.clone(),
            row.clone(),
            row,
        ]);
        let strides = derive_strides_from_kav(&m, 2);
        assert_eq!(strides, Some(vec![6]));
    }

    /// 1-D access against a 1-D kav doesn't need strides, returns None.
    #[test]
    fn derive_strides_returns_none_for_1d_access() {
        let arr = array_1d(&[1, 2, 3]);
        assert_eq!(derive_strides_from_kav(&arr, 1), None);
    }

    /// Ragged 2-D shape (rows have different inner lengths) returns
    /// None — uniformity defence. The caller's strides guard then fires
    /// E213 instead of silently linearising with wrong strides.
    #[test]
    fn derive_strides_returns_none_for_ragged_2d() {
        let row_a = array_1d(&[1, 2, 3]);
        let row_b = array_1d(&[4, 5]);
        let m = EvalValue::Array(vec![row_a, row_b]);
        assert_eq!(derive_strides_from_kav(&m, 2), None);
    }

    /// Empty outer array returns None — no shape to derive from.
    #[test]
    fn derive_strides_returns_none_for_empty_array() {
        let m = EvalValue::Array(vec![]);
        assert_eq!(derive_strides_from_kav(&m, 2), None);
    }

    /// 1-D kav indexed with `n_dims=2` (caller asks for 2-D strides
    /// against a 1-D value) returns None — the kav isn't deep enough.
    #[test]
    fn derive_strides_returns_none_for_too_shallow_kav() {
        let arr = array_1d(&[1, 2, 3]);
        assert_eq!(derive_strides_from_kav(&arr, 2), None);
    }

    /// 3-D uniform shape: 2×3×4 produces strides `[12, 4]`. Matches
    /// `extract_signal_strides`'s row-major convention.
    #[test]
    fn derive_strides_handles_3d_uniform() {
        let leaf = array_1d(&[1, 2, 3, 4]);
        let row = EvalValue::Array(vec![leaf.clone(), leaf.clone(), leaf]);
        let m = EvalValue::Array(vec![row.clone(), row]);
        let strides = derive_strides_from_kav(&m, 3);
        assert_eq!(strides, Some(vec![12, 4]));
    }
}
