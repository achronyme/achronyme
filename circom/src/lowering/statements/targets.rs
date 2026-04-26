//! Assignment target resolution.
//!
//! Parses and resolves the left-hand side of signal/variable assignments:
//! simple identifiers, dot access (component signals), array indexing,
//! and multi-dimensional array access with stride linearization.

use std::collections::HashMap;

use ir_forge::types::{CircuitBinOp, CircuitExpr, FieldConst};

use crate::ast::Expr;

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::utils::{const_eval_u64, extract_ident_name};

/// Describes the target of a signal assignment.
#[cfg_attr(test, derive(Debug))]
pub(super) enum AssignTarget {
    /// Simple identifier: `x`
    Scalar(String),
    /// Indexed array element: `out[i]`
    Indexed { array: String, index: Box<Expr> },
    /// Multi-indexed: `c[i][j]`, `c[i][j][k]`, etc.
    /// Indices are in order: [outer, ..., inner].
    MultiIndexed { array: String, indices: Vec<Expr> },
}

/// Extract a target from either a simple identifier, dot access, or array index.
///
/// - `Ident("x")` → `Scalar("x")`
/// - `DotAccess { object: "c", field: "a" }` → `Scalar("c.a")`
/// - `Index { object: "out", index: i }` → `Indexed { array: "out", index: i }`
pub(super) fn extract_assign_target(expr: &Expr) -> Option<AssignTarget> {
    extract_assign_target_with_constants(expr, &HashMap::new())
}

/// Extract an assignment target using ctx+env for constant resolution.
///
/// Avoids creating a merged HashMap by looking up constants directly
/// in `ctx.param_values` and `env.known_constants`.
pub(super) fn extract_assign_target_ctx(
    expr: &Expr,
    ctx: &LoweringContext,
    env: &LoweringEnv,
) -> Option<AssignTarget> {
    match expr {
        Expr::Ident { name, .. } => Some(AssignTarget::Scalar(name.clone())),
        Expr::DotAccess { object, field, .. } => {
            if let Some(obj) = extract_ident_name(object) {
                return Some(AssignTarget::Scalar(format!("{obj}.{field}")));
            }
            if let Some(comp_name) = resolve_component_array_name_ctx(object, ctx, env) {
                return Some(AssignTarget::Scalar(format!("{comp_name}.{field}")));
            }
            None
        }
        Expr::Index { object, index, .. } => {
            let mut indices: Vec<Expr> = vec![index.as_ref().clone()];
            let mut current = object.as_ref();
            loop {
                match current {
                    Expr::Ident { name, .. } => {
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array: name.clone(),
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed {
                                array: name.clone(),
                                indices,
                            })
                        };
                    }
                    Expr::DotAccess {
                        object: inner,
                        field,
                        ..
                    } => {
                        let base = if let Some(obj) = extract_ident_name(inner) {
                            format!("{obj}.{field}")
                        } else if let Some(comp) = resolve_component_array_name_ctx(inner, ctx, env)
                        {
                            format!("{comp}.{field}")
                        } else {
                            return None;
                        };
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array: base,
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed {
                                array: base,
                                indices,
                            })
                        };
                    }
                    Expr::Index {
                        object: o,
                        index: i,
                        ..
                    } => {
                        indices.push(i.as_ref().clone());
                        current = o.as_ref();
                    }
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}

/// Resolve component array name using ctx+env (avoids merged HashMap).
pub(super) fn resolve_component_array_name_ctx(
    expr: &Expr,
    ctx: &LoweringContext,
    env: &LoweringEnv,
) -> Option<String> {
    match expr {
        Expr::Index { object, index, .. } => {
            // R1″ Phase 6 / Option D: when the index references the
            // active memoization placeholder (e.g. `comp[i]` while
            // capturing iter 0 of the loop over `i`), embed the
            // placeholder substring instead of the iter-0 numeric
            // value so `substitute_loop_var` can rewrite it per
            // iteration during replay. Falls back to the numeric
            // resolution otherwise — non-memoization callers hit the
            // `None` branch and behave exactly as before.
            let idx_segment = ctx
                .placeholder_index_segment(index)
                .or_else(|| resolve_const_index_ctx(index, ctx, env).map(|v| v.to_string()))?;
            if let Some(arr_name) = extract_ident_name(object) {
                Some(format!("{arr_name}_{idx_segment}"))
            } else {
                let inner = resolve_component_array_name_ctx(object, ctx, env)?;
                Some(format!("{inner}_{idx_segment}"))
            }
        }
        _ => None,
    }
}

/// Resolve constant index using ctx+env (avoids creating merged HashMap).
///
/// Mirrors [`resolve_const_index`]'s capability set so the two variants
/// stay interchangeable from the caller's perspective. Earlier this
/// function only handled `Add` / `Sub` and relied on the BigVal
/// fallback for everything else; subbing `extract_assign_target_ctx`
/// for `extract_assign_target_with_constants` exposed the gap on
/// circomlib's Poseidon (`ark[nRoundsF\2]` = IntDiv on a capture).
fn resolve_const_index_ctx(expr: &Expr, ctx: &LoweringContext, env: &LoweringEnv) -> Option<u64> {
    if let Some(v) = const_eval_u64(expr) {
        return Some(v);
    }
    if let Expr::Ident { name, .. } = expr {
        return ctx.resolve_constant(name, env)?.to_u64();
    }
    if let Expr::BinOp { op, lhs, rhs, .. } = expr {
        if let (Expr::Ident { name, .. }, Some(rhs_val)) = (lhs.as_ref(), const_eval_u64(rhs)) {
            if let Some(lhs_val) = ctx.resolve_constant(name, env)?.to_u64() {
                return match op {
                    crate::ast::BinOp::Add => lhs_val.checked_add(rhs_val),
                    crate::ast::BinOp::Sub => lhs_val.checked_sub(rhs_val),
                    crate::ast::BinOp::Mul => lhs_val.checked_mul(rhs_val),
                    crate::ast::BinOp::IntDiv => {
                        if rhs_val != 0 {
                            Some(lhs_val / rhs_val)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
            }
        }
    }
    // Fallback
    let all = ctx.all_constants(env);
    resolve_const_index(expr, &all)
}

/// Extract an assignment target, resolving known constants for component array indices.
pub(super) fn extract_assign_target_with_constants(
    expr: &Expr,
    known_constants: &HashMap<String, FieldConst>,
) -> Option<AssignTarget> {
    match expr {
        Expr::Ident { name, .. } => Some(AssignTarget::Scalar(name.clone())),
        Expr::DotAccess { object, field, .. } => {
            // Simple: comp.field
            if let Some(obj) = extract_ident_name(object) {
                return Some(AssignTarget::Scalar(format!("{obj}.{field}")));
            }
            // Component array: comp[i].field → comp_{i}.field
            // Also handles 2D: comp[i][j].field → comp_{i}_{j}.field
            if let Some(comp_name) = resolve_component_array_name(object, known_constants) {
                return Some(AssignTarget::Scalar(format!("{comp_name}.{field}")));
            }
            None
        }
        Expr::Index { object, index, .. } => {
            // Unwrap nested Index chains: arr[i][j][k] → base + [i, j, k]
            let mut indices: Vec<Expr> = vec![index.as_ref().clone()];
            let mut current = object.as_ref();
            loop {
                match current {
                    Expr::Ident { name, .. } => {
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array: name.clone(),
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed {
                                array: name.clone(),
                                indices,
                            })
                        };
                    }
                    Expr::DotAccess {
                        object: inner,
                        field,
                        ..
                    } => {
                        // comp.signal[j] or comp[i].signal[j]
                        let base = if let Some(obj) = extract_ident_name(inner) {
                            format!("{obj}.{field}")
                        } else if let Some(comp) =
                            resolve_component_array_name(inner, known_constants)
                        {
                            format!("{comp}.{field}")
                        } else {
                            return None;
                        };
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array: base,
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed {
                                array: base,
                                indices,
                            })
                        };
                    }
                    Expr::Index {
                        object: inner_obj,
                        index: inner_idx,
                        ..
                    } => {
                        indices.push(inner_idx.as_ref().clone());
                        current = inner_obj.as_ref();
                    }
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}

/// Resolve a component array expression like `comp[i]` or `comp[i][j]` to
/// a mangled component name (`comp_0`, `comp_0_1`).
///
/// Returns `None` if indices cannot be resolved at compile time.
pub(super) fn resolve_component_array_name(
    expr: &Expr,
    known_constants: &HashMap<String, FieldConst>,
) -> Option<String> {
    match expr {
        Expr::Index { object, index, .. } => {
            let idx = resolve_const_index(index, known_constants)?;
            if let Some(arr_name) = extract_ident_name(object) {
                // 1D: comp[i] → comp_{i}
                Some(format!("{arr_name}_{idx}"))
            } else {
                // Multi-dim: recurse on inner
                let inner = resolve_component_array_name(object, known_constants)?;
                Some(format!("{inner}_{idx}"))
            }
        }
        _ => None,
    }
}

/// Resolve an index expression to a constant u64 using literals + known_constants.
///
/// Returns `None` for negative values (e.g., `n-2` where `n=1`), which
/// indicate out-of-bounds component array access. This prevents wrapping
/// to u64::MAX and generating invalid component names like `bits_18446744073709551615`.
pub(super) fn resolve_const_index(
    expr: &Expr,
    known_constants: &HashMap<String, FieldConst>,
) -> Option<u64> {
    if let Some(v) = const_eval_u64(expr) {
        return Some(v);
    }
    // Fast path: simple identifier lookup (avoids creating BigVal HashMap)
    if let Expr::Ident { name, .. } = expr {
        return known_constants.get(name.as_str())?.to_u64();
    }
    // Fast path: ident op literal (e.g., `i-1`, `i+1`, `n\2`)
    if let Expr::BinOp { op, lhs, rhs, .. } = expr {
        if let (Expr::Ident { name, .. }, Some(rhs_val)) = (lhs.as_ref(), const_eval_u64(rhs)) {
            if let Some(lhs_val) = known_constants.get(name.as_str())?.to_u64() {
                return match op {
                    crate::ast::BinOp::Add => lhs_val.checked_add(rhs_val),
                    crate::ast::BinOp::Sub => lhs_val.checked_sub(rhs_val),
                    crate::ast::BinOp::Mul => lhs_val.checked_mul(rhs_val),
                    crate::ast::BinOp::IntDiv => {
                        if rhs_val != 0 {
                            Some(lhs_val / rhs_val)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
            }
        }
    }
    // Fallback: full BigVal evaluation for complex expressions
    let vars = super::super::utils::fc_map_to_bigval(known_constants);
    let empty_fns = HashMap::new();
    let empty_arrays: HashMap<String, crate::lowering::utils::EvalValue> = HashMap::new();
    let result = super::super::utils::eval_expr(expr, &vars, &empty_arrays, &empty_fns, 0)?;
    if result.is_negative() {
        None
    } else {
        result.to_u64()
    }
}

/// Try to resolve a component array target (1D or multi-dim) to a component name.
///
/// `muls[i]` → `Some("muls_0")`, `sigmaF[r][j]` → `Some("sigmaF_0_1")`
/// Returns `None` if the target isn't a component array access.
pub(super) fn try_resolve_component_array_target(
    target: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<String> {
    let all_constants = ctx.all_constants(env);
    let mut indices: Vec<&Expr> = Vec::new();
    let mut current = target;
    loop {
        match current {
            Expr::Index { object, index, .. } => {
                indices.push(index.as_ref());
                current = object.as_ref();
            }
            Expr::Ident { name, .. } => {
                if !env.component_arrays.contains(name) {
                    return None;
                }
                indices.reverse();
                let mut comp_name = name.clone();
                for idx_expr in &indices {
                    // R1″ Phase 6 / Option D: per-index placeholder
                    // check. Multi-dim arrays may mix placeholder and
                    // non-placeholder slots (e.g. `mux.c[0][i]`).
                    let idx_segment =
                        ctx.placeholder_index_segment(idx_expr).or_else(|| {
                            resolve_const_index(idx_expr, &all_constants).map(|v| v.to_string())
                        })?;
                    comp_name = format!("{comp_name}_{idx_segment}");
                }
                return Some(comp_name);
            }
            _ => return None,
        }
    }
}

/// Extract a simple scalar target name (for backwards compatibility).
pub(super) fn extract_target_name(expr: &Expr) -> Option<String> {
    match extract_assign_target(expr)? {
        AssignTarget::Scalar(name) => Some(name),
        AssignTarget::Indexed { .. } | AssignTarget::MultiIndexed { .. } => None,
    }
}

/// Linearize multi-dimensional array indices using strides.
///
/// For `arr[i][j]` with strides [s0]: linear = i * s0 + j
/// For `arr[i][j][k]` with strides [s0, s1]: linear = i * s0 + j * s1 + k
///
/// Falls back to stride=1 if no stride info is available.
pub(super) fn linearize_multi_index(
    array_name: &str,
    indices: &[Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext<'_>,
) -> Result<CircuitExpr, LoweringError> {
    let strides = env.strides.get(array_name);
    let n = indices.len();

    // Try full constant evaluation first — return a constant index value.
    // Note: we return Const(linear), NOT Var(element_name), because this
    // function is used for LetIndexed/WitnessHintIndexed where the index
    // must be a constant, not a variable reference to the element itself.
    let const_indices: Option<Vec<u64>> = indices.iter().map(const_eval_u64).collect();
    if let Some(vals) = const_indices {
        let mut linear: usize = 0;
        for (dim, &val) in vals.iter().enumerate() {
            let stride = if dim < n - 1 {
                strides.and_then(|s| s.get(dim)).copied().unwrap_or(1)
            } else {
                1
            };
            linear += val as usize * stride;
        }
        return Ok(CircuitExpr::Const(FieldConst::from_u64(linear as u64)));
    }

    // Build symbolic linearized expression
    let mut result: Option<CircuitExpr> = None;
    for (dim, idx_expr) in indices.iter().enumerate() {
        let lowered = lower_expr(idx_expr, env, ctx)?;
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

    // SAFETY: `indices` is non-empty (caller guarantees multi-indexed access),
    // so at least one iteration ran and `result` is Some.
    Ok(result.expect("linearize_multi_index called with empty indices"))
}

#[cfg(test)]
mod tests {
    use super::super::super::test_helpers::{make_ctx, parse_expr};
    use super::super::super::env::LoweringEnv;
    use super::*;

    #[test]
    fn assign_target_ctx_uses_placeholder_for_component_array() {
        // R1″ Phase 6 / Option D: `comp[i].sig <== expr` with the
        // memoization placeholder active should produce a target
        // whose component segment is the placeholder substring, not
        // the iter-0 numeric value. After `substitute_loop_var` runs
        // per replay iteration the substring is rewritten to the
        // concrete iter index.
        let target = parse_expr("comp[i].sig");
        let mut env = LoweringEnv::new();
        env.component_arrays.insert("comp".to_string());
        // Seed `i` in known_constants too — the placeholder check
        // must take precedence so the placeholder regime doesn't
        // depend on whether the unroll path also cleared the entry.
        env.known_constants
            .insert("i".to_string(), FieldConst::from_u64(0));

        let mut ctx = make_ctx();
        ctx.placeholder_loop_var = Some(("i".to_string(), 7));

        match extract_assign_target_ctx(&target, &ctx, &env) {
            Some(AssignTarget::Scalar(s)) => assert_eq!(s, "comp_$LV7$.sig"),
            other => panic!("expected Scalar(\"comp_$LV7$.sig\"), got {other:?}"),
        }
    }

    #[test]
    fn assign_target_ctx_no_placeholder_uses_numeric() {
        // Sanity: with no placeholder set, the legacy numeric
        // resolution path runs, producing the iter-0 name from
        // `known_constants`. Proves the new branch is gated on
        // `placeholder_loop_var` and doesn't leak into vanilla
        // lowering.
        let target = parse_expr("comp[i].sig");
        let mut env = LoweringEnv::new();
        env.component_arrays.insert("comp".to_string());
        env.known_constants
            .insert("i".to_string(), FieldConst::from_u64(3));

        let ctx = make_ctx();

        match extract_assign_target_ctx(&target, &ctx, &env) {
            Some(AssignTarget::Scalar(s)) => assert_eq!(s, "comp_3.sig"),
            other => panic!("expected Scalar(\"comp_3.sig\"), got {other:?}"),
        }
    }

    #[test]
    fn try_resolve_component_array_target_mixes_placeholder_and_literal() {
        // 2D component array `mux[0][i]`: the outer index is a literal
        // (must stay numeric), the inner is the placeholder loop var
        // (must become `$LV{t}$`). Proves the per-index check inside
        // `try_resolve_component_array_target` doesn't clobber
        // non-placeholder slots.
        let target = parse_expr("mux[0][i]");
        let mut env = LoweringEnv::new();
        env.component_arrays.insert("mux".to_string());
        env.known_constants
            .insert("i".to_string(), FieldConst::from_u64(0));

        let mut ctx = make_ctx();
        ctx.placeholder_loop_var = Some(("i".to_string(), 7));

        let resolved = try_resolve_component_array_target(&target, &env, &ctx);
        assert_eq!(resolved.as_deref(), Some("mux_0_$LV7$"));
    }
}
