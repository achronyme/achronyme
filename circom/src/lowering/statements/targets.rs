//! Assignment target resolution.
//!
//! Parses and resolves the left-hand side of signal/variable assignments:
//! simple identifiers, dot access (component signals), array indexing,
//! and multi-dimensional array access with stride linearization.

use std::collections::HashMap;

use ir::prove_ir::types::{CircuitBinOp, CircuitExpr, FieldConst};

use crate::ast::Expr;

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::utils::{const_eval_u64, extract_ident_name};

/// Describes the target of a signal assignment.
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
    // Evaluate using BigVal to detect negative values
    let vars = super::super::utils::fc_map_to_bigval(known_constants);
    let empty_fns = HashMap::new();
    let result = super::super::utils::eval_expr(expr, &vars, &empty_fns, 0)?;
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
    // Combine known_constants + param_values for full resolution
    let all_constants = ctx.all_constants(env);
    // Unwrap Index chain to find base name and indices
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
                    let idx = resolve_const_index(idx_expr, &all_constants)?;
                    comp_name = format!("{comp_name}_{idx}");
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
