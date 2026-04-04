//! Array evaluation helpers and reference checking.
//!
//! Provides compile-time array evaluation (for `var C[n] = POSEIDON_C(t)` patterns),
//! expansion to CircuitNode let-bindings, and AST scanning predicates that determine
//! whether a loop body references component arrays or known array values (requiring
//! lowering-time unrolling).

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitExpr, CircuitNode, FieldConst};

use crate::ast::{ElseBranch, Expr, Stmt};

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::utils::{extract_ident_name, EvalValue};

// ---------------------------------------------------------------------------
// Compile-time array evaluation
// ---------------------------------------------------------------------------

/// Try to evaluate a var initializer to a compile-time array.
///
/// Attempts compile-time evaluation for function calls that return arrays
/// (e.g. `POSEIDON_C(t)`) and for array literals whose elements are all
/// compile-time constants.  Returns `None` if the expression cannot be
/// fully evaluated.
pub(super) fn try_eval_array_init(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<EvalValue> {
    // Build a combined params map from ctx.param_values + env.known_constants
    let mut params: HashMap<String, u64> = ctx.param_values.clone();
    for (k, &v) in &env.known_constants {
        params.insert(k.clone(), v);
    }

    match expr {
        Expr::Call { callee, args, .. } => {
            let fn_name = extract_ident_name(callee)?;
            let func = *ctx.functions.get(fn_name.as_str())?;
            let val = super::super::utils::try_eval_function_call_to_value(
                func,
                args,
                &params,
                &ctx.functions,
                ctx.inline_depth,
            )?;
            // Only return array values — scalars are handled by the normal path
            if matches!(val, EvalValue::Array(_)) {
                Some(val)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Expand an [`EvalValue`] into `CircuitNode::Let` bindings.
///
/// For a 1-D array `EvalValue::Array([S(1), Expr(0xabc), …])` with base `C`:
///   → `Let { name: "C_0", value: Const(1) }`
///   → `Let { name: "C_1", value: Const(from_hex("0xabc")) }`
///   → registers `C` as an array of length N
///
/// For 2-D arrays, flattens with strides.
pub(super) fn expand_eval_value_to_nodes(
    base: &str,
    val: &EvalValue,
    nodes: &mut Vec<CircuitNode>,
    env: &mut LoweringEnv,
    span: &Option<SpanRange>,
) {
    match val {
        EvalValue::Scalar(v) => {
            nodes.push(CircuitNode::Let {
                name: base.to_string(),
                value: CircuitExpr::Const(FieldConst::from_u64(*v as u64)),
                span: span.clone(),
            });
            env.locals.insert(base.to_string());
        }
        EvalValue::Expr(expr) => {
            if let Some(fc) = expr_to_field_const(expr) {
                nodes.push(CircuitNode::Let {
                    name: base.to_string(),
                    value: CircuitExpr::Const(fc),
                    span: span.clone(),
                });
                env.locals.insert(base.to_string());
            }
        }
        EvalValue::Array(elems) => {
            // Check if this is a 2-D array (elements are arrays)
            let is_2d = elems
                .first()
                .is_some_and(|e| matches!(e, EvalValue::Array(_)));
            if is_2d {
                // 2-D: flatten with linearized indexing
                let mut flat_idx = 0;
                let row_len = elems.first().and_then(|e| e.len()).unwrap_or(0);
                for row_val in elems.iter() {
                    if let EvalValue::Array(cols) = row_val {
                        for col_val in cols.iter() {
                            let elem_name = format!("{base}_{flat_idx}");
                            emit_eval_leaf(&elem_name, col_val, nodes, env, span);
                            flat_idx += 1;
                        }
                    }
                }
                let total = elems.len() * row_len;
                env.register_array(base.to_string(), total);
                // Strides for 2-D: arr[i][j] → arr[i*cols+j]
                env.strides.insert(base.to_string(), vec![row_len]);
            } else {
                // 1-D: simple element naming
                for (i, elem) in elems.iter().enumerate() {
                    let elem_name = format!("{base}_{i}");
                    emit_eval_leaf(&elem_name, elem, nodes, env, span);
                }
                env.register_array(base.to_string(), elems.len());
            }
        }
    }
}

/// Emit a single Let node for a leaf EvalValue (Scalar or Expr).
fn emit_eval_leaf(
    name: &str,
    val: &EvalValue,
    nodes: &mut Vec<CircuitNode>,
    env: &mut LoweringEnv,
    span: &Option<SpanRange>,
) {
    let fc = match val {
        EvalValue::Scalar(v) => Some(FieldConst::from_u64(*v as u64)),
        EvalValue::Expr(expr) => expr_to_field_const(expr),
        EvalValue::Array(_) => None, // shouldn't happen at leaf level
    };
    if let Some(fc) = fc {
        nodes.push(CircuitNode::Let {
            name: name.to_string(),
            value: CircuitExpr::Const(fc),
            span: span.clone(),
        });
        env.locals.insert(name.to_string());
    }
}

/// Convert an AST expression (number or hex literal) to a `FieldConst`.
pub(super) fn expr_to_field_const(expr: &Expr) -> Option<FieldConst> {
    match expr {
        Expr::Number { value, .. } => FieldConst::from_decimal_str(value),
        Expr::HexNumber { value, .. } => FieldConst::from_hex_str(value),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// AST reference checking predicates
// ---------------------------------------------------------------------------

/// Check if any statement in the body references a component array.
///
/// Uses a conservative approach: scans ALL expressions (not just direct
/// patterns) for any identifier matching a declared component array name.
/// This catches indirect access via functions, complex indices like
/// `muls[i*n+j]`, and nested expressions.
pub(super) fn body_has_component_array_ops(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    if env.component_arrays.is_empty() {
        return false;
    }
    stmts_reference_names(stmts, &env.component_arrays)
}

/// Check if any statement in the body references a known compile-time array.
///
/// If so, the enclosing for loop must be unrolled so that array indices
/// resolve to constants at lowering time.
pub(super) fn body_references_known_arrays(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    if env.known_array_values.is_empty() {
        return false;
    }
    let array_names: HashSet<String> = env.known_array_values.keys().cloned().collect();
    stmts_reference_names(stmts, &array_names)
}

fn stmts_reference_names(stmts: &[Stmt], names: &HashSet<String>) -> bool {
    stmts.iter().any(|s| stmt_references_names(s, names))
}

fn stmt_references_names(stmt: &Stmt, names: &HashSet<String>) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_references_names(target, names) || expr_references_names(value, names)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_references_names(target, names) || expr_references_names(value, names)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_references_names(lhs, names) || expr_references_names(rhs, names)
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_references_names(condition, names)
                || stmts_reference_names(&then_body.stmts, names)
                || match else_body {
                    Some(ElseBranch::Block(b)) => stmts_reference_names(&b.stmts, names),
                    Some(ElseBranch::IfElse(s)) => stmt_references_names(s, names),
                    None => false,
                }
        }
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            stmts_reference_names(&body.stmts, names)
        }
        Stmt::Block(b) => stmts_reference_names(&b.stmts, names),
        Stmt::ComponentDecl { init, .. } => init
            .as_ref()
            .map(|e| expr_references_names(e, names))
            .unwrap_or(false),
        Stmt::Expr { expr, .. } => expr_references_names(expr, names),
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .map(|e| expr_references_names(e, names))
            .unwrap_or(false),
        _ => false,
    }
}

fn expr_references_names(expr: &Expr, names: &HashSet<String>) -> bool {
    match expr {
        Expr::Ident { name, .. } => names.contains(name),
        Expr::BinOp { lhs, rhs, .. } => {
            expr_references_names(lhs, names) || expr_references_names(rhs, names)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_references_names(operand, names),
        Expr::Index { object, index, .. } => {
            expr_references_names(object, names) || expr_references_names(index, names)
        }
        Expr::DotAccess { object, .. } => expr_references_names(object, names),
        Expr::Call { callee, args, .. } => {
            expr_references_names(callee, names)
                || args.iter().any(|a| expr_references_names(a, names))
        }
        Expr::AnonComponent {
            callee,
            template_args,
            signal_args,
            ..
        } => {
            expr_references_names(callee, names)
                || template_args
                    .iter()
                    .any(|a| expr_references_names(a, names))
                || signal_args
                    .iter()
                    .any(|a| expr_references_names(&a.value, names))
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_references_names(condition, names)
                || expr_references_names(if_true, names)
                || expr_references_names(if_false, names)
        }
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(|e| expr_references_names(e, names))
        }
        _ => false,
    }
}
