//! Compile-time precomputation of template variables.
//!
//! Scans template body for `var x = <const-expr>` declarations and evaluates
//! them, including function calls that return scalars or arrays. This enables
//! signal dimension resolution (e.g., `signal output out[nbits(n)]`) and
//! known array indexing (e.g., `ROUNDS[t - 2]`).

use std::collections::HashMap;

use ir::prove_ir::types::FieldConst;

use crate::ast::{Expr, FunctionDef, Stmt};

use super::bigval::BigVal;
use super::eval::{eval_expr, eval_function, eval_function_to_value};
use super::eval_value::{EvalValue, PrecomputeResult};
use super::extract_ident_name;

/// Pre-evaluate compile-time `var` declarations from a template body.
///
/// Returns a map of scalar computed values. Used before signal layout extraction
/// so that dimensions like `signal output out[nbits(n)]` resolve correctly.
pub fn precompute_vars(
    stmts: &[Stmt],
    params: &HashMap<String, FieldConst>,
    functions: &HashMap<&str, &FunctionDef>,
) -> HashMap<String, FieldConst> {
    precompute_all(stmts, params, functions).scalars
}

/// Pre-evaluate compile-time `var` declarations that produce arrays.
///
/// Returns a map of variable name to the evaluated [`EvalValue`].
pub fn precompute_array_vars(
    stmts: &[Stmt],
    params: &HashMap<String, FieldConst>,
    functions: &HashMap<&str, &FunctionDef>,
) -> HashMap<String, EvalValue> {
    precompute_all(stmts, params, functions).arrays
}

/// Unified single-pass precomputation of both scalar and array vars.
///
/// Processes `var` declarations in order, maintaining both scalar and array
/// maps.  This allows later declarations to reference earlier ones.
pub fn precompute_all(
    stmts: &[Stmt],
    params: &HashMap<String, FieldConst>,
    functions: &HashMap<&str, &FunctionDef>,
) -> PrecomputeResult {
    let mut scalars = params.clone();
    let mut arrays: HashMap<String, EvalValue> = HashMap::new();

    for stmt in stmts {
        if let Stmt::VarDecl {
            names,
            init: Some(expr),
            ..
        } = stmt
        {
            if names.len() != 1 {
                continue;
            }
            let name = &names[0];

            // 1. Try scalar eval (with array-index support)
            if let Some(val) = const_eval_with_arrays(expr, &scalars, &arrays, functions) {
                scalars.insert(name.clone(), val);
                continue;
            }

            // 2. Try array-returning function call
            if let Expr::Call { callee, args, .. } = expr {
                if let Some(fn_name) = extract_ident_name(callee) {
                    if let Some(func) = functions.get(fn_name.as_str()) {
                        if let Some(val) =
                            try_eval_function_call_to_value(func, args, &scalars, functions, 0)
                        {
                            if val.is_array() {
                                arrays.insert(name.clone(), val);
                                continue;
                            }
                        }
                    }
                }
            }

            // 3. Try array literal
            if let Expr::ArrayLit { elements, .. } = expr {
                let vars = fc_map_to_bigval(&scalars);
                let vals: Option<Vec<EvalValue>> = elements
                    .iter()
                    .map(|e| super::eval::eval_expr_value(e, &vars, functions, 0))
                    .collect();
                if let Some(vals) = vals {
                    arrays.insert(name.clone(), EvalValue::Array(vals));
                }
            }
        }
    }

    PrecomputeResult {
        scalars: scalars
            .into_iter()
            .filter(|(k, _)| !params.contains_key(k))
            .collect(),
        arrays,
    }
}

/// Evaluate an expression to FieldConst with support for indexing into known arrays.
pub(super) fn const_eval_with_arrays(
    expr: &Expr,
    params: &HashMap<String, FieldConst>,
    arrays: &HashMap<String, EvalValue>,
    functions: &HashMap<&str, &FunctionDef>,
) -> Option<FieldConst> {
    match expr {
        Expr::Index { object, index, .. } => {
            let base_name = extract_ident_name(object)?;
            let arr = arrays.get(&base_name)?;
            let idx = const_eval_with_arrays(index, params, arrays, functions)?;
            let idx_usize = idx.to_u64()? as usize;
            let elem = arr.index(idx_usize)?;
            elem.as_scalar().map(|v| v.to_field_const())
        }
        _ => const_eval_with_functions(expr, params, functions),
    }
}

/// Evaluate a Circom expression as FieldConst with parameter substitution and
/// function call support.
pub fn const_eval_with_functions(
    expr: &Expr,
    params: &HashMap<String, FieldConst>,
    functions: &HashMap<&str, &FunctionDef>,
) -> Option<FieldConst> {
    let vars = fc_map_to_bigval(params);
    eval_expr(expr, &vars, functions, 0).map(|v| v.to_field_const())
}

/// Try to evaluate a function call at compile time (scalar result).
pub fn try_eval_function_call(
    func: &FunctionDef,
    args: &[Expr],
    params: &HashMap<String, FieldConst>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<FieldConst> {
    let vars = fc_map_to_bigval(params);
    let arg_vals: Vec<BigVal> = args
        .iter()
        .map(|a| eval_expr(a, &vars, functions, depth))
        .collect::<Option<_>>()?;
    eval_function(func, &arg_vals, functions, depth).map(|v| v.to_field_const())
}

/// Try to evaluate a function call at compile time (scalar or array result).
pub fn try_eval_function_call_to_value(
    func: &FunctionDef,
    args: &[Expr],
    params: &HashMap<String, FieldConst>,
    functions: &HashMap<&str, &FunctionDef>,
    depth: usize,
) -> Option<EvalValue> {
    let vars = fc_map_to_bigval(params);
    let arg_vals: Vec<BigVal> = args
        .iter()
        .map(|a| eval_expr(a, &vars, functions, depth))
        .collect::<Option<_>>()?;
    eval_function_to_value(func, &arg_vals, functions, depth + 1)
}

/// Evaluate a single statement in-place, updating `vars`.
pub fn try_eval_stmt_in_place(
    stmt: &Stmt,
    vars: &mut HashMap<String, BigVal>,
    functions: &HashMap<&str, &FunctionDef>,
) -> Option<()> {
    super::eval::eval_stmt(stmt, vars, functions, 0)?;
    Some(())
}

/// Evaluate an expression to a BigVal value.
pub fn try_eval_expr(
    expr: &Expr,
    vars: &HashMap<String, BigVal>,
    functions: &HashMap<&str, &FunctionDef>,
) -> Option<BigVal> {
    eval_expr(expr, vars, functions, 0)
}

/// Convert a FieldConst parameter map to BigVal for the evaluator.
pub fn fc_map_to_bigval(params: &HashMap<String, FieldConst>) -> HashMap<String, BigVal> {
    params
        .iter()
        .map(|(k, &v)| (k.clone(), BigVal::from_field_const(v)))
        .collect()
}
