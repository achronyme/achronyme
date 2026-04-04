//! Shared lowering utilities.
//!
//! Helper functions used across multiple lowering modules (signals,
//! expressions, statements). These operate on the Circom AST and
//! don't depend on ProveIR types.

mod eval;
pub mod eval_value;
mod precompute;

use std::collections::HashMap;

use crate::ast::Expr;

// Re-export public API — some are used by sibling lowering modules, some by lib.rs/template.rs
#[allow(unused_imports)]
pub use eval::{eval_function, eval_function_to_value};
#[allow(unused_imports)]
pub use eval_value::{EvalValue, PrecomputeResult};
#[allow(unused_imports)]
pub use precompute::{
    const_eval_with_functions, precompute_all, precompute_array_vars, precompute_vars,
    try_eval_expr_i64, try_eval_function_call, try_eval_function_call_to_value,
    try_eval_stmt_in_place,
};

/// Extract a simple identifier name from an expression.
///
/// Returns `Some("x")` for `Expr::Ident { name: "x" }`, `None` for
/// anything more complex (index, dot access, etc.).
pub fn extract_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Try to evaluate a Circom AST expression as a constant u64.
///
/// Used for array dimensions, loop bounds, and power exponents that must
/// be compile-time constants.
pub fn const_eval_u64(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

/// Evaluate a Circom expression as u64 by substituting known parameter values.
///
/// Like `const_eval_u64` but also resolves identifiers from the param map
/// and handles binary/unary operations, ternaries, and function calls.
/// Delegates to `eval_expr_i64` to avoid duplicating operator logic.
pub fn const_eval_with_params(expr: &Expr, params: &HashMap<String, u64>) -> Option<u64> {
    let vars: HashMap<String, i64> = params.iter().map(|(k, &v)| (k.clone(), v as i64)).collect();
    let empty_fns = HashMap::new();
    eval::eval_expr_i64(expr, &vars, &empty_fns, 0).map(|v| v as u64)
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{extract_functions, parse_expr, parse_program};
    use super::*;

    #[test]
    fn const_eval_decimal() {
        assert_eq!(const_eval_u64(&parse_expr("42")), Some(42));
    }

    #[test]
    fn const_eval_hex() {
        assert_eq!(const_eval_u64(&parse_expr("0x10")), Some(16));
    }

    #[test]
    fn const_eval_non_const() {
        assert_eq!(const_eval_u64(&parse_expr("a + 1")), None);
    }

    #[test]
    fn extract_ident() {
        let expr = parse_expr("foo");
        assert_eq!(extract_ident_name(&expr), Some("foo".to_string()));
    }

    #[test]
    fn extract_ident_from_non_ident() {
        let expr = parse_expr("1 + 2");
        assert_eq!(extract_ident_name(&expr), None);
    }

    #[test]
    fn eval_simple_return() {
        let prog = parse_program("function double(x) { return x * 2; }");
        let fns = extract_functions(&prog);
        let f = fns["double"];
        assert_eq!(eval_function(f, &[5], &fns, 0), Some(10));
        assert_eq!(eval_function(f, &[0], &fns, 0), Some(0));
    }

    #[test]
    fn eval_nbits() {
        let prog = parse_program(
            r#"
            function nbits(a) {
                var n = 1; var r = 0;
                while (n - 1 < a) { r++; n *= 2; }
                return r;
            }
            "#,
        );
        let fns = extract_functions(&prog);
        let f = fns["nbits"];
        assert_eq!(eval_function(f, &[0], &fns, 0), Some(0));
        assert_eq!(eval_function(f, &[1], &fns, 0), Some(1));
        assert_eq!(eval_function(f, &[255], &fns, 0), Some(8));
    }

    #[test]
    fn eval_for_loop() {
        let prog = parse_program(
            r#"
            function factorial(n) {
                var result = 1;
                for (var i = 2; i <= n; i++) { result *= i; }
                return result;
            }
            "#,
        );
        let fns = extract_functions(&prog);
        assert_eq!(eval_function(fns["factorial"], &[5], &fns, 0), Some(120));
    }

    #[test]
    fn eval_if_else() {
        let prog = parse_program(
            r#"
            function abs_val(x) {
                if (x < 0) { return 0 - x; } else { return x; }
            }
            "#,
        );
        let fns = extract_functions(&prog);
        assert_eq!(eval_function(fns["abs_val"], &[5], &fns, 0), Some(5));
        assert_eq!(eval_function(fns["abs_val"], &[-3], &fns, 0), Some(3));
    }

    #[test]
    fn eval_nested_function_call() {
        let prog = parse_program(
            r#"
            function double(x) { return x * 2; }
            function quad(x) { return double(double(x)); }
            "#,
        );
        let fns = extract_functions(&prog);
        assert_eq!(eval_function(fns["quad"], &[3], &fns, 0), Some(12));
    }

    #[test]
    fn eval_ternary() {
        let prog = parse_program("function pick(a) { return a > 0 ? a : 0; }");
        let fns = extract_functions(&prog);
        assert_eq!(eval_function(fns["pick"], &[5], &fns, 0), Some(5));
        assert_eq!(eval_function(fns["pick"], &[-1], &fns, 0), Some(0));
    }

    #[test]
    fn precompute_vars_with_function() {
        let prog = parse_program(
            r#"
            function nbits(a) {
                var n = 1; var r = 0;
                while (n - 1 < a) { r++; n *= 2; }
                return r;
            }
            template T(maxval) {
                var nb = nbits(maxval);
                signal input in; signal output out[nb];
            }
            component main {public [in]} = T(255);
            "#,
        );
        let fns = extract_functions(&prog);
        let mut params = HashMap::new();
        params.insert("maxval".to_string(), 255u64);
        let t = match &prog.definitions[1] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };
        assert_eq!(
            precompute_vars(&t.body.stmts, &params, &fns).get("nb"),
            Some(&8u64)
        );
    }

    #[test]
    fn eval_array_return() {
        let prog = parse_program("function get_constants() { return [10, 20, 30]; }");
        let fns = extract_functions(&prog);
        let val = eval_function_to_value(fns["get_constants"], &[], &fns, 0).unwrap();
        assert!(val.is_array());
        assert_eq!(val.index(0).unwrap().as_scalar(), Some(10));
        assert_eq!(val.index(2).unwrap().as_scalar(), Some(30));
    }

    #[test]
    fn eval_array_return_in_if_else() {
        let prog = parse_program(
            r#"
            function select(t) {
                if (t == 1) { return [100, 200]; }
                else if (t == 2) { return [300, 400, 500]; }
                else { return [0]; }
            }
            "#,
        );
        let fns = extract_functions(&prog);
        let v1 = eval_function_to_value(fns["select"], &[1], &fns, 0).unwrap();
        assert_eq!(v1.index(0).unwrap().as_scalar(), Some(100));
        let v2 = eval_function_to_value(fns["select"], &[2], &fns, 0).unwrap();
        assert_eq!(v2.index(0).unwrap().as_scalar(), Some(300));
    }

    #[test]
    fn eval_2d_array_return() {
        let prog = parse_program("function get_matrix() { return [[1, 2], [3, 4]]; }");
        let fns = extract_functions(&prog);
        let val = eval_function_to_value(fns["get_matrix"], &[], &fns, 0).unwrap();
        let row0 = val.index(0).unwrap();
        assert_eq!(row0.index(0).unwrap().as_scalar(), Some(1));
        assert_eq!(row0.index(1).unwrap().as_scalar(), Some(2));
    }

    #[test]
    fn eval_hex_in_array_preserved_as_expr() {
        let prog = parse_program("function get_hex() { return [0x1, 0xFFFFFFFFFFFFFFFF]; }");
        let fns = extract_functions(&prog);
        let val = eval_function_to_value(fns["get_hex"], &[], &fns, 0).unwrap();
        assert_eq!(val.index(0).unwrap().as_scalar(), Some(1));
        assert!(matches!(val.index(1).unwrap(), EvalValue::Expr(_)));
    }

    #[test]
    fn precompute_array_vars_basic() {
        let prog = parse_program(
            r#"
            function constants(t) {
                if (t == 1) { return [10, 20]; } else { return [30, 40]; }
            }
            template T(n) { var C[2] = constants(n); signal input in; signal output out; }
            component main {public [in]} = T(1);
            "#,
        );
        let fns = extract_functions(&prog);
        let mut params = HashMap::new();
        params.insert("n".to_string(), 1u64);
        let t = match &prog.definitions[1] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };
        let arrays = precompute_array_vars(&t.body.stmts, &params, &fns);
        assert_eq!(arrays["C"].index(0).unwrap().as_scalar(), Some(10));
    }

    #[test]
    fn precompute_all_indexed_array_as_scalar() {
        let prog = parse_program(
            r#"
            template T(nInputs) {
                var t = nInputs + 1;
                var ROUNDS[4] = [56, 57, 56, 60];
                var nRoundsP = ROUNDS[t - 2];
                signal input in; signal output out;
            }
            component main {public [in]} = T(2);
            "#,
        );
        let fns = extract_functions(&prog);
        let mut params = HashMap::new();
        params.insert("nInputs".to_string(), 2u64);
        let t = match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };
        let result = precompute_all(&t.body.stmts, &params, &fns);
        assert_eq!(result.scalars.get("t"), Some(&3u64));
        assert_eq!(result.scalars.get("nRoundsP"), Some(&57u64));
    }

    #[test]
    fn const_eval_with_arrays_index() {
        let mut params = HashMap::new();
        params.insert("t".to_string(), 3u64);
        let mut arrays = HashMap::new();
        arrays.insert(
            "ROUNDS".to_string(),
            EvalValue::Array(vec![
                EvalValue::Scalar(56),
                EvalValue::Scalar(57),
                EvalValue::Scalar(56),
                EvalValue::Scalar(60),
            ]),
        );
        let expr = parse_expr("ROUNDS[t - 2]");
        let fns = HashMap::new();
        assert_eq!(
            precompute::const_eval_with_arrays(&expr, &params, &arrays, &fns),
            Some(57)
        );
    }
}
