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
fn ctx_env_lookup_precedence() {
    // param_values shadow known_constants which shadow bound_const_vars.
    use crate::lowering::context::LoweringContext;
    use crate::lowering::env::LoweringEnv;
    let prog = parse_program("template Foo() {}");
    let mut ctx = LoweringContext::from_program(&prog);
    let mut env = LoweringEnv::new();

    let p = FieldConst::from_decimal_str("11").unwrap();
    let k = FieldConst::from_decimal_str("22").unwrap();
    let b = FieldConst::from_decimal_str("33").unwrap();

    // bound_const_vars only
    env.bound_const_vars.insert("x".to_string(), b);
    let lookup = CtxEnvLookup::new(&ctx, &env);
    assert_eq!(lookup.get_var("x"), Some(BigVal::from_field_const(b)));

    // known_constants overrides bound_const_vars
    env.known_constants.insert("x".to_string(), k);
    let lookup = CtxEnvLookup::new(&ctx, &env);
    assert_eq!(lookup.get_var("x"), Some(BigVal::from_field_const(k)));

    // param_values overrides known_constants
    ctx.param_values.insert("x".to_string(), p);
    let lookup = CtxEnvLookup::new(&ctx, &env);
    assert_eq!(lookup.get_var("x"), Some(BigVal::from_field_const(p)));

    // missing identifier yields None
    assert_eq!(lookup.get_var("missing"), None);
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
    assert_eq!(
        eval_function(f, &[BigVal::from_i64(5)], &fns, 0),
        Some(BigVal::from_i64(10))
    );
    assert_eq!(
        eval_function(f, &[BigVal::ZERO], &fns, 0),
        Some(BigVal::ZERO)
    );
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
    assert_eq!(
        eval_function(f, &[BigVal::ZERO], &fns, 0),
        Some(BigVal::ZERO)
    );
    assert_eq!(
        eval_function(f, &[BigVal::ONE], &fns, 0),
        Some(BigVal::from_i64(1))
    );
    assert_eq!(
        eval_function(f, &[BigVal::from_i64(255)], &fns, 0),
        Some(BigVal::from_i64(8))
    );
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
    assert_eq!(
        eval_function(fns["factorial"], &[BigVal::from_i64(5)], &fns, 0),
        Some(BigVal::from_i64(120))
    );
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
    assert_eq!(
        eval_function(fns["abs_val"], &[BigVal::from_i64(5)], &fns, 0),
        Some(BigVal::from_i64(5))
    );
    assert_eq!(
        eval_function(fns["abs_val"], &[BigVal::from_i64(-3)], &fns, 0),
        Some(BigVal::from_i64(3))
    );
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
    assert_eq!(
        eval_function(fns["quad"], &[BigVal::from_i64(3)], &fns, 0),
        Some(BigVal::from_i64(12))
    );
}

#[test]
fn eval_ternary() {
    let prog = parse_program("function pick(a) { return a > 0 ? a : 0; }");
    let fns = extract_functions(&prog);
    assert_eq!(
        eval_function(fns["pick"], &[BigVal::from_i64(5)], &fns, 0),
        Some(BigVal::from_i64(5))
    );
    assert_eq!(
        eval_function(fns["pick"], &[BigVal::from_i64(-1)], &fns, 0),
        Some(BigVal::ZERO)
    );
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
    params.insert("maxval".to_string(), FieldConst::from_u64(255));
    let t = match &prog.definitions[1] {
        crate::ast::Definition::Template(t) => t,
        _ => panic!("expected template"),
    };
    assert_eq!(
        precompute_vars(&t.body.stmts, &params, &fns).get("nb"),
        Some(&FieldConst::from_u64(8))
    );
}

#[test]
fn eval_array_return() {
    let prog = parse_program("function get_constants() { return [10, 20, 30]; }");
    let fns = extract_functions(&prog);
    let empty_arrays: HashMap<String, EvalValue> = HashMap::new();
    let val =
        eval_function_to_value(fns["get_constants"], &[], &empty_arrays, &[], &fns, 0).unwrap();
    assert!(val.is_array());
    assert_eq!(
        val.index(0).unwrap().as_scalar(),
        Some(BigVal::from_i64(10))
    );
    assert_eq!(
        val.index(2).unwrap().as_scalar(),
        Some(BigVal::from_i64(30))
    );
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
    let empty_arrays: HashMap<String, EvalValue> = HashMap::new();
    let v1 = eval_function_to_value(
        fns["select"],
        &[BigVal::ONE],
        &empty_arrays,
        &[None],
        &fns,
        0,
    )
    .unwrap();
    assert_eq!(
        v1.index(0).unwrap().as_scalar(),
        Some(BigVal::from_i64(100))
    );
    let v2 = eval_function_to_value(
        fns["select"],
        &[BigVal::from_i64(2)],
        &empty_arrays,
        &[None],
        &fns,
        0,
    )
    .unwrap();
    assert_eq!(
        v2.index(0).unwrap().as_scalar(),
        Some(BigVal::from_i64(300))
    );
}

#[test]
fn eval_2d_array_return() {
    let prog = parse_program("function get_matrix() { return [[1, 2], [3, 4]]; }");
    let fns = extract_functions(&prog);
    let empty_arrays: HashMap<String, EvalValue> = HashMap::new();
    let val = eval_function_to_value(fns["get_matrix"], &[], &empty_arrays, &[], &fns, 0).unwrap();
    let row0 = val.index(0).unwrap();
    assert_eq!(
        row0.index(0).unwrap().as_scalar(),
        Some(BigVal::from_i64(1))
    );
    assert_eq!(
        row0.index(1).unwrap().as_scalar(),
        Some(BigVal::from_i64(2))
    );
}

#[test]
fn eval_hex_in_array_preserved_as_expr() {
    let prog = parse_program("function get_hex() { return [0x1, 0xFFFFFFFFFFFFFFFF]; }");
    let fns = extract_functions(&prog);
    let empty_arrays: HashMap<String, EvalValue> = HashMap::new();
    let val = eval_function_to_value(fns["get_hex"], &[], &empty_arrays, &[], &fns, 0).unwrap();
    assert_eq!(val.index(0).unwrap().as_scalar(), Some(BigVal::from_i64(1)));
    // With BigVal, 0xFFFFFFFFFFFFFFFF fits as a positive 256-bit value now
    let second = val.index(1).unwrap().as_scalar().unwrap();
    assert_eq!(second.to_u64(), Some(u64::MAX));
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
    params.insert("n".to_string(), FieldConst::from_u64(1));
    let t = match &prog.definitions[1] {
        crate::ast::Definition::Template(t) => t,
        _ => panic!("expected template"),
    };
    let arrays = precompute_array_vars(&t.body.stmts, &params, &fns);
    assert_eq!(
        arrays["C"].index(0).unwrap().as_scalar(),
        Some(BigVal::from_i64(10))
    );
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
    params.insert("nInputs".to_string(), FieldConst::from_u64(2));
    let t = match &prog.definitions[0] {
        crate::ast::Definition::Template(t) => t,
        _ => panic!("expected template"),
    };
    let result = precompute_all(&t.body.stmts, &params, &fns);
    assert_eq!(result.scalars.get("t"), Some(&FieldConst::from_u64(3)));
    assert_eq!(
        result.scalars.get("nRoundsP"),
        Some(&FieldConst::from_u64(57))
    );
}

#[test]
fn const_eval_with_arrays_index() {
    let mut params = HashMap::new();
    params.insert("t".to_string(), FieldConst::from_u64(3));
    let mut arrays = HashMap::new();
    arrays.insert(
        "ROUNDS".to_string(),
        EvalValue::Array(vec![
            EvalValue::Scalar(BigVal::from_i64(56)),
            EvalValue::Scalar(BigVal::from_i64(57)),
            EvalValue::Scalar(BigVal::from_i64(56)),
            EvalValue::Scalar(BigVal::from_i64(60)),
        ]),
    );
    let expr = parse_expr("ROUNDS[t - 2]");
    let fns = HashMap::new();
    assert_eq!(
        precompute::const_eval_with_arrays(&expr, &params, &arrays, &fns),
        Some(FieldConst::from_u64(57))
    );
}

#[test]
fn eval_shift_left_128() {
    // The critical bug fix: (1 << 128) - 1 must produce 2^128 - 1
    let prog = parse_program(
        r#"
        function get_b() {
            var b = (1 << 128) - 1;
            return b;
        }
        "#,
    );
    let fns = extract_functions(&prog);
    let result = eval_function(fns["get_b"], &[], &fns, 0).unwrap();
    // 2^128 - 1 = [u64::MAX, u64::MAX, 0, 0]
    assert_eq!(result.0, [u64::MAX, u64::MAX, 0, 0]);
    assert!(result.to_u64().is_none()); // doesn't fit in u64
    assert!(!result.is_negative());
}
