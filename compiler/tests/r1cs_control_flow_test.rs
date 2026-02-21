use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::IrError;
use ir::IrLowering;
use memory::FieldElement;

/// Helper: lower source through the IR pipeline, optimize, and compile to R1CS.
/// Returns the R1CSCompiler so tests can inspect constraint counts etc.
fn ir_compile(source: &str, public: &[&str], witness: &[&str]) -> Result<R1CSCompiler, String> {
    let mut prog = IrLowering::lower_circuit(source, public, witness)
        .map_err(|e| format!("IR: {e}"))?;
    ir::passes::optimize(&mut prog);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&prog).map_err(|e| format!("R1CS: {e}"))?;
    Ok(rc)
}

/// Helper: compile source through the IR pipeline with concrete inputs,
/// generating and verifying the witness automatically.
fn ir_compile_and_verify(
    source: &str,
    public: &[(&str, u64)],
    witness: &[(&str, u64)],
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();

    let mut prog = IrLowering::lower_circuit(source, &pub_names, &wit_names)
        .expect("IR lowering failed");
    ir::passes::optimize(&mut prog);

    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness.iter()) {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }

    let mut rc = R1CSCompiler::new();
    let w = rc
        .compile_ir_with_witness(&prog, &inputs)
        .expect("compile_ir_with_witness failed");
    rc.cs
        .verify(&w)
        .expect("witness verification failed");
}

// ====================================================================
// For unrolling tests
// ====================================================================

#[test]
fn test_for_static_range_constraint_count() {
    // for i in 0..3 { let step = a * a } -> 3 mul constraints
    let rc = ir_compile("for i in 0..3 { let step = a * a }", &[], &["a"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_for_empty_range() {
    // for i in 0..0 { ... } -> 0 iterations, 0 constraints
    let rc = ir_compile("for i in 0..0 { let step = a * a }", &[], &["a"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_for_iterator_as_constant() {
    // for i in 0..3 { let x = a * i }
    // i=0: a*0 -> const_fold → Const(0), no constraint
    // i=1: a*1 -> multiply_lcs sees constant 1, scalar mul → 0 constraints
    // i=2: a*2 -> multiply_lcs sees constant 2, scalar mul → 0 constraints
    let rc = ir_compile("for i in 0..3 { let x = a * i }", &[], &["a"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0, "multiplying by constant iterator should be free");
}

#[test]
fn test_for_nested() {
    // Nested for: outer 0..2, inner 0..3, body = a * a (1 constraint)
    // Total: 2 * 3 * 1 = 6 constraints
    let rc = ir_compile(
        "for i in 0..2 { for j in 0..3 { let step = a * a } }",
        &[],
        &["a"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 6);
}

#[test]
fn test_for_integration_with_witness() {
    // Circuit: for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)
    // 3 mul inside loop + 1 mul for final a*b + 1 assert_eq = 5
    let rc = ir_compile(
        "for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 5);

    // Verify with concrete inputs: a=3, b=7, out=a*b=21
    ir_compile_and_verify(
        "for i in 0..3 { let prod = a * b }; assert_eq(a * b, out)",
        &[("out", 21)],
        &[("a", 3), ("b", 7)],
    );
}

#[test]
fn test_for_non_literal_rejected() {
    // for i in expr (not a range and not an array) -> error from IR lowering
    let err = IrLowering::lower_circuit("for i in a { let x = 1 }", &[], &["a"]).unwrap_err();
    assert!(matches!(err, IrError::UnsupportedOperation(..)));
}

// ====================================================================
// If/MUX tests
// ====================================================================

#[test]
fn test_if_else_two_constraints() {
    // if flag { a } else { b } -> 1 boolean check + 1 MUX mul = 2 constraints
    let rc = ir_compile(
        "if flag { a } else { b }",
        &[],
        &["flag", "a", "b"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_if_without_else() {
    // if flag { a } -> else defaults to 0, still 2 constraints
    let rc = ir_compile("if flag { a }", &[], &["flag", "a"]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 2);
}

#[test]
fn test_if_else_integration_flag_one() {
    // if flag { a } else { b } with flag=1 -> result should be a = 42
    let source = "let result = if flag { a } else { b }; assert_eq(result, out)";

    let rc = ir_compile(source, &["out"], &["flag", "a", "b"]).unwrap();
    // 2 (if/mux) + 1 (assert_eq) = 3
    assert_eq!(rc.cs.num_constraints(), 3);

    // flag=1, a=42, b=99 -> result = a = 42
    ir_compile_and_verify(
        source,
        &[("out", 42)],
        &[("flag", 1), ("a", 42), ("b", 99)],
    );
}

#[test]
fn test_if_else_integration_flag_zero() {
    // if flag { a } else { b } with flag=0 -> result should be b = 99
    let source = "let result = if flag { a } else { b }; assert_eq(result, out)";

    // flag=0, a=42, b=99 -> result = b = 99
    ir_compile_and_verify(
        source,
        &[("out", 99)],
        &[("flag", 0), ("a", 42), ("b", 99)],
    );
}

#[test]
fn test_if_else_boolean_enforcement() {
    // if flag { a } else { b } with flag=2 -> boolean check should fail
    //
    // We compile the circuit without the IR evaluator (which would reject
    // flag=2 at evaluation time), then generate the witness with a malicious
    // flag=2 value to verify the constraint system catches it.
    let source = "let result = if flag { a } else { b }; assert_eq(result, out)";

    let mut prog = IrLowering::lower_circuit(source, &["out"], &["flag", "a", "b"]).unwrap();
    ir::passes::optimize(&mut prog);

    // Compile constraints only (no evaluation)
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&prog).unwrap();

    // Generate witness with flag=2 (invalid boolean)
    let a_val = FieldElement::from_u64(42);
    let b_val = FieldElement::from_u64(99);
    let flag_val = FieldElement::from_u64(2);
    // result = flag * (a - b) + b = 2 * (42 - 99) + 99 = 2*(-57) + 99 = -15
    let diff = a_val.sub(&b_val);
    let mux_prod = flag_val.mul(&diff);
    let result = mux_prod.add(&b_val);

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), result);
    inputs.insert("flag".to_string(), flag_val);
    inputs.insert("a".to_string(), a_val);
    inputs.insert("b".to_string(), b_val);

    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inputs).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "flag=2 should fail boolean enforcement"
    );
}

#[test]
fn test_if_nested_mux() {
    // if c1 { a } else { if c2 { b } else { c } }
    // Outer: 2 constraints, inner: 2 constraints -> 4 total
    let rc = ir_compile(
        "if c1 { a } else { if c2 { b } else { c } }",
        &[],
        &["c1", "c2", "a", "b", "c"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 4);
}

#[test]
fn test_if_with_arithmetic_branches() {
    // if flag { a * b } else { c + d }
    // a*b = 1 mul constraint (in then branch)
    // c+d = 0 constraints (in else branch)
    // MUX = 2 constraints (boolean + mul)
    // Total = 3
    let rc = ir_compile(
        "if flag { a * b } else { c + d }",
        &[],
        &["flag", "a", "b", "c", "d"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 3);
}

#[test]
fn test_if_else_if_chain() {
    // if c1 { a } else if c2 { b } else { c }
    // This parses as: if c1 { a } else { if c2 { b } else { c } }
    // Each if level = 2 constraints -> 4 total
    let rc = ir_compile(
        "if c1 { a } else if c2 { b } else { c }",
        &[],
        &["c1", "c2", "a", "b", "c"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 4);
}

// ====================================================================
// Rejection tests
// ====================================================================

#[test]
fn test_while_rejected() {
    let err = IrLowering::lower_circuit("while x { let a = 1 }", &[], &["x"]).unwrap_err();
    assert!(matches!(err, IrError::UnboundedLoop(..)));
}

#[test]
fn test_forever_rejected() {
    let err = IrLowering::lower_circuit("forever { let a = 1 }", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::UnboundedLoop(..)));
}

#[test]
fn test_fn_declaration_accepted() {
    // fn_decl is supported in the IR lowering path (it stores function definitions
    // in the fn_table for inlining at call sites). This should succeed.
    let rc = ir_compile("fn foo() { 1 }", &[], &[]).unwrap();
    assert_eq!(rc.cs.num_constraints(), 0);
}

#[test]
fn test_break_rejected() {
    // break inside a for loop -- still rejected in circuits
    let err = IrLowering::lower_circuit("for i in 0..3 { break }", &[], &[]).unwrap_err();
    assert!(matches!(err, IrError::UnsupportedOperation(..)));
}

// ====================================================================
// Integration tests: control flow + witness verification
// ====================================================================

#[test]
fn test_for_with_if_inside() {
    // for i in 0..2 { if flag { a * b } else { c } }
    // Each iteration: 1 mul (a*b) + 2 MUX constraints = 3
    // 2 iterations -> 6 constraints
    let rc = ir_compile(
        "for i in 0..2 { if flag { a * b } else { c } }",
        &[],
        &["flag", "a", "b", "c"],
    ).unwrap();
    assert_eq!(rc.cs.num_constraints(), 6);
}

#[test]
fn test_full_circuit_with_control_flow() {
    // Realistic circuit: compute x^2 conditionally, accumulate in a loop
    // for i in 0..2 { let step = x * x }
    // let result = if flag { x * x } else { x + 1 }
    // assert_eq(result, out)
    let source =
        "for i in 0..2 { let step = x * x }; \
         let result = if flag { x * x } else { x + 1 }; \
         assert_eq(result, out)";

    let rc = ir_compile(source, &["out"], &["x", "flag"]).unwrap();

    // Loop: 2 * 1 = 2 constraints (x*x each iteration)
    // If: 1 (x*x in then) + 2 (boolean + MUX) = 3 constraints
    // assert_eq: 1 constraint
    // Total: 2 + 3 + 1 = 6
    assert_eq!(rc.cs.num_constraints(), 6);

    // flag=1, x=5: result = x*x = 25
    ir_compile_and_verify(source, &[("out", 25)], &[("x", 5), ("flag", 1)]);

    // flag=0, x=5: result = x+1 = 6
    ir_compile_and_verify(source, &[("out", 6)], &[("x", 5), ("flag", 0)]);
}
