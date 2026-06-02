use super::*;

// ============================================================================
// Boolean / comparison operators — IR → R1CS E2E
// ============================================================================

#[test]
fn ir_is_eq_true() {
    // x == y where x=5, y=5 → result=1, assert that
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("x", 5), ("y", 5)], source);
}

#[test]
fn ir_is_eq_false() {
    let source = "let eq = x == y\nassert_eq(eq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("x", 5), ("y", 10)], source);
}

#[test]
fn ir_is_neq() {
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("x", 5), ("y", 10)], source);
}

#[test]
fn ir_is_neq_false() {
    let source = "let neq = x != y\nassert_eq(neq, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("x", 7), ("y", 7)], source);
}

#[test]
fn ir_not_false() {
    let source = "let r = !x\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("x", 0)], source);
}

#[test]
fn ir_not_true() {
    let source = "let r = !x\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("x", 1)], source);
}

#[test]
fn ir_and_true() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("a", 1), ("b", 1)], source);
}

#[test]
fn ir_and_false() {
    let source = "let r = a && b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("a", 1), ("b", 0)], source);
}

#[test]
fn ir_or_true() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 1)], &[("a", 0), ("b", 1)], source);
}

#[test]
fn ir_or_false() {
    let source = "let r = a || b\nassert_eq(r, expected)";
    ir_pipeline_optimized_verify(&[("expected", 0)], &[("a", 0), ("b", 0)], source);
}

#[test]
fn ir_assert_pass() {
    // assert(true) should produce constraints that verify
    let source = "assert(flag)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["flag"];
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("flag".into(), FieldElement::ONE);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(1) should verify");
}

#[test]
fn ir_assert_eq_via_operators() {
    // assert(x == y) should work as a constraint
    let source = "assert(x == y)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["x", "y"];
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".into(), FieldElement::from_u64(42));
    inputs.insert("y".into(), FieldElement::from_u64(42));

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("assert(42 == 42) should verify");
}

#[test]
fn ir_assert_not_false() {
    // assert(!flag) where flag=0 → should pass
    let source = "assert(!flag)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["flag"];
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("flag".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).expect("assert(!0) should verify");
}

#[test]
fn ir_assert_and() {
    // assert(a && b) where a=1, b=1
    let source = "assert(a && b)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["a", "b"];
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::ONE);
    inputs.insert("b".into(), FieldElement::ONE);

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("assert(1 && 1) should verify");
}

#[test]
fn ir_assert_or() {
    // assert(a || b) where a=0, b=1
    let source = "assert(a || b)";
    let pub_names: Vec<&str> = vec![];
    let wit_names: Vec<&str> = vec!["a", "b"];
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::ZERO);
    inputs.insert("b".into(), FieldElement::ONE);

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("assert(0 || 1) should verify");
}

#[test]
fn ir_bool_true_false_in_circuit() {
    // true and false should be usable in circuits
    let source = "assert_eq(true, expected)";
    ir_pipeline_verify(&[("expected", 1)], &[], source);
}

#[test]
fn ir_optimized_complex() {
    // Multi-step with constants that can fold
    ir_pipeline_optimized_verify(
        &[("out", 50)],
        &[("x", 5)],
        "let a = 2 * 5\nlet b = x * a\nassert_eq(b, out)",
    );
}
