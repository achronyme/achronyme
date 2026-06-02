use super::*;

// ============================================================================
// T1: IsLt/IsLe boundary tests near 2^252
// ============================================================================

/// Compute 2^n as a FieldElement.
fn pow2(n: u32) -> FieldElement {
    let mut v = FieldElement::ONE;
    for _ in 0..n {
        v = v.add(&v);
    }
    v
}

#[test]
fn test_plonkish_is_lt_boundary_adjacent_at_max() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let almost = max.sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), almost);
    inputs.insert("b".to_string(), max);
    inputs.insert("out".to_string(), FieldElement::ONE);
    compile_source(
        "let r = a < b\nassert_eq(r, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_is_lt_boundary_equal_zero() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::ZERO);
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);
    compile_source(
        "let r = a < b\nassert_eq(r, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_is_lt_boundary_zero_vs_max() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::ZERO);
    inputs.insert("b".to_string(), max);
    inputs.insert("out".to_string(), FieldElement::ONE);
    compile_source(
        "let r = a < b\nassert_eq(r, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_is_lt_boundary_max_vs_zero() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), max);
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), FieldElement::ZERO);
    compile_source(
        "let r = a < b\nassert_eq(r, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_is_le_boundary_max_equal() {
    let max = pow2(252).sub(&FieldElement::ONE);
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), max);
    inputs.insert("b".to_string(), max);
    inputs.insert("out".to_string(), FieldElement::ONE);
    compile_source(
        "let r = a <= b\nassert_eq(r, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );
}

// ============================================================================
// T3: Plonkish boolean enforcement — flag=2 must fail
// ============================================================================

#[test]
fn test_plonkish_mux_non_boolean_flag_rejected() {
    // mux with cond=2 (not boolean) must fail boolean enforcement
    let source = r#"
        let r = mux(c, a, b)
        assert_eq(r, out)
    "#;
    let program =
        ir::IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["c", "a", "b"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("c".to_string(), FieldElement::from_u64(2)); // NOT boolean
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));
    // mux(2, 10, 20) = 2*(10-20)+20 = 2*(-10)+20 = 0 in honest computation
    // but the boolean enforcement c*(1-c)=0 → 2*(1-2)=2*(-1)=-2 ≠ 0
    inputs.insert("out".to_string(), FieldElement::ZERO);

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "mux with flag=2 must fail boolean enforcement in Plonkish"
    );
}

#[test]
fn test_plonkish_assert_non_boolean_rejected() {
    // assert(x) with x=2 must fail boolean enforcement
    let source = "assert(x)";
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["x"]).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(2)); // NOT boolean

    wg.generate(&inputs, &mut compiler.system.assignments)
        .unwrap();
    assert!(
        compiler.system.verify().is_err(),
        "assert(2) must fail boolean enforcement in Plonkish"
    );
}

// ============================================================================
// M1: IsLt/IsLe bounded-input optimization tests (Plonkish)
// ============================================================================

/// Helper: compile source, return row count (proxy for circuit size).
fn plonkish_row_count(source: &str, public: &[&str], witness: &[&str]) -> usize {
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, public, witness).unwrap();
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    compiler.num_circuit_rows()
}

#[test]
fn plonkish_is_lt_fewer_rows_with_prior_range_check() {
    let full = plonkish_row_count("assert(a < b)", &["a"], &["b"]);
    let opt = plonkish_row_count(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
        &["a"],
        &["b"],
    );
    assert!(opt < full, "bounded should use fewer rows: {opt} vs {full}");
}

#[test]
fn plonkish_is_lt_bounded_correct() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(100));
    inputs.insert("b".to_string(), FieldElement::from_u64(200));
    compile_source(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
        &["a"],
        &["b"],
        &inputs,
    );
}

#[test]
fn plonkish_is_le_bounded_equal() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(42));
    compile_source(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a <= b)",
        &["a"],
        &["b"],
        &inputs,
    );
}

#[test]
fn plonkish_is_lt_bounded_max_values() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(254));
    inputs.insert("b".to_string(), FieldElement::from_u64(255));
    compile_source(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
        &["a"],
        &["b"],
        &inputs,
    );
}
