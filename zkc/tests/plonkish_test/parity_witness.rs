use super::*;

// ============================================================================
// Parity tests: witness (from r1cs_witness_test.rs)
// ============================================================================

#[test]
fn test_plonkish_addition_no_ops() {
    // 3*a + 2*b = out → all linear, should produce 0 rows before assert_eq
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(4));
    inputs.insert("b".to_string(), FieldElement::from_u64(5));
    inputs.insert("out".to_string(), FieldElement::from_u64(22));

    compile_source(
        "assert_eq(3 * a + 2 * b, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_let_chain_witness() {
    // x=3 → x2=9, x3=27
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::from_u64(27));

    compile_source(
        "let x2 = x * x\nlet x3 = x2 * x\nassert_eq(x3, out)",
        &["out"],
        &["x"],
        &inputs,
    );
}

#[test]
fn test_plonkish_division_witness() {
    // a=42, b=7 → a/b=6
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("out".to_string(), FieldElement::from_u64(6));

    compile_source("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_for_loop_unrolled_witness() {
    // x^5 via power operator
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(2));
    inputs.insert("out".to_string(), FieldElement::from_u64(32));

    compile_source("assert_eq(x ^ 5, out)", &["out"], &["x"], &inputs);
}
