use super::*;

// ============================================================================
// L1: Poseidon hash tests for Plonkish backend
// ============================================================================

#[test]
fn test_plonkish_poseidon_single() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(1);
    let right = FieldElement::from_u64(2);
    let expected = poseidon_hash(&params, left, right);

    let mut inputs = HashMap::new();
    inputs.insert("l".to_string(), left);
    inputs.insert("r".to_string(), right);
    inputs.insert("out".to_string(), expected);

    let source = "assert_eq(poseidon(l, r), out)";
    compile_source(source, &["out"], &["l", "r"], &inputs);
}

#[test]
fn test_plonkish_poseidon_chained() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(10);
    let b = FieldElement::from_u64(20);
    let c = FieldElement::from_u64(30);
    let h1 = poseidon_hash(&params, a, b);
    let expected = poseidon_hash(&params, h1, c);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), a);
    inputs.insert("b".to_string(), b);
    inputs.insert("c".to_string(), c);
    inputs.insert("out".to_string(), expected);

    let source = r#"
        let h = poseidon(a, b)
        assert_eq(poseidon(h, c), out)
    "#;
    compile_source(source, &["out"], &["a", "b", "c"], &inputs);
}

#[test]
fn test_plonkish_poseidon_with_arithmetic() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let x = FieldElement::from_u64(5);
    let y = FieldElement::from_u64(7);
    let prod = x.mul(&y); // 35
    let expected = poseidon_hash(&params, prod, y);

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), x);
    inputs.insert("y".to_string(), y);
    inputs.insert("out".to_string(), expected);

    let source = r#"
        let p = x * y
        assert_eq(poseidon(p, y), out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}

// ============================================================================
// T7: Poseidon(0,0) through Plonkish pipeline
// ============================================================================

#[test]
fn test_plonkish_poseidon_zero_zero() {
    // T7: poseidon(0, 0) must produce the correct hash through the Plonkish pipeline
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(&params, FieldElement::ZERO, FieldElement::ZERO);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::ZERO);
    inputs.insert("b".to_string(), FieldElement::ZERO);
    inputs.insert("out".to_string(), expected);

    let source = "assert_eq(poseidon(a, b), out)";
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_plonkish_poseidon_expression_evaluating_to_zero() {
    // poseidon(a - a, b - b) should produce the same hash as poseidon(0, 0)
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(&params, FieldElement::ZERO, FieldElement::ZERO);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));
    inputs.insert("out".to_string(), expected);

    let source = "assert_eq(poseidon(a - a, b - b), out)";
    compile_source(source, &["out"], &["a", "b"], &inputs);
}
