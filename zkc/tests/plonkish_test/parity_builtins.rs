use super::*;

// ============================================================================
// Parity tests: builtins (from r1cs_builtins_test.rs)
// ============================================================================

#[test]
fn test_plonkish_poseidon_with_expression_args() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(3);
    let b = FieldElement::from_u64(5);
    let c = FieldElement::from_u64(2);
    let d = FieldElement::from_u64(4);
    let expected = poseidon_hash(&params, a.add(&b), c.mul(&d));

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), expected);
    inputs.insert("a".to_string(), a);
    inputs.insert("b".to_string(), b);
    inputs.insert("c".to_string(), c);
    inputs.insert("d".to_string(), d);

    compile_source(
        "assert_eq(poseidon(a + b, c * d), out)",
        &["out"],
        &["a", "b", "c", "d"],
        &inputs,
    );
}

#[test]
fn test_plonkish_poseidon_constant_arg() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let a = FieldElement::from_u64(42);
    let five = FieldElement::from_u64(5);
    let expected = poseidon_hash(&params, five, a);

    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), expected);
    inputs.insert("a".to_string(), a);

    compile_source("assert_eq(poseidon(5, a), out)", &["out"], &["a"], &inputs);
}

#[test]
fn test_plonkish_mux_selects_first() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));

    compile_source(
        "assert_eq(mux(flag, a, b), out)",
        &["out"],
        &["flag", "a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_mux_selects_second() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(99));
    inputs.insert("flag".to_string(), FieldElement::ZERO);
    inputs.insert("a".to_string(), FieldElement::from_u64(42));
    inputs.insert("b".to_string(), FieldElement::from_u64(99));

    compile_source(
        "assert_eq(mux(flag, a, b), out)",
        &["out"],
        &["flag", "a", "b"],
        &inputs,
    );
}

#[test]
fn test_plonkish_mux_complex_branches() {
    // mux(flag, a * b, c + d) — flag=1 → a*b=42
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("flag".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));
    inputs.insert("c".to_string(), FieldElement::from_u64(10));
    inputs.insert("d".to_string(), FieldElement::from_u64(20));

    compile_source(
        "assert_eq(mux(flag, a * b, c + d), out)",
        &["out"],
        &["flag", "a", "b", "c", "d"],
        &inputs,
    );
}
