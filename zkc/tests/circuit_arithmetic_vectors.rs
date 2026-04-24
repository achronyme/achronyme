//! Phase I — Circuit-Level Arithmetic Vectors
//!
//! Tests IR compilation + R1CS constraint generation + witness verification
//! for field arithmetic operations with boundary values.
//! Verifies that the full pipeline (source → IR → optimize → R1CS → verify) is correct.

use std::collections::HashMap;

use zkc::r1cs_backend::R1CSCompiler;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

/// Compile a circuit source, inject inputs, generate witness, and verify.
/// Returns the number of constraints generated.
fn compile_and_verify(source: &str, inputs: &[(&str, FieldElement)]) -> usize {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);

    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();

    let witness = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("R1CS compilation failed");

    compiler
        .cs
        .verify(&witness)
        .expect("R1CS witness verification failed");

    compiler.cs.num_constraints()
}

/// Compile and verify, expecting failure at verification.
fn compile_expect_fail(source: &str, inputs: &[(&str, FieldElement)]) {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);

    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();

    let result = compiler.compile_ir_with_witness(&program, &input_map);

    if let Ok(witness) = result {
        let verify = compiler.cs.verify(&witness);
        assert!(
            verify.is_err(),
            "expected verification failure but it passed"
        );
    }
    // If compilation itself failed, that's also acceptable
}

// ============================================================================
// Basic arithmetic circuits — addition
// ============================================================================

#[test]
fn circuit_add_simple() {
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a + b, out)",
        &[("a", fe(6)), ("b", fe(7)), ("out", fe(13))],
    );
}

#[test]
fn circuit_add_zero_identity() {
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a + 0, out)",
        &[("a", fe(42)), ("out", fe(42))],
    );
}

#[test]
fn circuit_add_overflow() {
    // (p-1) + 1 = 0 in the field
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a + 1, out)",
        &[("a", p_minus_1), ("out", fe(0))],
    );
}

#[test]
fn circuit_add_large_values() {
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    let p_minus_2 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495615");
    // (p-1) + (p-1) = p - 2
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a + b, out)",
        &[("a", p_minus_1), ("b", p_minus_1), ("out", p_minus_2)],
    );
}

// ============================================================================
// Basic arithmetic circuits — subtraction
// ============================================================================

#[test]
fn circuit_sub_simple() {
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a - b, out)",
        &[("a", fe(10)), ("b", fe(3)), ("out", fe(7))],
    );
}

#[test]
fn circuit_sub_underflow() {
    // 0 - 1 = p - 1 in the field
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_and_verify(
        "public out\nwitness a\nassert_eq(0 - a, out)",
        &[("a", fe(1)), ("out", p_minus_1)],
    );
}

#[test]
fn circuit_sub_self_is_zero() {
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a - a, out)",
        &[("a", fe(42)), ("out", fe(0))],
    );
}

// ============================================================================
// Basic arithmetic circuits — multiplication
// ============================================================================

#[test]
fn circuit_mul_simple() {
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a * b, out)",
        &[("a", fe(6)), ("b", fe(7)), ("out", fe(42))],
    );
}

#[test]
fn circuit_mul_zero_absorbing() {
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a * 0, out)",
        &[("a", fe(42)), ("out", fe(0))],
    );
}

#[test]
fn circuit_mul_one_identity() {
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a * 1, out)",
        &[("a", fe(42)), ("out", fe(42))],
    );
}

#[test]
fn circuit_mul_neg1_neg1() {
    // (-1) * (-1) = 1
    let neg1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a * b, out)",
        &[("a", neg1), ("b", neg1), ("out", fe(1))],
    );
}

// ============================================================================
// Basic arithmetic circuits — division (modular inverse)
// ============================================================================

#[test]
fn circuit_div_simple() {
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a / b, out)",
        &[("a", fe(42)), ("b", fe(7)), ("out", fe(6))],
    );
}

#[test]
fn circuit_div_self_is_one() {
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a / a, out)",
        &[("a", fe(42)), ("out", fe(1))],
    );
}

#[test]
fn circuit_div_by_one() {
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a / 1, out)",
        &[("a", fe(42)), ("out", fe(42))],
    );
}

// ============================================================================
// Negation in circuits
// ============================================================================

#[test]
fn circuit_neg_double() {
    // -(-a) == a
    compile_and_verify(
        "public out\nwitness a\nlet neg_a = 0 - a\nassert_eq(0 - neg_a, out)",
        &[("a", fe(42)), ("out", fe(42))],
    );
}

// ============================================================================
// Wrong witness — must fail verification
// ============================================================================

#[test]
fn circuit_wrong_add_fails() {
    compile_expect_fail(
        "public out\nwitness a\nwitness b\nassert_eq(a + b, out)",
        &[("a", fe(6)), ("b", fe(7)), ("out", fe(14))], // 6+7=13, not 14
    );
}

#[test]
fn circuit_wrong_mul_fails() {
    compile_expect_fail(
        "public out\nwitness a\nwitness b\nassert_eq(a * b, out)",
        &[("a", fe(6)), ("b", fe(7)), ("out", fe(43))], // 6*7=42, not 43
    );
}

// ============================================================================
// Poseidon in circuit — end to end
// ============================================================================

#[test]
fn circuit_poseidon_e2e() {
    let expected_hash =
        fe_str("7853200120776062878684798364095072458815029376092732009249414926327459813530");
    compile_and_verify(
        "public expected\nwitness a\nwitness b\nlet h = poseidon(a, b)\nassert_eq(h, expected)",
        &[("a", fe(1)), ("b", fe(2)), ("expected", expected_hash)],
    );
}

#[test]
fn circuit_poseidon_zero_inputs() {
    let p = constraints::poseidon::PoseidonParams::bn254_t3();
    let expected =
        constraints::poseidon::native::poseidon_hash(&p, FieldElement::ZERO, FieldElement::ZERO);
    compile_and_verify(
        "public expected\nwitness a\nwitness b\nlet h = poseidon(a, b)\nassert_eq(h, expected)",
        &[("a", fe(0)), ("b", fe(0)), ("expected", expected)],
    );
}

// ============================================================================
// Constraint count regression
// ============================================================================

#[test]
fn constraint_count_add() {
    let n = compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a + b, out)",
        &[("a", fe(1)), ("b", fe(2)), ("out", fe(3))],
    );
    // Addition is a linear constraint — should be minimal
    assert!(n <= 5, "add constraint count too high: {n}");
}

#[test]
fn constraint_count_mul() {
    let n = compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a * b, out)",
        &[("a", fe(3)), ("b", fe(7)), ("out", fe(21))],
    );
    // Multiplication is one quadratic constraint + assert_eq
    assert!(n <= 5, "mul constraint count too high: {n}");
}

#[test]
fn constraint_count_poseidon() {
    let p = constraints::poseidon::PoseidonParams::bn254_t3();
    let expected = constraints::poseidon::native::poseidon_hash(
        &p,
        FieldElement::from_u64(1),
        FieldElement::from_u64(2),
    );
    let n = compile_and_verify(
        "public expected\nwitness a\nwitness b\nlet h = poseidon(a, b)\nassert_eq(h, expected)",
        &[("a", fe(1)), ("b", fe(2)), ("expected", expected)],
    );
    // Poseidon should be ~362 constraints (361 + 1 assert_eq)
    assert!(
        (350..=370).contains(&n),
        "poseidon constraint count unexpected: {n}"
    );
}

// ============================================================================
// Complex expressions — constant folding verification
// ============================================================================

#[test]
fn circuit_const_fold_add() {
    // 2 + 3 should fold to 5 at compile time, no constraints for the addition
    compile_and_verify("public out\nassert_eq(2 + 3, out)", &[("out", fe(5))]);
}

#[test]
fn circuit_const_fold_mul() {
    // 6 * 7 should fold to 42
    compile_and_verify("public out\nassert_eq(6 * 7, out)", &[("out", fe(42))]);
}

#[test]
fn circuit_mixed_const_and_witness() {
    // a * 2 + 3 with a=10 → 23
    compile_and_verify(
        "public out\nwitness a\nassert_eq(a * 2 + 3, out)",
        &[("a", fe(10)), ("out", fe(23))],
    );
}

// ============================================================================
// Multiple constraints — larger circuits
// ============================================================================

#[test]
fn circuit_quadratic_equation() {
    // a^2 + b^2 == out (Pythagorean: 3^2 + 4^2 = 25)
    compile_and_verify(
        "public out\nwitness a\nwitness b\nassert_eq(a * a + b * b, out)",
        &[("a", fe(3)), ("b", fe(4)), ("out", fe(25))],
    );
}

#[test]
fn circuit_chain_of_ops() {
    // ((a + b) * c) - d == out: ((2 + 3) * 4) - 5 = 15
    compile_and_verify(
        "public out\nwitness a\nwitness b\nwitness c\nwitness d\nassert_eq((a + b) * c - d, out)",
        &[
            ("a", fe(2)),
            ("b", fe(3)),
            ("c", fe(4)),
            ("d", fe(5)),
            ("out", fe(15)),
        ],
    );
}
