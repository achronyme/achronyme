use super::*;

// ============================================================================
// T1: IsLt/IsLe boundary tests near 2^252
// ============================================================================

#[test]
fn ir_is_lt_boundary_adjacent_at_max() {
    // a = 2^252 - 2, b = 2^252 - 1 → a < b = true
    let max = pow2(252).sub(&FieldElement::ONE); // 2^252 - 1
    let almost = max.sub(&FieldElement::ONE); // 2^252 - 2
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", almost), ("b", max)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_equal_values() {
    // a = 0, b = 0 → a < b = false (diff = 2^252 - 1, bit 252 = 0)
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", FieldElement::ZERO), ("b", FieldElement::ZERO)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_zero_vs_max() {
    // a = 0, b = 2^252 - 1 → a < b = true (maximum valid diff)
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", FieldElement::ZERO), ("b", max)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_max_vs_zero() {
    // a = 2^252 - 1, b = 0 → a < b = false
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", max), ("b", FieldElement::ZERO)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_boundary_max_equal() {
    // a = 2^252 - 1, b = 2^252 - 1 → a < b = false
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", max), ("b", max)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_boundary_max_equal() {
    // a = 2^252 - 1, b = 2^252 - 1 → a <= b = true
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", max), ("b", max)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_boundary_max_vs_zero() {
    // a = 2^252 - 1, b = 0 → a <= b = false
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", max), ("b", FieldElement::ZERO)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_boundary_zero_vs_max() {
    // a = 0, b = 2^252 - 1 → a <= b = true
    let max = pow2(252).sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", FieldElement::ZERO), ("b", max)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

// ============================================================================
// T2: Division constraint soundness vs malicious prover
// ============================================================================

#[test]
fn ir_division_malicious_witness_divisor_zero_rejected() {
    // Compile a/b, then craft a witness where b=0 and a=0, claiming result=42.
    // The constraint den * inv = 1 cannot be satisfied when den=0.
    let source = "assert_eq(a / b, out)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    // Build witness from honest generator with valid inputs to get correct size
    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut honest_inputs = HashMap::new();
    honest_inputs.insert("a".into(), FieldElement::from_u64(42));
    honest_inputs.insert("b".into(), FieldElement::from_u64(7));
    honest_inputs.insert("out".into(), FieldElement::from_u64(6));
    let mut w = gen.generate(&honest_inputs).unwrap();

    // Now corrupt: set b=0 in the witness (wire index for b)
    // Wire layout: [ONE, pub(out), wit(a), wit(b), intermediates...]
    // b is the 4th wire (index 3)
    w[3] = FieldElement::ZERO;

    assert!(
        compiler.cs.verify(&w).is_err(),
        "division with divisor=0 in witness must fail constraint verification"
    );
}

#[test]
fn ir_division_malicious_witness_forged_result_rejected() {
    // Honest computation: 42/7=6. Prover claims result=99.
    let source = "assert_eq(a / b, out)";
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &["out"], &["a", "b"]).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(42));
    inputs.insert("b".into(), FieldElement::from_u64(7));
    inputs.insert("out".into(), FieldElement::from_u64(99)); // WRONG result

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "forged division result must fail verification"
    );
}

// ============================================================================
// M1: IsLt/IsLe bounded-input optimization tests
// ============================================================================

/// Helper: compile source with given pub/wit names and return constraint count.
fn compile_constraint_count(source: &str, public: &[&str], witness: &[&str]) -> usize {
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, public, witness).unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    compiler.cs.num_constraints()
}

#[test]
fn is_lt_fewer_constraints_with_prior_range_check() {
    // Unbounded: 760 (2×253 range + 254 decomp) + 2 (assert) = 762
    let full = compile_constraint_count("assert(a < b)", &["a"], &["b"]);

    // Bounded to 8 bits: 9+9 (range_check) + 10 (9-bit decomp) + 2 (assert) = 30
    let opt = compile_constraint_count(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
        &["a"],
        &["b"],
    );

    assert!(
        opt < full,
        "bounded should use fewer constraints: {opt} vs {full}"
    );
    assert!(
        opt <= 32,
        "expected ≤32 constraints with 8-bit bounds, got {opt}"
    );
    assert!(
        full >= 760,
        "unbounded should use ~762 constraints, got {full}"
    );
}

#[test]
fn is_le_fewer_constraints_with_prior_range_check() {
    let full = compile_constraint_count("assert(a <= b)", &["a"], &["b"]);
    let opt = compile_constraint_count(
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a <= b)",
        &["a"],
        &["b"],
    );

    assert!(opt < full, "bounded should use fewer: {opt} vs {full}");
    assert!(opt <= 32, "expected ≤32 with 8-bit bounds, got {opt}");
}

#[test]
fn is_lt_asymmetric_bounds_uses_max() {
    // range_check(a, 8) + range_check(b, 16) → effective_bits = 16
    // Cost: 9 + 17 + 18 + 2 = 46
    let count = compile_constraint_count(
        "range_check(a, 8)\nrange_check(b, 16)\nassert(a < b)",
        &["a"],
        &["b"],
    );
    assert!(
        count <= 48,
        "expected ≤48 with asymmetric bounds, got {count}"
    );
}

#[test]
fn is_lt_one_bounded_falls_back_to_full() {
    // Only a is range-checked → b needs full 252-bit range check
    // Cost: 9 (range_check a) + 253 (enforce_252 b) + 254 (decomp) + 2 = 518
    let count = compile_constraint_count("range_check(a, 8)\nassert(a < b)", &["a"], &["b"]);
    // Should be less than full (saves one 252-bit range check = 253 constraints)
    let full = compile_constraint_count("assert(a < b)", &["a"], &["b"]);
    assert!(
        count < full,
        "one bounded should save one range check: {count} vs {full}"
    );
}

#[test]
fn is_lt_bounded_correct_values() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(100))],
        &[("b", FieldElement::from_u64(200))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
    );
}

#[test]
fn is_le_bounded_equal_values() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(42))],
        &[("b", FieldElement::from_u64(42))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a <= b)",
    );
}

#[test]
fn is_lt_bounded_max_values_for_bits() {
    // Both at max of 8-bit range: 254 < 255
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(254))],
        &[("b", FieldElement::from_u64(255))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
    );
}

#[test]
fn is_lt_bounded_zero_values() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(0))],
        &[("b", FieldElement::from_u64(1))],
        "range_check(a, 8)\nrange_check(b, 8)\nassert(a < b)",
    );
}

#[test]
fn is_lt_bounded_asymmetric_correct() {
    ir_only_verify_fe(
        &[("a", FieldElement::from_u64(200))],
        &[("b", FieldElement::from_u64(50000))],
        "range_check(a, 8)\nrange_check(b, 16)\nassert(a < b)",
    );
}
