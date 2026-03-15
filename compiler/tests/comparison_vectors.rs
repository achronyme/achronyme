//! Phase II — Comparison Operations Vectors (R1CS, BN254 Fr)
//!
//! Industry-sourced test vectors for IsEq, IsNeq, IsLt, IsLe instructions
//! with boundary value analysis and constraint count benchmarking.
//!
//! Industry sources:
//!   - circomlib comparators.circom:  https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom
//!     LessThan, GreaterThan, IsEqual gadgets for R1CS. (GPL-3.0)
//!   - Constraint-Efficient Comparators via Weighted Accumulation (MDPI):
//!     https://www.mdpi.com/2227-7390/13/24/3959  [ref 32]
//!     Optimal Num2Bits decomposition (~65 constraints for 64-bit IsLt).
//!   - Noir stdlib field/mod.nr:     https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!     lt, lte comparison operations on BN254 Fr. (MIT/Apache-2.0) [ref 44]
//!   - gnark std comparators:        https://github.com/Consensys/gnark
//!     api.Cmp() — ~65 constraints for 64-bit comparison. (Apache-2.0) [ref 14]
//!   - 0xPARC zk-bug-tracker:        https://github.com/0xPARC/zk-bug-tracker
//!     Dark Forest LessThan vulnerability: omitted bit length restriction allowed
//!     overflow attacks with forged proofs. [ref 33]
//!
//! Key benchmark (Table 1 from research document):
//!   - IsLt 64-bit: Circom ~65, Gnark ~65, Achronyme ~760 constraints
//!   - This 12× gap is weakness D7 (STRATEGY.md), tracked by constraint count tests below.
//!
//! Reference: "Análisis Integral de Vectores de Prueba y Evaluación de Rendimiento
//! para Entornos de Compilación de Conocimiento Cero" (2026), §Vulnerabilidades y
//! Restricciones en Desigualdades Lógicas.
//!
//! License compatibility: circomlib GPL-3.0, Noir MIT/Apache-2.0, gnark Apache-2.0.

use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Constants — BN254 Fr boundary values
// ============================================================================

/// p - 1: largest element in the field (equivalent to -1)
const P_MINUS_1: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";
/// p - 2: second-largest element
const P_MINUS_2: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495615";

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

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
}

/// Macro for parameterized comparison tests.
macro_rules! comparison_tests {
    ($(($name:ident, $source:expr, $inputs:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify($source, $inputs);
            }
        )*
    };
}

// ============================================================================
// IsEq — equality check
// Source: circomlib comparators.circom IsEqual template.
// Uses IsZero gadget: diff * inv = 1 - eq; diff * eq = 0 (2 constraints).
// ============================================================================

comparison_tests! {
    // Basic equality
    (is_eq_zero_zero,   "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(0)), ("b", fe(0)), ("out", fe(1))]),
    (is_eq_one_one,     "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(1)), ("b", fe(1)), ("out", fe(1))]),
    (is_eq_42_42,       "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(42)), ("b", fe(42)), ("out", fe(1))]),
    (is_eq_zero_one,    "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(0)), ("b", fe(1)), ("out", fe(0))]),
    (is_eq_one_zero,    "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(1)), ("b", fe(0)), ("out", fe(0))]),
    (is_eq_42_43,       "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(42)), ("b", fe(43)), ("out", fe(0))]),

    // Boundary values
    (is_eq_p_minus_1_self,  "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe_str(P_MINUS_1)), ("b", fe_str(P_MINUS_1)), ("out", fe(1))]),
    (is_eq_p_minus_1_vs_0,  "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe_str(P_MINUS_1)), ("b", fe(0)), ("out", fe(0))]),
    (is_eq_p_minus_1_vs_p_minus_2, "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe_str(P_MINUS_1)), ("b", fe_str(P_MINUS_2)), ("out", fe(0))]),
    (is_eq_large_equal,     "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(1_000_000_007)), ("b", fe(1_000_000_007)), ("out", fe(1))]),
    (is_eq_large_unequal,   "witness a\nwitness b\npublic out\nassert_eq(a == b, out)", &[("a", fe(1_000_000_007)), ("b", fe(1_000_000_009)), ("out", fe(0))]),
}

// ============================================================================
// IsNeq — not-equal check
// Source: circomlib comparators.circom IsEqual + NOT.
// Implemented as 1 - IsEq (2 constraints for IsZero gadget).
// ============================================================================

comparison_tests! {
    (is_neq_zero_zero,     "witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe(0)), ("b", fe(0)), ("out", fe(0))]),
    (is_neq_zero_one,      "witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe(0)), ("b", fe(1)), ("out", fe(1))]),
    (is_neq_one_zero,      "witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe(1)), ("b", fe(0)), ("out", fe(1))]),
    (is_neq_42_42,         "witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe(42)), ("b", fe(42)), ("out", fe(0))]),
    (is_neq_42_43,         "witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe(42)), ("b", fe(43)), ("out", fe(1))]),
    (is_neq_p_minus_1_0,   "witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe_str(P_MINUS_1)), ("b", fe(0)), ("out", fe(1))]),
    (is_neq_p_minus_1_self,"witness a\nwitness b\npublic out\nassert_eq(a != b, out)", &[("a", fe_str(P_MINUS_1)), ("b", fe_str(P_MINUS_1)), ("out", fe(0))]),
}

// ============================================================================
// IsEq + IsNeq complementarity: (a == b) + (a != b) == 1
// Source: fundamental Boolean complement property.
// ============================================================================

#[test]
fn eq_neq_complement_equal() {
    // When a == b, (a==b)=1 and (a!=b)=0, sum=1
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a == b) + (a != b), out)",
        &[("a", fe(42)), ("b", fe(42)), ("out", fe(1))],
    );
}

#[test]
fn eq_neq_complement_unequal() {
    // When a != b, (a==b)=0 and (a!=b)=1, sum=1
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a == b) + (a != b), out)",
        &[("a", fe(7)), ("b", fe(13)), ("out", fe(1))],
    );
}

// ============================================================================
// IsLt — less-than check
// Source: circomlib comparators.circom LessThan template — Num2Bits decomposition.
// Without prior range_check: ~760 constraints (252-bit full decomposition).
// With prior range_check(x, n): ~(n+2) constraints (bounded decomposition).
// Industry reference: Circom ~65, Gnark ~65 for 64-bit. [ref 32, Table 1]
// ============================================================================

comparison_tests! {
    // Basic less-than (small values — unsigned integer semantics)
    (is_lt_0_1,         "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(0)), ("b", fe(1)), ("out", fe(1))]),
    (is_lt_1_0,         "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(1)), ("b", fe(0)), ("out", fe(0))]),
    (is_lt_0_0,         "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(0)), ("b", fe(0)), ("out", fe(0))]),
    (is_lt_3_5,         "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))]),
    (is_lt_5_3,         "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(5)), ("b", fe(3)), ("out", fe(0))]),
    (is_lt_5_5,         "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(5)), ("b", fe(5)), ("out", fe(0))]),
    (is_lt_255_256,     "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(255)), ("b", fe(256)), ("out", fe(1))]),
    (is_lt_256_255,     "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(256)), ("b", fe(255)), ("out", fe(0))]),
    (is_lt_consecutive, "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(999)), ("b", fe(1000)), ("out", fe(1))]),

    // Large values (still within u64)
    (is_lt_u32_max_boundary,   "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(u32::MAX as u64)), ("b", fe(u32::MAX as u64 + 1)), ("out", fe(1))]),
    (is_lt_u32_max_equal,      "witness a\nwitness b\npublic out\nassert_eq(a < b, out)", &[("a", fe(u32::MAX as u64)), ("b", fe(u32::MAX as u64)), ("out", fe(0))]),
}

// ============================================================================
// IsLe — less-or-equal check
// Source: circomlib LessEqThan — implemented as !(b < a), i.e. 1 - IsLt(b, a).
// Same constraint cost as IsLt.
// ============================================================================

comparison_tests! {
    (is_le_0_0,         "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(0)), ("b", fe(0)), ("out", fe(1))]),
    (is_le_0_1,         "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(0)), ("b", fe(1)), ("out", fe(1))]),
    (is_le_1_0,         "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(1)), ("b", fe(0)), ("out", fe(0))]),
    (is_le_5_5,         "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(5)), ("b", fe(5)), ("out", fe(1))]),
    (is_le_3_5,         "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))]),
    (is_le_5_3,         "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(5)), ("b", fe(3)), ("out", fe(0))]),
    (is_le_255_255,     "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(255)), ("b", fe(255)), ("out", fe(1))]),
    (is_le_255_256,     "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(255)), ("b", fe(256)), ("out", fe(1))]),
    (is_le_256_255,     "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)", &[("a", fe(256)), ("b", fe(255)), ("out", fe(0))]),
}

// ============================================================================
// Gt and Ge — greater-than, greater-or-equal (syntax sugar)
// Source: implemented as IsLt/IsLe with swapped operands in the IR lowering.
// ============================================================================

comparison_tests! {
    (is_gt_5_3,  "witness a\nwitness b\npublic out\nassert_eq(a > b, out)", &[("a", fe(5)), ("b", fe(3)), ("out", fe(1))]),
    (is_gt_3_5,  "witness a\nwitness b\npublic out\nassert_eq(a > b, out)", &[("a", fe(3)), ("b", fe(5)), ("out", fe(0))]),
    (is_gt_5_5,  "witness a\nwitness b\npublic out\nassert_eq(a > b, out)", &[("a", fe(5)), ("b", fe(5)), ("out", fe(0))]),
    (is_ge_5_3,  "witness a\nwitness b\npublic out\nassert_eq(a >= b, out)", &[("a", fe(5)), ("b", fe(3)), ("out", fe(1))]),
    (is_ge_3_5,  "witness a\nwitness b\npublic out\nassert_eq(a >= b, out)", &[("a", fe(3)), ("b", fe(5)), ("out", fe(0))]),
    (is_ge_5_5,  "witness a\nwitness b\npublic out\nassert_eq(a >= b, out)", &[("a", fe(5)), ("b", fe(5)), ("out", fe(1))]),
}

// ============================================================================
// IsLt + IsLe relationship: (a < b) + (a >= b) == 1
// Source: Boolean complement property applied to comparisons.
// ============================================================================

#[test]
fn lt_ge_complement_true() {
    // 3 < 5 → lt=1, ge=0, sum=1
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a >= b), out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
}

#[test]
fn lt_ge_complement_false() {
    // 5 < 3 → lt=0, ge=1, sum=1
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a >= b), out)",
        &[("a", fe(5)), ("b", fe(3)), ("out", fe(1))],
    );
}

#[test]
fn lt_ge_complement_equal() {
    // 5 < 5 → lt=0, ge=1, sum=1
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a >= b), out)",
        &[("a", fe(5)), ("b", fe(5)), ("out", fe(1))],
    );
}

// ============================================================================
// IsEq reflexivity: a == a is always 1
// Source: fundamental mathematical property.
// ============================================================================

#[test]
fn eq_reflexive_zero() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a == a, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn eq_reflexive_one() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a == a, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn eq_reflexive_large() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a == a, out)",
        &[("a", fe(999_999_999)), ("out", fe(1))],
    );
}

// ============================================================================
// IsLe reflexivity: a <= a is always 1
// ============================================================================

#[test]
fn le_reflexive_zero() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a <= a, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn le_reflexive_42() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a <= a, out)",
        &[("a", fe(42)), ("out", fe(1))],
    );
}

// ============================================================================
// IsLt irreflexivity: a < a is always 0
// ============================================================================

#[test]
fn lt_irreflexive_zero() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a < a, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn lt_irreflexive_42() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a < a, out)",
        &[("a", fe(42)), ("out", fe(0))],
    );
}

// ============================================================================
// Range-bounded comparisons — reduced constraint cost
// Source: circomlib Num2Bits optimization; when operands are range-checked
// to n bits, IsLt uses ~(n+2) constraints instead of ~760.
// This validates the compiler's range_bounds inference path.
// ============================================================================

#[test]
fn range_bounded_islt_8bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 8)\nrange_check(b, 8)\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(100)), ("b", fe(200)), ("out", fe(1))],
    );
    // With 8-bit range bounds: IsLt should be ~11 constraints
    // (9 bit decomposition + 1 sum + 1 final) + range_check overhead
    // Much less than the unbounded ~760
    assert!(
        n < 100,
        "range-bounded IsLt should be << 760 constraints, got: {n}"
    );
}

#[test]
fn range_bounded_islt_16bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 16)\nrange_check(b, 16)\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(1000)), ("b", fe(60000)), ("out", fe(1))],
    );
    assert!(
        n < 150,
        "16-bit range-bounded IsLt should be << 760, got: {n}"
    );
}

#[test]
fn range_bounded_isle_8bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 8)\nrange_check(b, 8)\npublic out\nassert_eq(a <= b, out)",
        &[("a", fe(200)), ("b", fe(200)), ("out", fe(1))],
    );
    assert!(
        n < 100,
        "range-bounded IsLe should be << 760 constraints, got: {n}"
    );
}

// ============================================================================
// Constraint count benchmarks — the core Phase II metric
// Source: Table 1 from research document.
// Circom comparators.circom: ~65 constraints for 64-bit IsLt
// Gnark std: ~65 constraints for 64-bit IsLt
// Achronyme (unbounded): ~760 constraints — weakness D7
// ============================================================================

#[test]
fn constraint_count_iseq() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a == b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(0))],
    );
    // IsEq: 2 constraints (IsZero gadget) + 1 assert_eq = 3
    assert!(n <= 5, "IsEq constraint count too high: {n} (expected ~3)");
}

#[test]
fn constraint_count_isneq() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a != b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    // IsNeq: 2 constraints (IsZero gadget) + 1 assert_eq = 3
    assert!(n <= 5, "IsNeq constraint count too high: {n} (expected ~3)");
}

/// Constraint benchmark: IsLt without prior range check.
/// Achronyme: ~760 constraints (252-bit decomposition × 3 = ~756 + overhead).
/// Circom comparators.circom: ~65 constraints (Num2Bits optimization). [ref 32]
/// Gnark std: ~65 constraints. [ref 14]
///
/// This 12× gap is tracked as weakness D7 in STRATEGY.md.
#[test]
fn constraint_count_islt_unbounded() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    // Current: ~760 constraints for 252-bit decomposition
    // Industry target: ~65 constraints
    assert!(
        (600..=900).contains(&n),
        "IsLt unbounded constraint count unexpected: {n} (expected ~760, \
         industry target ~65 — see D7 in STRATEGY.md)"
    );
}

/// Same benchmark for IsLe (uses same bit decomposition as IsLt).
#[test]
fn constraint_count_isle_unbounded() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    assert!(
        (600..=900).contains(&n),
        "IsLe unbounded constraint count unexpected: {n} (expected ~760)"
    );
}

/// Range-bounded IsLt should dramatically reduce constraints.
/// With 8-bit bounds: ~30 constraints vs ~760 unbounded.
#[test]
fn constraint_count_islt_bounded_8bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 8)\nrange_check(b, 8)\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    // 2×9 (range_check) + ~11 (bounded IsLt) + 1 (assert_eq) = ~30
    assert!(
        n < 60,
        "bounded 8-bit IsLt should be ~30 constraints, got: {n}"
    );
}

/// Range-bounded IsLt with 64-bit bounds — target: ~67 constraints (Circom parity).
#[test]
fn constraint_count_islt_bounded_64bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 64)\nrange_check(b, 64)\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    // 2×65 (range_check) + ~66 (bounded IsLt 65 bits) + 1 (assert_eq) = ~197
    // But the key metric is the IsLt portion alone: ~66 constraints
    // Total with range_checks: should be well under 250
    assert!(
        n < 250,
        "bounded 64-bit IsLt total should be <250 constraints, got: {n}"
    );
}

/// Range-bounded IsLe with 64-bit bounds.
#[test]
fn constraint_count_isle_bounded_64bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 64)\nrange_check(b, 64)\npublic out\nassert_eq(a <= b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    assert!(
        n < 250,
        "bounded 64-bit IsLe total should be <250 constraints, got: {n}"
    );
}

/// Dark Forest anti-regression: P-1 must NOT pass a 64-bit bounded comparison.
/// With range_check(a, 64), a=P-1 must fail because P-1 > 2^64.
#[test]
fn soundness_dark_forest_bounded_64bit() {
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    // P-1 cannot pass range_check(a, 64) — the range check itself should reject it
    compile_expect_fail(
        "witness a\nwitness b\nrange_check(a, 64)\nrange_check(b, 64)\npublic out\nassert_eq(a < b, out)",
        &[("a", p_minus_1), ("b", fe(0)), ("out", fe(1))],
    );
}

// ============================================================================
// Wrong witness rejection — soundness
// Source: fundamental ZK requirement; 0xPARC zk-bug-tracker patterns.
// ============================================================================

#[test]
fn soundness_wrong_eq_result() {
    // 42 == 42 should be 1, not 0
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a == b, out)",
        &[("a", fe(42)), ("b", fe(42)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_neq_result() {
    // 42 != 43 should be 1, not 0
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a != b, out)",
        &[("a", fe(42)), ("b", fe(43)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_lt_result_true() {
    // 3 < 5 should be 1, not 0
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_lt_result_false() {
    // 5 < 3 should be 0, not 1
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(5)), ("b", fe(3)), ("out", fe(1))],
    );
}

#[test]
fn soundness_wrong_le_result() {
    // 5 <= 3 should be 0, not 1
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a <= b, out)",
        &[("a", fe(5)), ("b", fe(3)), ("out", fe(1))],
    );
}

// ============================================================================
// Chained comparisons — combination with boolean operators
// ============================================================================

#[test]
fn chained_lt_and_eq() {
    // (a < b) && (b == c) with a=1, b=5, c=5 → 1 && 1 = 1
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq((a < b) && (b == c), out)",
        &[("a", fe(1)), ("b", fe(5)), ("c", fe(5)), ("out", fe(1))],
    );
}

#[test]
fn chained_lt_or_eq() {
    // (a < b) || (a == c) with a=5, b=3, c=5 → 0 || 1 = 1
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq((a < b) || (a == c), out)",
        &[("a", fe(5)), ("b", fe(3)), ("c", fe(5)), ("out", fe(1))],
    );
}

#[test]
fn chained_not_eq() {
    // !(a == b) with a=3, b=5 → !0 = 1 (equivalent to a != b)
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(!(a == b), out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
}

#[test]
fn chained_not_eq_is_neq() {
    // !(a == b) == (a != b) — semantic equivalence
    compile_and_verify(
        "witness a\nwitness b\nassert_eq(!(a == b), a != b)",
        &[("a", fe(3)), ("b", fe(5))],
    );
}

#[test]
fn chained_not_eq_is_neq_equal() {
    // Same test with equal values
    compile_and_verify(
        "witness a\nwitness b\nassert_eq(!(a == b), a != b)",
        &[("a", fe(42)), ("b", fe(42))],
    );
}

// ============================================================================
// Trichotomy: exactly one of (a < b), (a == b), (a > b) is true
// Source: fundamental total order property. For any a, b in Fr:
//   (a < b) + (a == b) + (a > b) == 1
// This catches bugs where two comparison results are simultaneously true.
// ============================================================================

#[test]
fn trichotomy_less() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a == b) + (a > b), out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
}

#[test]
fn trichotomy_equal() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a == b) + (a > b), out)",
        &[("a", fe(5)), ("b", fe(5)), ("out", fe(1))],
    );
}

#[test]
fn trichotomy_greater() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a == b) + (a > b), out)",
        &[("a", fe(5)), ("b", fe(3)), ("out", fe(1))],
    );
}

#[test]
fn trichotomy_zero_zero() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a == b) + (a > b), out)",
        &[("a", fe(0)), ("b", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn trichotomy_zero_one() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a < b) + (a == b) + (a > b), out)",
        &[("a", fe(0)), ("b", fe(1)), ("out", fe(1))],
    );
}

// ============================================================================
// Mixed constant-witness comparisons
// Source: exercises the compiler path where one operand is a constant
// (LinearCombination::from_constant) and the other is a witness variable.
// This is a different code path than two-witness comparisons.
// ============================================================================

#[test]
fn mixed_lt_const_rhs() {
    // x < 100 with x=50 → 1
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x < 100, out)",
        &[("x", fe(50)), ("out", fe(1))],
    );
}

#[test]
fn mixed_lt_const_rhs_false() {
    // x < 100 with x=200 → 0
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x < 100, out)",
        &[("x", fe(200)), ("out", fe(0))],
    );
}

#[test]
fn mixed_lt_const_rhs_boundary() {
    // x < 100 with x=100 → 0 (not strictly less)
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x < 100, out)",
        &[("x", fe(100)), ("out", fe(0))],
    );
}

#[test]
fn mixed_lt_const_rhs_boundary_minus_1() {
    // x < 100 with x=99 → 1
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x < 100, out)",
        &[("x", fe(99)), ("out", fe(1))],
    );
}

#[test]
fn mixed_eq_const_zero() {
    // x == 0 with x=0 → 1
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x == 0, out)",
        &[("x", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn mixed_eq_const_zero_false() {
    // x == 0 with x=42 → 0
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x == 0, out)",
        &[("x", fe(42)), ("out", fe(0))],
    );
}

#[test]
fn mixed_le_const_rhs() {
    // x <= 255 with x=255 → 1
    compile_and_verify(
        "witness x\npublic out\nassert_eq(x <= 255, out)",
        &[("x", fe(255)), ("out", fe(1))],
    );
}

#[test]
fn mixed_gt_const_lhs() {
    // 100 > x with x=50 → 1
    compile_and_verify(
        "witness x\npublic out\nassert_eq(100 > x, out)",
        &[("x", fe(50)), ("out", fe(1))],
    );
}

#[test]
fn mixed_gt_const_lhs_false() {
    // 100 > x with x=200 → 0
    compile_and_verify(
        "witness x\npublic out\nassert_eq(100 > x, out)",
        &[("x", fe(200)), ("out", fe(0))],
    );
}

// ============================================================================
// Constant folding — comparisons with pure constants
// Source: validates optimizer constant propagation for comparison expressions.
// ============================================================================

#[test]
fn const_fold_lt_true() {
    compile_and_verify("public out\nassert_eq(3 < 5, out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_lt_false() {
    compile_and_verify("public out\nassert_eq(5 < 3, out)", &[("out", fe(0))]);
}

#[test]
fn const_fold_eq_true() {
    compile_and_verify("public out\nassert_eq(42 == 42, out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_eq_false() {
    compile_and_verify("public out\nassert_eq(42 == 43, out)", &[("out", fe(0))]);
}

#[test]
fn const_fold_lt_reduces_constraints() {
    let n_const = compile_and_verify("public out\nassert_eq(3 < 5, out)", &[("out", fe(1))]);
    let n_witness = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(3)), ("b", fe(5)), ("out", fe(1))],
    );
    assert!(
        n_const <= n_witness,
        "constant folding should not increase constraints: const={n_const}, witness={n_witness}"
    );
}

// ============================================================================
// Transitivity: a < b ∧ b < c → a < c
// Source: fundamental transitive property of total order.
// ============================================================================

#[test]
fn transitivity_lt() {
    // If a < b and b < c, then a < c must hold.
    // We assert all three comparisons explicitly.
    compile_and_verify(
        "witness a\nwitness b\nwitness c\nassert_eq(a < b, 1)\nassert_eq(b < c, 1)\nassert_eq(a < c, 1)",
        &[("a", fe(1)), ("b", fe(5)), ("c", fe(10))],
    );
}

#[test]
fn transitivity_le() {
    // a <= b ∧ b <= c → a <= c
    compile_and_verify(
        "witness a\nwitness b\nwitness c\nassert_eq(a <= b, 1)\nassert_eq(b <= c, 1)\nassert_eq(a <= c, 1)",
        &[("a", fe(3)), ("b", fe(3)), ("c", fe(7))],
    );
}

// ============================================================================
// Anti-symmetry: a <= b ∧ b <= a → a == b
// Source: fundamental anti-symmetric property of partial order.
// ============================================================================

#[test]
fn anti_symmetry_le() {
    // If a <= b and b <= a, then a must equal b.
    compile_and_verify(
        "witness a\nwitness b\nassert_eq(a <= b, 1)\nassert_eq(b <= a, 1)\nassert_eq(a == b, 1)",
        &[("a", fe(42)), ("b", fe(42))],
    );
}
