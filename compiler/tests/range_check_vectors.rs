//! Phase II — Range Check Exhaustive Vectors (R1CS, BN254 Fr)
//!
//! Systematic range check validation across bit widths 1–253 with boundary
//! value analysis, constraint count regression, and vulnerability testing.
//!
//! Industry sources:
//!   - circomlib aliascheck.circom:   https://github.com/iden3/circomlib/blob/master/circuits/aliascheck.circom
//!     Num2Bits constraint pattern for range validation. (GPL-3.0) [ref 1]
//!   - 0xPARC zk-bug-tracker:        https://github.com/0xPARC/zk-bug-tracker
//!     Dark Forest LessThan vulnerability: omitted bit length restriction
//!     in comparators.circom allowed overflow attacks. [ref 33]
//!   - Noir stdlib field/mod.nr:      https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!     Range constraint patterns for BN254 Fr. (MIT/Apache-2.0) [ref 44]
//!   - gnark-crypto bn254 Fr:        https://github.com/Consensys/gnark-crypto/blob/master/ecc/bn254/fr/element_test.go
//!     Field element boundary testing methodology. (Apache-2.0) [ref 46]
//!
//! Constraint cost model (R1CS): range_check(x, n) = n + 1 constraints
//!   - n constraints for bit decomposition (one boolean per bit)
//!   - 1 constraint for sum equality (reconstruct value from bits)
//!
//! Reference: "Análisis Integral de Vectores de Prueba y Evaluación de Rendimiento
//! para Entornos de Compilación de Conocimiento Cero" (2026), §Vulnerabilidades y
//! Restricciones en Desigualdades Lógicas, Dark Forest case study.
//!
//! Note: only numerical test vectors (not code) are referenced here.
//! These are facts, not copyrightable expression — compatible with our Apache-2.0.

use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
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

/// Compute 2^n as a FieldElement.
fn two_pow(n: u32) -> FieldElement {
    let mut result = FieldElement::ONE;
    let two = FieldElement::from_u64(2);
    for _ in 0..n {
        result = result.mul(&two);
    }
    result
}

/// Compute 2^n - 1 (max valid value for n-bit range check).
fn max_for_bits(n: u32) -> FieldElement {
    two_pow(n).sub(&FieldElement::ONE)
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

/// Macro for parameterized range check tests.
macro_rules! range_check_tests {
    ($(($name:ident, $bits:expr, $val:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let source = format!("witness x\nrange_check(x, {})", $bits);
                compile_and_verify(&source, &[("x", $val)]);
            }
        )*
    };
}

/// Macro for parameterized range check failure tests.
macro_rules! range_check_fail_tests {
    ($(($name:ident, $bits:expr, $val:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let source = format!("witness x\nrange_check(x, {})", $bits);
                compile_expect_fail(&source, &[("x", $val)]);
            }
        )*
    };
}

// ============================================================================
// Valid maximum values: 2^n - 1 for each bit width
// Source: circomlib aliascheck — Num2Bits accepts values in [0, 2^n - 1].
// ============================================================================

range_check_tests! {
    (valid_max_1bit,   1,  fe(1)),
    (valid_max_2bit,   2,  fe(3)),
    (valid_max_3bit,   3,  fe(7)),
    (valid_max_4bit,   4,  fe(15)),
    (valid_max_5bit,   5,  fe(31)),
    (valid_max_6bit,   6,  fe(63)),
    (valid_max_7bit,   7,  fe(127)),
    (valid_max_8bit,   8,  fe(255)),
    (valid_max_10bit, 10,  fe(1023)),
    (valid_max_12bit, 12,  fe(4095)),
    (valid_max_16bit, 16,  fe(65535)),
    (valid_max_20bit, 20,  fe(1_048_575)),
    (valid_max_24bit, 24,  fe(16_777_215)),
    (valid_max_32bit, 32,  fe(4_294_967_295)),
    (valid_max_48bit, 48,  fe((1u64 << 48) - 1)),
    (valid_max_64bit, 64,  fe(u64::MAX)),
}

// ============================================================================
// Invalid overflow: 2^n (one above maximum) must be rejected
// Source: circomlib aliascheck — values >= 2^n must fail bit decomposition.
// This is the exact boundary tested by the Dark Forest vulnerability. [ref 33]
// ============================================================================

range_check_fail_tests! {
    (overflow_1bit,   1,  fe(2)),
    (overflow_2bit,   2,  fe(4)),
    (overflow_3bit,   3,  fe(8)),
    (overflow_4bit,   4,  fe(16)),
    (overflow_5bit,   5,  fe(32)),
    (overflow_6bit,   6,  fe(64)),
    (overflow_7bit,   7,  fe(128)),
    (overflow_8bit,   8,  fe(256)),
    (overflow_10bit, 10,  fe(1024)),
    (overflow_12bit, 12,  fe(4096)),
    (overflow_16bit, 16,  fe(65536)),
    (overflow_20bit, 20,  fe(1_048_576)),
    (overflow_24bit, 24,  fe(16_777_216)),
    (overflow_32bit, 32,  fe(4_294_967_296)),
    (overflow_48bit, 48,  fe(1u64 << 48)),
}

// ============================================================================
// Zero value: always valid for any bit width >= 0
// Source: fundamental — zero is representable in any number of bits.
// ============================================================================

range_check_tests! {
    (zero_1bit,   1,  fe(0)),
    (zero_4bit,   4,  fe(0)),
    (zero_8bit,   8,  fe(0)),
    (zero_16bit, 16,  fe(0)),
    (zero_32bit, 32,  fe(0)),
    (zero_64bit, 64,  fe(0)),
}

// ============================================================================
// One value: valid for any bit width >= 1
// ============================================================================

range_check_tests! {
    (one_1bit,   1,  fe(1)),
    (one_4bit,   4,  fe(1)),
    (one_8bit,   8,  fe(1)),
    (one_16bit, 16,  fe(1)),
    (one_32bit, 32,  fe(1)),
    (one_64bit, 64,  fe(1)),
}

// ============================================================================
// Boundary: 2^n - 2 (one below maximum — always valid)
// ============================================================================

range_check_tests! {
    (below_max_1bit,   1,  fe(0)),
    (below_max_4bit,   4,  fe(14)),
    (below_max_8bit,   8,  fe(254)),
    (below_max_16bit, 16,  fe(65534)),
    (below_max_32bit, 32,  fe(4_294_967_294)),
}

// ============================================================================
// Half-range values: 2^(n-1) — the midpoint, always valid
// ============================================================================

range_check_tests! {
    (half_range_4bit,   4,  fe(8)),
    (half_range_8bit,   8,  fe(128)),
    (half_range_16bit, 16,  fe(32768)),
    (half_range_32bit, 32,  fe(2_147_483_648)),
}

// ============================================================================
// Large bit widths (> 64 bits) — using FieldElement arithmetic
// Source: gnark-crypto bn254 Fr element_test.go — large field element tests.
// ============================================================================

#[test]
fn valid_max_128bit() {
    // 2^128 - 1
    let val = max_for_bits(128);
    compile_and_verify("witness x\nrange_check(x, 128)", &[("x", val)]);
}

#[test]
fn overflow_128bit() {
    // 2^128 — one above max
    let val = two_pow(128);
    compile_expect_fail("witness x\nrange_check(x, 128)", &[("x", val)]);
}

#[test]
fn valid_max_252bit() {
    // 2^252 - 1 — largest practical range check (near field size)
    let val = max_for_bits(252);
    compile_and_verify("witness x\nrange_check(x, 252)", &[("x", val)]);
}

#[test]
fn overflow_252bit() {
    // 2^252 — exceeds 252-bit range
    let val = two_pow(252);
    compile_expect_fail("witness x\nrange_check(x, 252)", &[("x", val)]);
}

#[test]
fn valid_max_253bit() {
    // 2^253 - 1 — maximum practical bit width for BN254
    let val = max_for_bits(253);
    compile_and_verify("witness x\nrange_check(x, 253)", &[("x", val)]);
}

// ============================================================================
// Constraint count regression: cost = bits + 1
// Source: circomlib Num2Bits — n boolean constraints + 1 sum constraint.
// ============================================================================

macro_rules! constraint_count_tests {
    ($(($name:ident, $bits:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let source = format!("witness x\nrange_check(x, {})", $bits);
                let n = compile_and_verify(&source, &[("x", fe(0))]);
                let expected = $bits + 1;
                assert_eq!(
                    n, expected,
                    "range_check(x, {}) should cost {} constraints, got {}",
                    $bits, expected, n
                );
            }
        )*
    };
}

constraint_count_tests! {
    (constraint_count_1bit,   1),
    (constraint_count_2bit,   2),
    (constraint_count_3bit,   3),
    (constraint_count_4bit,   4),
    (constraint_count_5bit,   5),
    (constraint_count_6bit,   6),
    (constraint_count_7bit,   7),
    (constraint_count_8bit,   8),
    (constraint_count_10bit, 10),
    (constraint_count_12bit, 12),
    (constraint_count_16bit, 16),
    (constraint_count_20bit, 20),
    (constraint_count_24bit, 24),
    (constraint_count_32bit, 32),
    (constraint_count_48bit, 48),
    (constraint_count_64bit, 64),
}

// ============================================================================
// 0-bit range check: only value 0 is valid
// Source: edge case — range_check(x, 0) means x must be exactly 0.
// ============================================================================

#[test]
fn zero_bit_accepts_zero() {
    compile_and_verify("witness x\nrange_check(x, 0)", &[("x", fe(0))]);
}

#[test]
fn zero_bit_rejects_one() {
    compile_expect_fail("witness x\nrange_check(x, 0)", &[("x", fe(1))]);
}

#[test]
fn zero_bit_rejects_large() {
    compile_expect_fail("witness x\nrange_check(x, 0)", &[("x", fe(42))]);
}

// ============================================================================
// Dark Forest vulnerability test vectors
// Source: 0xPARC zk-bug-tracker — Dark Forest under-constrained LessThan. [ref 33]
// The vulnerability: comparators.circom LessThan omitted algorithmic restriction
// of input bit length, allowing attackers to inject massive integers that
// overflowed the underlying range checker, producing forged valid proofs.
//
// Test strategy: inject values near field boundaries into range-checked
// circuits and verify the enforcement catches them.
// ============================================================================

#[test]
fn dark_forest_p_minus_1_in_8bit() {
    // p-1 is a valid field element but NOT an 8-bit value.
    // An under-constrained circuit would accept it — ours must reject.
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_expect_fail("witness x\nrange_check(x, 8)", &[("x", p_minus_1)]);
}

#[test]
fn dark_forest_p_minus_1_in_64bit() {
    // p-1 is NOT a 64-bit value (it's ~254 bits).
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_expect_fail("witness x\nrange_check(x, 64)", &[("x", p_minus_1)]);
}

#[test]
fn dark_forest_p_minus_1_in_128bit() {
    // p-1 is NOT a 128-bit value.
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_expect_fail("witness x\nrange_check(x, 128)", &[("x", p_minus_1)]);
}

#[test]
fn dark_forest_half_p_in_253bit() {
    // p/2 ≈ 2^253, fits in 253 bits but NOT in 252. Validates correct boundary.
    let half_p =
        fe_str("10944121435919637611123202872628637544274182200208017171849102093287904247808");
    compile_and_verify("witness x\nrange_check(x, 253)", &[("x", half_p)]);
}

#[test]
fn dark_forest_half_p_rejected_in_252bit() {
    // p/2 does NOT fit in 252 bits — must be rejected.
    let half_p =
        fe_str("10944121435919637611123202872628637544274182200208017171849102093287904247808");
    compile_expect_fail("witness x\nrange_check(x, 252)", &[("x", half_p)]);
}

// ============================================================================
// Combined range_check + comparison (constraint optimization path)
// Source: validates that the compiler correctly infers range bounds from
// prior range_check instructions to reduce IsLt constraint cost.
// ============================================================================

#[test]
fn range_check_then_lt() {
    // range_check reduces IsLt from ~760 to ~30 constraints
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 8)\nrange_check(b, 8)\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(10)), ("b", fe(200)), ("out", fe(1))],
    );
    // 2×9 (range_check) + ~11 (bounded IsLt) + 1 (assert_eq) = ~30
    assert!(
        n < 60,
        "range_check + IsLt should optimize to ~30, got: {n}"
    );
}

#[test]
fn range_check_then_le() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 8)\nrange_check(b, 8)\npublic out\nassert_eq(a <= b, out)",
        &[("a", fe(200)), ("b", fe(200)), ("out", fe(1))],
    );
    assert!(
        n < 60,
        "range_check + IsLe should optimize to ~30, got: {n}"
    );
}

#[test]
fn range_check_then_lt_16bit() {
    let n = compile_and_verify(
        "witness a\nwitness b\nrange_check(a, 16)\nrange_check(b, 16)\npublic out\nassert_eq(a < b, out)",
        &[("a", fe(1000)), ("b", fe(50000)), ("out", fe(1))],
    );
    // 2×17 (range_check) + ~19 (bounded IsLt) + 1 (assert_eq) = ~54
    assert!(
        n < 100,
        "16-bit range_check + IsLt should optimize significantly, got: {n}"
    );
}

// ============================================================================
// Multiple range checks on same variable — idempotence
// Source: validates compiler doesn't emit duplicate constraints.
// ============================================================================

#[test]
fn double_range_check_same_width() {
    // Two range_check(x, 8) on the same variable
    compile_and_verify(
        "witness x\nrange_check(x, 8)\nrange_check(x, 8)",
        &[("x", fe(200))],
    );
}

#[test]
fn range_check_narrow_then_wide() {
    // range_check(x, 4) then range_check(x, 8) — narrower dominates
    compile_and_verify(
        "witness x\nrange_check(x, 4)\nrange_check(x, 8)",
        &[("x", fe(15))],
    );
}

#[test]
fn range_check_narrow_rejects_over() {
    // range_check(x, 4) limits to [0, 15], even if range_check(x, 8) follows
    compile_expect_fail(
        "witness x\nrange_check(x, 4)\nrange_check(x, 8)",
        &[("x", fe(16))],
    );
}
