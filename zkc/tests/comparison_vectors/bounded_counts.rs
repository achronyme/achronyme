use crate::helpers::{compile_and_verify, compile_expect_fail, fe, fe_str};

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
