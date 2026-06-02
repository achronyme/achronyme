use super::*;

// ============================================================================

div_tests! {
    (div_42_by_7, fe(42), fe(7), fe(6)),
    (div_100_by_10, fe(100), fe(10), fe(10)),
    (div_6_by_3, fe(6), fe(3), fe(2)),
    (div_1_by_1, fe(1), fe(1), fe(1)),
    (div_0_by_1, fe(0), fe(1), fe(0)),
    (div_0_by_42, fe(0), fe(42), fe(0)),
    (div_0_by_pminus1, fe(0), p_minus_1(), fe(0)),
    (div_10_by_2, fe(10), fe(2), fe(5)),
    (div_12_by_4, fe(12), fe(4), fe(3)),
    (div_1000000_by_1000, fe(1_000_000), fe(1000), fe(1000)),
    (div_255_by_5, fe(255), fe(5), fe(51)),
    (div_256_by_16, fe(256), fe(16), fe(16)),
    (div_65536_by_256, fe(65536), fe(256), fe(256)),
}

// ============================================================================
// 2. Identity property: a / 1 = a
// Source: field axiom — multiplicative identity inverse is 1.
// ============================================================================

div_tests! {
    (div_by_one_zero, fe(0), fe(1), fe(0)),
    (div_by_one_one, fe(1), fe(1), fe(1)),
    (div_by_one_42, fe(42), fe(1), fe(42)),
    (div_by_one_255, fe(255), fe(1), fe(255)),
    (div_by_one_u32max, fe(u32::MAX as u64), fe(1), fe(u32::MAX as u64)),
    (div_by_one_u64max, fe(u64::MAX), fe(1), fe(u64::MAX)),
    (div_by_one_pminus1, p_minus_1(), fe(1), p_minus_1()),
    (div_by_one_pminus2, p_minus_2(), fe(1), p_minus_2()),
}

#[test]
fn div_by_one_exhaustive() {
    let values = [
        fe(0),
        fe(1),
        fe(2),
        fe(42),
        fe(255),
        fe(256),
        fe(65535),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &v in &values {
        compile_and_verify(DIV_SOURCE, &[("a", v), ("b", fe(1)), ("out", v)]);
    }
}

// ============================================================================
// 3. Self-division: a / a = 1 (for a ≠ 0)
// Source: field axiom — a * a^{-1} = 1.
// ============================================================================

div_tests! {
    (div_self_1, fe(1), fe(1), fe(1)),
    (div_self_2, fe(2), fe(2), fe(1)),
    (div_self_42, fe(42), fe(42), fe(1)),
    (div_self_255, fe(255), fe(255), fe(1)),
    (div_self_u32max, fe(u32::MAX as u64), fe(u32::MAX as u64), fe(1)),
    (div_self_u64max, fe(u64::MAX), fe(u64::MAX), fe(1)),
    (div_self_pminus1, p_minus_1(), p_minus_1(), fe(1)),
    (div_self_pminus2, p_minus_2(), p_minus_2(), fe(1)),
}

#[test]
fn div_self_exhaustive() {
    let values = [
        fe(1),
        fe(2),
        fe(3),
        fe(42),
        fe(100),
        fe(255),
        fe(256),
        fe(65535),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &v in &values {
        compile_and_verify(DIV_SOURCE, &[("a", v), ("b", v), ("out", fe(1))]);
    }
}

// ============================================================================
// 4. Zero numerator: 0 / b = 0 (for b ≠ 0)
// Source: field axiom — 0 * b^{-1} = 0.
// ============================================================================

#[test]
fn div_zero_numerator_exhaustive() {
    let divisors = [
        fe(1),
        fe(2),
        fe(3),
        fe(42),
        fe(255),
        fe(256),
        fe(65535),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &d in &divisors {
        compile_and_verify(DIV_SOURCE, &[("a", fe(0)), ("b", d), ("out", fe(0))]);
    }
}

// ============================================================================
// 5. Division by zero — must fail
// Source: circomspect analysis — Div(x, 0) produces under-constrained circuits.
// Achronyme catches this at witness generation time (catastrophic failure).
// ============================================================================

#[test]
fn div_by_zero_one() {
    compile_expect_fail(DIV_SOURCE, &[("a", fe(1)), ("b", fe(0)), ("out", fe(0))]);
}

#[test]
fn div_by_zero_42() {
    compile_expect_fail(DIV_SOURCE, &[("a", fe(42)), ("b", fe(0)), ("out", fe(0))]);
}

#[test]
fn div_by_zero_zero() {
    compile_expect_fail(DIV_SOURCE, &[("a", fe(0)), ("b", fe(0)), ("out", fe(0))]);
}

#[test]
fn div_by_zero_pminus1() {
    compile_expect_fail(
        DIV_SOURCE,
        &[("a", p_minus_1()), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn div_by_zero_large() {
    compile_expect_fail(
        DIV_SOURCE,
        &[("a", fe(u64::MAX)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn div_by_zero_in_expression() {
    // Division by zero within a larger expression
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a / b + 1, out)",
        &[("a", fe(10)), ("b", fe(0)), ("out", fe(0))],
    );
}
