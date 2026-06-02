use super::*;

const ROUNDTRIP_SOURCE: &str =
    "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)";

// ============================================================================
// 17. Boundary value division
// Source: arkworks test-templates — boundary values for field operations.
// ============================================================================

#[test]
fn div_pminus1_by_pminus1() {
    // (p-1)/(p-1) = 1
    compile_and_verify(
        DIV_SOURCE,
        &[("a", p_minus_1()), ("b", p_minus_1()), ("out", fe(1))],
    );
}

#[test]
fn div_pminus2_by_pminus1() {
    // (p-2)/(p-1) — verify via roundtrip
    compile_and_verify(
        ROUNDTRIP_SOURCE,
        &[
            ("a", p_minus_2()),
            ("b", p_minus_1()),
            ("expected", p_minus_2()),
        ],
    );
}

#[test]
fn div_1_by_pminus2() {
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", p_minus_2()), ("out", fe(1))],
    );
}

#[test]
fn div_u64max_by_u64max() {
    compile_and_verify(
        DIV_SOURCE,
        &[("a", fe(u64::MAX)), ("b", fe(u64::MAX)), ("out", fe(1))],
    );
}

#[test]
fn div_large_by_small() {
    // (p-1) / 2 — result * 2 should equal p-1
    compile_and_verify(
        ROUNDTRIP_SOURCE,
        &[("a", p_minus_1()), ("b", fe(2)), ("expected", p_minus_1())],
    );
}

// ============================================================================
// 18. Negation via division: a / (p-1) = -a (since p-1 ≡ -1 mod p)
// Source: field axiom — (p-1) is the additive inverse of 1.
// ============================================================================

#[test]
fn div_by_neg1_is_negation() {
    // 5 / (p-1) = 5 * (p-1)^{-1} = 5 * (p-1) = -5 = p-5
    // Because (p-1)^{-1} = p-1 (since (p-1)^2 = 1 mod p)
    let p_minus_5 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495612");
    compile_and_verify(
        DIV_SOURCE,
        &[("a", fe(5)), ("b", p_minus_1()), ("out", p_minus_5)],
    );
}

#[test]
fn div_by_neg1_roundtrip() {
    // a / (p-1) * (p-1) = a
    compile_and_verify(
        ROUNDTRIP_SOURCE,
        &[("a", fe(42)), ("b", p_minus_1()), ("expected", fe(42))],
    );
}

// ============================================================================
// 19. Associativity of inverse: (a/b) / c = a / (b*c)
// Source: field axiom — a * b^{-1} * c^{-1} = a * (b*c)^{-1}
// ============================================================================

#[test]
fn div_associative_simple() {
    // (60/3)/4 = 5, and 60/(3*4) = 60/12 = 5
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\n\
         assert_eq(a / b / c, a / (b * c))",
        &[("a", fe(60)), ("b", fe(3)), ("c", fe(4)), ("out", fe(0))],
    );
}

#[test]
fn div_associative_primes() {
    compile_and_verify(
        "witness a\nwitness b\nwitness c\n\
         assert_eq(a / b / c, a / (b * c))",
        &[("a", fe(210)), ("b", fe(7)), ("c", fe(5))],
    );
}

#[test]
fn div_associative_large() {
    compile_and_verify(
        "witness a\nwitness b\nwitness c\n\
         assert_eq(a / b / c, a / (b * c))",
        &[("a", p_minus_1()), ("b", fe(42)), ("c", fe(7))],
    );
}

// ============================================================================
// 20. Fully constant division — compile-time folding
// ============================================================================

#[test]
fn div_all_const_42_7() {
    compile_and_verify("public out\nassert_eq(42 / 7, out)", &[("out", fe(6))]);
}

#[test]
fn div_all_const_100_10() {
    compile_and_verify("public out\nassert_eq(100 / 10, out)", &[("out", fe(10))]);
}

#[test]
fn div_all_const_reduces_constraints() {
    let n = compile_and_verify("public out\nassert_eq(42 / 7, out)", &[("out", fe(6))]);
    assert!(
        n <= 2,
        "fully constant div should produce minimal constraints: {n}"
    );
}
