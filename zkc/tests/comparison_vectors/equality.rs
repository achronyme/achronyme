use crate::helpers::{compile_and_verify, fe, fe_str, P_MINUS_1, P_MINUS_2};

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
