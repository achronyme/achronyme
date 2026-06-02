use crate::helpers::{compile_and_verify, compile_expect_fail, fe};

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
