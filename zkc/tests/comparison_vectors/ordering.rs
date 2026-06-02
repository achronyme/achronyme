use crate::helpers::{compile_and_verify, fe};

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
