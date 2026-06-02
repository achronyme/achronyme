use crate::helpers::{compile_and_verify, fe};

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
