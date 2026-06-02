use super::*;

// ============================================================================
// Soundness — non-boolean witness rejection
// Source: 0xPARC zk-bug-tracker — under-constrained boolean attacks.
// The boolean enforcement gadget b*(1-b)=0 must reject values ∉ {0, 1}.
// Source: arkworks r1cs-std Boolean<F> — enforces_in_scope() constraint.
// ============================================================================

#[test]
fn soundness_not_rejects_2() {
    compile_expect_fail(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(2)), ("out", fe(0))],
    );
}

#[test]
fn soundness_not_rejects_large() {
    compile_expect_fail(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(42)), ("out", fe(0))],
    );
}

#[test]
fn soundness_and_rejects_non_boolean_lhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(2)), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn soundness_and_rejects_non_boolean_rhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(1)), ("b", fe(5)), ("out", fe(0))],
    );
}

#[test]
fn soundness_or_rejects_non_boolean_lhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(3)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn soundness_or_rejects_non_boolean_rhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(0)), ("b", fe(100)), ("out", fe(0))],
    );
}

#[test]
fn soundness_and_rejects_p_minus_1() {
    // p-1 is not boolean despite being a valid field element
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", p_minus_1), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_not_result() {
    // !0 should be 1, not 0 — wrong output must fail
    compile_expect_fail(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_and_result() {
    // 1 && 1 should be 1, not 0 — wrong output must fail
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(1)), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_or_result() {
    // 0 || 1 should be 1, not 0 — wrong output must fail
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(0)), ("b", fe(1)), ("out", fe(0))],
    );
}
