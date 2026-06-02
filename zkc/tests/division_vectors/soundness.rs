use super::*;

// Source: validates soundness — incorrect quotient must fail.
// ============================================================================

#[test]
fn soundness_div_wrong_quotient() {
    // 42/7 = 6, not 7
    compile_expect_fail(DIV_SOURCE, &[("a", fe(42)), ("b", fe(7)), ("out", fe(7))]);
}

#[test]
fn soundness_div_wrong_quotient_zero() {
    // 42/7 = 6, not 0
    compile_expect_fail(DIV_SOURCE, &[("a", fe(42)), ("b", fe(7)), ("out", fe(0))]);
}

#[test]
fn soundness_div_wrong_quotient_pminus1() {
    compile_expect_fail(
        DIV_SOURCE,
        &[("a", fe(42)), ("b", fe(7)), ("out", p_minus_1())],
    );
}

#[test]
fn soundness_div_self_wrong() {
    // a/a = 1, not 0
    compile_expect_fail(DIV_SOURCE, &[("a", fe(42)), ("b", fe(42)), ("out", fe(0))]);
}

#[test]
fn soundness_div_identity_wrong() {
    // a/1 = a, not a+1
    compile_expect_fail(DIV_SOURCE, &[("a", fe(42)), ("b", fe(1)), ("out", fe(43))]);
}
