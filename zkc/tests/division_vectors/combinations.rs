use super::*;

#[test]
fn div_non_integer_1_by_3() {
    // 1/3 in the field — verify via roundtrip
    compile_and_verify(
        "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)",
        &[("a", fe(1)), ("b", fe(3)), ("expected", fe(1))],
    );
}

#[test]
fn div_non_integer_2_by_3() {
    compile_and_verify(
        "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)",
        &[("a", fe(2)), ("b", fe(3)), ("expected", fe(2))],
    );
}

#[test]
fn div_non_integer_1_by_7() {
    compile_and_verify(
        "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)",
        &[("a", fe(1)), ("b", fe(7)), ("expected", fe(1))],
    );
}

#[test]
fn div_pminus1_by_2() {
    // (p-1) / 2 — verify via roundtrip: result * 2 = p-1
    compile_and_verify(
        "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)",
        &[("a", p_minus_1()), ("b", fe(2)), ("expected", p_minus_1())],
    );
}

// ============================================================================
// 12. Chained divisions
// Source: validates compiler handles sequential Div instructions correctly.
// ============================================================================

#[test]
fn div_chained_a_b_c() {
    // (a / b) / c with a=120, b=4, c=3 → 120/4=30, 30/3=10
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(a / b / c, out)",
        &[("a", fe(120)), ("b", fe(4)), ("c", fe(3)), ("out", fe(10))],
    );
}

#[test]
fn div_chained_three_levels() {
    // ((a / b) / c) / d = 360/6/5/2 = 6
    compile_and_verify(
        "witness a\nwitness b\nwitness c\nwitness d\npublic out\n\
         assert_eq(a / b / c / d, out)",
        &[
            ("a", fe(360)),
            ("b", fe(6)),
            ("c", fe(5)),
            ("d", fe(2)),
            ("out", fe(6)),
        ],
    );
}

#[test]
fn div_chained_roundtrip() {
    // (a / b / c) * c * b should equal a
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic expected\n\
         let q = a / b / c\nassert_eq(q * c * b, expected)",
        &[
            ("a", fe(42)),
            ("b", fe(3)),
            ("c", fe(7)),
            ("expected", fe(42)),
        ],
    );
}

// ============================================================================
// 13. Division combined with other operations
// ============================================================================

#[test]
fn div_plus_const() {
    // a / b + 1 with a=10, b=2 → 5 + 1 = 6
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a / b + 1, out)",
        &[("a", fe(10)), ("b", fe(2)), ("out", fe(6))],
    );
}

#[test]
fn div_times_const() {
    // (a / b) * 3 with a=10, b=2 → 5 * 3 = 15
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a / b * 3, out)",
        &[("a", fe(10)), ("b", fe(2)), ("out", fe(15))],
    );
}

#[test]
fn div_minus_div() {
    // a/b - c/d with a=20,b=4,c=6,d=3 → 5 - 2 = 3
    compile_and_verify(
        "witness a\nwitness b\nwitness c\nwitness d\npublic out\n\
         assert_eq(a / b - c / d, out)",
        &[
            ("a", fe(20)),
            ("b", fe(4)),
            ("c", fe(6)),
            ("d", fe(3)),
            ("out", fe(3)),
        ],
    );
}

#[test]
fn div_in_quadratic() {
    // (a / b)^2 with a=12, b=3 → 4^2 = 16
    compile_and_verify(
        "witness a\nwitness b\npublic out\n\
         let q = a / b\nassert_eq(q * q, out)",
        &[("a", fe(12)), ("b", fe(3)), ("out", fe(16))],
    );
}

#[test]
fn div_with_mux() {
    // mux(c, a/b, d) with c=1, a=42, b=7 → 6
    compile_and_verify(
        "witness c\nwitness a\nwitness b\nwitness d\npublic out\n\
         let q = a / b\nassert_eq(mux(c, q, d), out)",
        &[
            ("c", fe(1)),
            ("a", fe(42)),
            ("b", fe(7)),
            ("d", fe(99)),
            ("out", fe(6)),
        ],
    );
}

#[test]
fn div_with_mux_sel0() {
    // mux(c, a/b, d) with c=0, d=99 → 99
    compile_and_verify(
        "witness c\nwitness a\nwitness b\nwitness d\npublic out\n\
         let q = a / b\nassert_eq(mux(c, q, d), out)",
        &[
            ("c", fe(0)),
            ("a", fe(42)),
            ("b", fe(7)),
            ("d", fe(99)),
            ("out", fe(99)),
        ],
    );
}

// ============================================================================
// 14. Constant denominator — 0 constraints for the division itself
// Source: R1CS backend — constant denominator is precomputed at compile time.
// ============================================================================

#[test]
fn div_const_denom_2() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a / 2, out)",
        &[("a", fe(10)), ("out", fe(5))],
    );
}

#[test]
fn div_const_denom_7() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a / 7, out)",
        &[("a", fe(42)), ("out", fe(6))],
    );
}

#[test]
fn div_const_denom_reduces_constraints() {
    // Division by constant should produce fewer constraints than by variable.
    let n_const = compile_and_verify(
        "witness a\npublic out\nassert_eq(a / 7, out)",
        &[("a", fe(42)), ("out", fe(6))],
    );
    let n_var = compile_and_verify(DIV_SOURCE, &[("a", fe(42)), ("b", fe(7)), ("out", fe(6))]);
    assert!(
        n_const <= n_var,
        "constant denominator should not produce more constraints: const={n_const}, var={n_var}"
    );
}

// ============================================================================
// 15. Constraint count regression
// Source: R1CS cost analysis:
//   - Constant denominator: 0 constraints (precomputed inverse)
//   - Variable denominator: 2 constraints (1 inverse + 1 multiply)
// ============================================================================

#[test]
fn constraint_count_div_variable() {
    let n = compile_and_verify(DIV_SOURCE, &[("a", fe(42)), ("b", fe(7)), ("out", fe(6))]);
    // Div (2) + assert_eq (1) → expect ≤ 5
    assert!(n <= 5, "variable div constraint count too high: {n}");
}

#[test]
fn constraint_count_div_constant() {
    let n = compile_and_verify(
        "witness a\npublic out\nassert_eq(a / 7, out)",
        &[("a", fe(42)), ("out", fe(6))],
    );
    // Div with constant denom (0) + assert_eq (1) → expect ≤ 3
    assert!(n <= 3, "constant div constraint count too high: {n}");
}

#[test]
fn constraint_count_chained_div() {
    let n = compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(a / b / c, out)",
        &[("a", fe(120)), ("b", fe(4)), ("c", fe(3)), ("out", fe(10))],
    );
    // 2 divs (4) + assert_eq (1) → expect ≤ 8
    assert!(n <= 8, "chained div constraint count too high: {n}");
}

// ============================================================================
