use super::*;

// ============================================================================
// 8. Mux in arithmetic context — result used in add/mul/sub
// Source: validates that mux outputs compose correctly with arithmetic.
// ============================================================================

#[test]
fn mux_result_in_addition() {
    // mux(1, 10, 20) + 5 = 15
    compile_and_verify(
        "witness c\nwitness a\nwitness b\nwitness d\npublic out\nassert_eq(mux(c, a, b) + d, out)",
        &[
            ("c", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("d", fe(5)),
            ("out", fe(15)),
        ],
    );
}

#[test]
fn mux_result_in_multiplication() {
    // mux(0, 10, 3) * 7 = 3 * 7 = 21
    compile_and_verify(
        "witness c\nwitness a\nwitness b\nwitness d\npublic out\nassert_eq(mux(c, a, b) * d, out)",
        &[
            ("c", fe(0)),
            ("a", fe(10)),
            ("b", fe(3)),
            ("d", fe(7)),
            ("out", fe(21)),
        ],
    );
}

#[test]
fn mux_result_in_subtraction() {
    // mux(1, 100, 50) - 30 = 100 - 30 = 70
    compile_and_verify(
        "witness c\nwitness a\nwitness b\nwitness d\npublic out\nassert_eq(mux(c, a, b) - d, out)",
        &[
            ("c", fe(1)),
            ("a", fe(100)),
            ("b", fe(50)),
            ("d", fe(30)),
            ("out", fe(70)),
        ],
    );
}

#[test]
fn mux_both_sides_of_add() {
    // mux(c1, a1, b1) + mux(c2, a2, b2)
    // c1=1 → a1=10, c2=0 → b2=5. Result = 15
    compile_and_verify(
        "witness c1\nwitness c2\nwitness a1\nwitness b1\nwitness a2\nwitness b2\npublic out\n\
         assert_eq(mux(c1, a1, b1) + mux(c2, a2, b2), out)",
        &[
            ("c1", fe(1)),
            ("c2", fe(0)),
            ("a1", fe(10)),
            ("b1", fe(20)),
            ("a2", fe(30)),
            ("b2", fe(5)),
            ("out", fe(15)),
        ],
    );
}

#[test]
fn mux_both_sides_of_mul() {
    // mux(1, 6, 2) * mux(0, 3, 7) = 6 * 7 = 42
    compile_and_verify(
        "witness c1\nwitness c2\nwitness a1\nwitness b1\nwitness a2\nwitness b2\npublic out\n\
         assert_eq(mux(c1, a1, b1) * mux(c2, a2, b2), out)",
        &[
            ("c1", fe(1)),
            ("c2", fe(0)),
            ("a1", fe(6)),
            ("b1", fe(2)),
            ("a2", fe(3)),
            ("b2", fe(7)),
            ("out", fe(42)),
        ],
    );
}

#[test]
fn mux_result_squared() {
    // mux(1, 5, 3) * mux(1, 5, 3) = 25
    compile_and_verify(
        "witness c\nwitness a\nwitness b\npublic out\n\
         let r = mux(c, a, b)\nassert_eq(r * r, out)",
        &[("c", fe(1)), ("a", fe(5)), ("b", fe(3)), ("out", fe(25))],
    );
}

#[test]
fn mux_chained_arithmetic() {
    // (mux(1, 10, 5) + mux(0, 3, 7)) * 2 = (10 + 7) * 2 = 34
    compile_and_verify(
        "witness c1\nwitness c2\nwitness a\nwitness b\nwitness d\nwitness e\npublic out\n\
         assert_eq((mux(c1, a, b) + mux(c2, d, e)) * 2, out)",
        &[
            ("c1", fe(1)),
            ("c2", fe(0)),
            ("a", fe(10)),
            ("b", fe(5)),
            ("d", fe(3)),
            ("e", fe(7)),
            ("out", fe(34)),
        ],
    );
}

// ============================================================================
// 9. Mux with comparison and boolean condition sources
// Source: validates mux where condition comes from IsEq, IsLt, And, Or.
// ============================================================================

#[test]
fn mux_cond_from_iseq_true() {
    // x == 5 is true → select a=100
    compile_and_verify(
        "witness x\nwitness a\nwitness b\npublic out\nassert_eq(mux(x == 5, a, b), out)",
        &[
            ("x", fe(5)),
            ("a", fe(100)),
            ("b", fe(200)),
            ("out", fe(100)),
        ],
    );
}

#[test]
fn mux_cond_from_iseq_false() {
    // x == 5 is false → select b=200
    compile_and_verify(
        "witness x\nwitness a\nwitness b\npublic out\nassert_eq(mux(x == 5, a, b), out)",
        &[
            ("x", fe(3)),
            ("a", fe(100)),
            ("b", fe(200)),
            ("out", fe(200)),
        ],
    );
}

#[test]
fn mux_cond_from_isneq_true() {
    // x != 0 with x=7 → true → a=10
    compile_and_verify(
        "witness x\nwitness a\nwitness b\npublic out\nassert_eq(mux(x != 0, a, b), out)",
        &[("x", fe(7)), ("a", fe(10)), ("b", fe(20)), ("out", fe(10))],
    );
}

#[test]
fn mux_cond_from_isneq_false() {
    // x != 0 with x=0 → false → b=20
    compile_and_verify(
        "witness x\nwitness a\nwitness b\npublic out\nassert_eq(mux(x != 0, a, b), out)",
        &[("x", fe(0)), ("a", fe(10)), ("b", fe(20)), ("out", fe(20))],
    );
}

#[test]
fn mux_cond_from_and() {
    // (p && q) with p=1, q=1 → true → a
    compile_and_verify(
        "witness p\nwitness q\nwitness a\nwitness b\npublic out\nassert_eq(mux(p && q, a, b), out)",
        &[
            ("p", fe(1)),
            ("q", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn mux_cond_from_and_false() {
    // (p && q) with p=1, q=0 → false → b
    compile_and_verify(
        "witness p\nwitness q\nwitness a\nwitness b\npublic out\nassert_eq(mux(p && q, a, b), out)",
        &[
            ("p", fe(1)),
            ("q", fe(0)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(20)),
        ],
    );
}

#[test]
fn mux_cond_from_or() {
    // (p || q) with p=0, q=1 → true → a
    compile_and_verify(
        "witness p\nwitness q\nwitness a\nwitness b\npublic out\nassert_eq(mux(p || q, a, b), out)",
        &[
            ("p", fe(0)),
            ("q", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn mux_cond_from_or_false() {
    // (p || q) with p=0, q=0 → false → b
    compile_and_verify(
        "witness p\nwitness q\nwitness a\nwitness b\npublic out\nassert_eq(mux(p || q, a, b), out)",
        &[
            ("p", fe(0)),
            ("q", fe(0)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(20)),
        ],
    );
}

#[test]
fn mux_cond_from_not() {
    // !p with p=0 → true → a=10
    compile_and_verify(
        "witness p\nwitness a\nwitness b\npublic out\nassert_eq(mux(!p, a, b), out)",
        &[("p", fe(0)), ("a", fe(10)), ("b", fe(20)), ("out", fe(10))],
    );
}

#[test]
fn mux_cond_from_not_true() {
    // !p with p=1 → false → b=20
    compile_and_verify(
        "witness p\nwitness a\nwitness b\npublic out\nassert_eq(mux(!p, a, b), out)",
        &[("p", fe(1)), ("a", fe(10)), ("b", fe(20)), ("out", fe(20))],
    );
}
