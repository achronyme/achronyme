use super::*;

// ============================================================================
// 10. Constant folding — mux with compile-time-known condition
// Source: validates the compiler's constant propagation pass for mux.
// ============================================================================

#[test]
fn mux_const_cond_1() {
    // mux(1, a, b) should fold at compile time → a
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(mux(1, a, b), out)",
        &[("a", fe(42)), ("b", fe(99)), ("out", fe(42))],
    );
}

#[test]
fn mux_const_cond_0() {
    // mux(0, a, b) should fold at compile time → b
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(mux(0, a, b), out)",
        &[("a", fe(42)), ("b", fe(99)), ("out", fe(99))],
    );
}

#[test]
fn mux_const_cond_true() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(mux(true, a, b), out)",
        &[("a", fe(10)), ("b", fe(20)), ("out", fe(10))],
    );
}

#[test]
fn mux_const_cond_false() {
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(mux(false, a, b), out)",
        &[("a", fe(10)), ("b", fe(20)), ("out", fe(20))],
    );
}

#[test]
fn mux_all_const_1_10_20() {
    // Fully constant mux should fold entirely
    compile_and_verify(
        "public out\nassert_eq(mux(1, 10, 20), out)",
        &[("out", fe(10))],
    );
}

#[test]
fn mux_all_const_0_10_20() {
    compile_and_verify(
        "public out\nassert_eq(mux(0, 10, 20), out)",
        &[("out", fe(20))],
    );
}

#[test]
fn mux_const_cond_reduces_constraints() {
    // Constant condition should produce fewer constraints than witness condition.
    let n_const = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(mux(1, a, b), out)",
        &[("a", fe(10)), ("b", fe(20)), ("out", fe(10))],
    );
    let n_witness = compile_and_verify(
        MUX_SOURCE,
        &[
            ("cond", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
    assert!(
        n_const <= n_witness,
        "constant folding should not increase constraints: const={n_const}, witness={n_witness}"
    );
}

#[test]
fn mux_const_branches_const_cond() {
    // mux(1, 100, 200) = 100 — everything is constant
    let n = compile_and_verify(
        "public out\nassert_eq(mux(1, 100, 200), out)",
        &[("out", fe(100))],
    );
    assert!(
        n <= 2,
        "fully constant mux should produce minimal constraints: {n}"
    );
}

// ============================================================================
// 11. Constraint count regression
// Source: R1CS cost analysis — mux with proven boolean cond = 1 constraint.
// Without boolean proof: 2 constraints (1 enforcement + 1 mux).
// ============================================================================

#[test]
fn constraint_count_mux_basic() {
    let n = compile_and_verify(
        MUX_SOURCE,
        &[
            ("cond", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
    // mux: 1-2 constraints + 1 assert_eq, plus boolean enforcement
    assert!(n <= 5, "basic mux constraint count too high: {n}");
}

#[test]
fn constraint_count_mux_proven_boolean() {
    // Condition from a comparison (proven boolean) → no enforcement needed.
    let n = compile_and_verify(
        "witness x\nwitness a\nwitness b\npublic out\nassert_eq(mux(x == 5, a, b), out)",
        &[("x", fe(5)), ("a", fe(10)), ("b", fe(20)), ("out", fe(10))],
    );
    // IsEq (~2) + mux (1, proven) + assert_eq (1) → should be modest
    assert!(n <= 8, "proven-boolean mux constraint count too high: {n}");
}

#[test]
fn constraint_count_nested_mux() {
    // Two chained mux operations
    let n = compile_and_verify(
        "witness c0\nwitness c1\nwitness a\nwitness b\nwitness c_val\npublic out\n\
         let inner = mux(c0, a, b)\nassert_eq(mux(c1, inner, c_val), out)",
        &[
            ("c0", fe(1)),
            ("c1", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("c_val", fe(30)),
            ("out", fe(10)),
        ],
    );
    // 2 mux (2-4 each) + 1 assert_eq → expect ≤ 10
    assert!(n <= 12, "nested mux constraint count too high: {n}");
}

#[test]
fn constraint_count_mux4() {
    // 4-to-1 multiplexer: 3 mux operations
    let n = compile_and_verify(
        MUX4_SOURCE,
        &[
            ("s0", fe(0)),
            ("s1", fe(0)),
            ("v0", fe(10)),
            ("v1", fe(20)),
            ("v2", fe(30)),
            ("v3", fe(40)),
            ("out", fe(10)),
        ],
    );
    // 3 mux + 1 assert_eq → expect ≤ 15
    assert!(n <= 16, "mux4 constraint count too high: {n}");
}
