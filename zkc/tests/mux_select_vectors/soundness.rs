use super::*;

// ============================================================================
// 12. Soundness — non-boolean condition must be rejected
// Source: 0xPARC zk-bug-tracker — under-constrained mux vulnerability.
// The boolean enforcement gadget cond*(1-cond)=0 must reject values ∉ {0, 1}.
// ============================================================================

#[test]
fn soundness_mux_rejects_cond_2() {
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", fe(2)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn soundness_mux_rejects_cond_42() {
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", fe(42)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn soundness_mux_rejects_cond_pminus1() {
    // p-1 is a valid field element but not boolean
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", p_minus_1()),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn soundness_mux_rejects_cond_large() {
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", fe(u32::MAX as u64)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn soundness_mux_wrong_output_sel0() {
    // cond=0 should select b=20, not a=10
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", fe(0)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn soundness_mux_wrong_output_sel1() {
    // cond=1 should select a=10, not b=20
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(20)),
        ],
    );
}

#[test]
fn soundness_mux_wrong_output_pminus1() {
    // cond=1, a=p-1, b=0 → expected p-1, not 0
    compile_expect_fail(
        MUX_SOURCE,
        &[
            ("cond", fe(1)),
            ("a", p_minus_1()),
            ("b", fe(0)),
            ("out", fe(0)),
        ],
    );
}

#[test]
fn soundness_mux_wrong_nested() {
    // Nested mux with wrong output
    compile_expect_fail(
        "witness c0\nwitness c1\nwitness a\nwitness b\nwitness c_val\npublic out\n\
         let inner = mux(c0, a, b)\nassert_eq(mux(c1, inner, c_val), out)",
        &[
            ("c0", fe(1)),
            ("c1", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("c_val", fe(30)),
            ("out", fe(99)),
        ],
    );
}
