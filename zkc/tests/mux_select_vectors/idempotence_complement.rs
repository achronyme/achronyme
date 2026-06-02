use super::*;

// ============================================================================
// 3. Algebraic properties — idempotence
// mux(c, x, x) = x for any condition c and value x.
// Source: gnark std — CondSelectGadget identity property.
// ============================================================================

#[test]
fn mux_idempotent_sel0_zero() {
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(0)), ("a", fe(0)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn mux_idempotent_sel1_zero() {
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(1)), ("a", fe(0)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn mux_idempotent_sel0_one() {
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(0)), ("a", fe(1)), ("b", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn mux_idempotent_sel1_one() {
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(1)), ("a", fe(1)), ("b", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn mux_idempotent_sel0_42() {
    compile_and_verify(
        MUX_SOURCE,
        &[
            ("cond", fe(0)),
            ("a", fe(42)),
            ("b", fe(42)),
            ("out", fe(42)),
        ],
    );
}

#[test]
fn mux_idempotent_sel1_42() {
    compile_and_verify(
        MUX_SOURCE,
        &[
            ("cond", fe(1)),
            ("a", fe(42)),
            ("b", fe(42)),
            ("out", fe(42)),
        ],
    );
}

#[test]
fn mux_idempotent_sel0_pminus1() {
    let v = p_minus_1();
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(0)), ("a", v), ("b", v), ("out", v)],
    );
}

#[test]
fn mux_idempotent_sel1_pminus1() {
    let v = p_minus_1();
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(1)), ("a", v), ("b", v), ("out", v)],
    );
}

#[test]
fn mux_idempotent_exhaustive() {
    let values = [
        fe(0),
        fe(1),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
    ];
    for &v in &values {
        for cond in [0u64, 1] {
            compile_and_verify(
                MUX_SOURCE,
                &[("cond", fe(cond)), ("a", v), ("b", v), ("out", v)],
            );
        }
    }
}

// ============================================================================
// 4. Complement property — mux(c, a, b) == mux(!c, b, a)
// Flipping the condition and swapping branches gives the same result.
// Source: Boolean algebra symmetry; gnark CondSelectGadget.
// ============================================================================

const MUX_COMPLEMENT_SOURCE: &str = "\
witness c\n\
witness a\n\
witness b\n\
assert_eq(mux(c, a, b), mux(!c, b, a))";

mux_property_tests! {
    (mux_complement_0_10_20, MUX_COMPLEMENT_SOURCE, [("c", fe(0)), ("a", fe(10)), ("b", fe(20))]),
    (mux_complement_1_10_20, MUX_COMPLEMENT_SOURCE, [("c", fe(1)), ("a", fe(10)), ("b", fe(20))]),
    (mux_complement_0_zero_pminus1, MUX_COMPLEMENT_SOURCE, [("c", fe(0)), ("a", fe(0)), ("b", p_minus_1())]),
    (mux_complement_1_zero_pminus1, MUX_COMPLEMENT_SOURCE, [("c", fe(1)), ("a", fe(0)), ("b", p_minus_1())]),
    (mux_complement_0_pminus1_one, MUX_COMPLEMENT_SOURCE, [("c", fe(0)), ("a", p_minus_1()), ("b", fe(1))]),
    (mux_complement_1_pminus1_one, MUX_COMPLEMENT_SOURCE, [("c", fe(1)), ("a", p_minus_1()), ("b", fe(1))]),
    (mux_complement_0_42_42, MUX_COMPLEMENT_SOURCE, [("c", fe(0)), ("a", fe(42)), ("b", fe(42))]),
    (mux_complement_1_42_42, MUX_COMPLEMENT_SOURCE, [("c", fe(1)), ("a", fe(42)), ("b", fe(42))]),
}
