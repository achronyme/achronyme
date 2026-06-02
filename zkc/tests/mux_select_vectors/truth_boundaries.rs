use super::*;

// ============================================================================
// 1. Basic truth table — mux(0, a, b) = b, mux(1, a, b) = a
// Source: R1CS native quadratic constraint: result = cond * (a - b) + b
// ============================================================================

mux_tests! {
    (mux_sel0_returns_b_simple, 0, fe(10), fe(20)),
    (mux_sel1_returns_a_simple, 1, fe(10), fe(20)),
    (mux_sel0_both_zero, 0, fe(0), fe(0)),
    (mux_sel1_both_zero, 1, fe(0), fe(0)),
    (mux_sel0_both_one, 0, fe(1), fe(1)),
    (mux_sel1_both_one, 1, fe(1), fe(1)),
    (mux_sel0_a_zero_b_one, 0, fe(0), fe(1)),
    (mux_sel1_a_zero_b_one, 1, fe(0), fe(1)),
    (mux_sel0_a_one_b_zero, 0, fe(1), fe(0)),
    (mux_sel1_a_one_b_zero, 1, fe(1), fe(0)),
}

// ============================================================================
// 2. Boundary values — field element extremes
// Source: arkworks test-templates methodology — boundary value analysis.
// ============================================================================

mux_tests! {
    // Zero and p-1
    (mux_sel0_zero_pminus1, 0, fe(0), p_minus_1()),
    (mux_sel1_zero_pminus1, 1, fe(0), p_minus_1()),
    (mux_sel0_pminus1_zero, 0, p_minus_1(), fe(0)),
    (mux_sel1_pminus1_zero, 1, p_minus_1(), fe(0)),
    // p-1 and p-1
    (mux_sel0_pminus1_pminus1, 0, p_minus_1(), p_minus_1()),
    (mux_sel1_pminus1_pminus1, 1, p_minus_1(), p_minus_1()),
    // p-1 and p-2
    (mux_sel0_pminus1_pminus2, 0, p_minus_1(), p_minus_2()),
    (mux_sel1_pminus1_pminus2, 1, p_minus_1(), p_minus_2()),
    (mux_sel0_pminus2_pminus1, 0, p_minus_2(), p_minus_1()),
    (mux_sel1_pminus2_pminus1, 1, p_minus_2(), p_minus_1()),
    // One and p-1
    (mux_sel0_one_pminus1, 0, fe(1), p_minus_1()),
    (mux_sel1_one_pminus1, 1, fe(1), p_minus_1()),
    (mux_sel0_pminus1_one, 0, p_minus_1(), fe(1)),
    (mux_sel1_pminus1_one, 1, p_minus_1(), fe(1)),
    // Powers of two boundaries
    (mux_sel0_255_256, 0, fe(255), fe(256)),
    (mux_sel1_255_256, 1, fe(255), fe(256)),
    (mux_sel0_65535_65536, 0, fe(65535), fe(65536)),
    (mux_sel1_65535_65536, 1, fe(65535), fe(65536)),
    // 2^32 boundary
    (mux_sel0_u32max_zero, 0, fe(u32::MAX as u64), fe(0)),
    (mux_sel1_u32max_zero, 1, fe(u32::MAX as u64), fe(0)),
    (mux_sel0_u32max_u32max, 0, fe(u32::MAX as u64), fe(u32::MAX as u64)),
    (mux_sel1_u32max_u32max, 1, fe(u32::MAX as u64), fe(u32::MAX as u64)),
    // Large u64 values
    (mux_sel0_u64max_zero, 0, fe(u64::MAX), fe(0)),
    (mux_sel1_u64max_zero, 1, fe(u64::MAX), fe(0)),
    (mux_sel0_u64max_one, 0, fe(u64::MAX), fe(1)),
    (mux_sel1_u64max_one, 1, fe(u64::MAX), fe(1)),
    (mux_sel0_u64max_pminus1, 0, fe(u64::MAX), p_minus_1()),
    (mux_sel1_u64max_pminus1, 1, fe(u64::MAX), p_minus_1()),
    // Small values
    (mux_sel0_2_3, 0, fe(2), fe(3)),
    (mux_sel1_2_3, 1, fe(2), fe(3)),
    (mux_sel0_42_0, 0, fe(42), fe(0)),
    (mux_sel1_42_0, 1, fe(42), fe(0)),
    (mux_sel0_0_42, 0, fe(0), fe(42)),
    (mux_sel1_0_42, 1, fe(0), fe(42)),
    (mux_sel0_100_200, 0, fe(100), fe(200)),
    (mux_sel1_100_200, 1, fe(100), fe(200)),
    (mux_sel0_1000_9999, 0, fe(1000), fe(9999)),
    (mux_sel1_1000_9999, 1, fe(1000), fe(9999)),
}

// ============================================================================
// 2b. Exhaustive boundary cross-product (loop-based)
// Tests all combinations of 12 boundary values with both conditions.
// Source: gnark-crypto field element test methodology.
// ============================================================================

#[test]
fn mux_sel0_boundary_exhaustive() {
    let values = [
        fe(0),
        fe(1),
        fe(2),
        fe(42),
        fe(255),
        fe(256),
        fe(65535),
        fe(65536),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for (i, &a) in values.iter().enumerate() {
        for (j, &b) in values.iter().enumerate() {
            compile_and_verify(
                MUX_SOURCE,
                &[("cond", fe(0)), ("a", a), ("b", b), ("out", b)],
            );
            let _ = (i, j); // suppress unused warnings
        }
    }
}

#[test]
fn mux_sel1_boundary_exhaustive() {
    let values = [
        fe(0),
        fe(1),
        fe(2),
        fe(42),
        fe(255),
        fe(256),
        fe(65535),
        fe(65536),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for (i, &a) in values.iter().enumerate() {
        for (j, &b) in values.iter().enumerate() {
            compile_and_verify(
                MUX_SOURCE,
                &[("cond", fe(1)), ("a", a), ("b", b), ("out", a)],
            );
            let _ = (i, j);
        }
    }
}
