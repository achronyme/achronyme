use super::*;

// ============================================================================
// 5. Nested mux — chained conditional selections
// Source: ZoKrates stdlib — nested conditional patterns for control flow.
// ============================================================================

#[test]
fn mux_nested_depth2_sel00() {
    // mux(c1, mux(c0, a, b), c_val) with c1=0 → c_val
    compile_and_verify(
        "witness c0\nwitness c1\nwitness a\nwitness b\nwitness c_val\npublic out\n\
         let inner = mux(c0, a, b)\nassert_eq(mux(c1, inner, c_val), out)",
        &[
            ("c0", fe(0)),
            ("c1", fe(0)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("c_val", fe(30)),
            ("out", fe(30)),
        ],
    );
}

#[test]
fn mux_nested_depth2_sel01() {
    // c1=0 → c_val=30
    compile_and_verify(
        "witness c0\nwitness c1\nwitness a\nwitness b\nwitness c_val\npublic out\n\
         let inner = mux(c0, a, b)\nassert_eq(mux(c1, inner, c_val), out)",
        &[
            ("c0", fe(1)),
            ("c1", fe(0)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("c_val", fe(30)),
            ("out", fe(30)),
        ],
    );
}

#[test]
fn mux_nested_depth2_sel10() {
    // c1=1 → inner. c0=0 → inner=b=20
    compile_and_verify(
        "witness c0\nwitness c1\nwitness a\nwitness b\nwitness c_val\npublic out\n\
         let inner = mux(c0, a, b)\nassert_eq(mux(c1, inner, c_val), out)",
        &[
            ("c0", fe(0)),
            ("c1", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("c_val", fe(30)),
            ("out", fe(20)),
        ],
    );
}

#[test]
fn mux_nested_depth2_sel11() {
    // c1=1 → inner. c0=1 → inner=a=10
    compile_and_verify(
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
}

#[test]
fn mux_nested_depth3_all_paths() {
    // 3-level nested mux: 8 paths (2^3 combinations of c0, c1, c2)
    let source = "\
        witness c0\nwitness c1\nwitness c2\n\
        witness v0\nwitness v1\nwitness v2\nwitness v3\n\
        public out\n\
        let m0 = mux(c0, v1, v0)\n\
        let m1 = mux(c0, v3, v2)\n\
        let m2 = mux(c1, m1, m0)\n\
        assert_eq(mux(c2, m2, v0), out)";

    let vals = [fe(100), fe(200), fe(300), fe(400)];

    // All 8 combinations of (c0, c1, c2)
    for c2 in 0..2u64 {
        for c1 in 0..2u64 {
            for c0 in 0..2u64 {
                let m0 = if c0 == 1 { vals[1] } else { vals[0] };
                let m1 = if c0 == 1 { vals[3] } else { vals[2] };
                let m2 = if c1 == 1 { m1 } else { m0 };
                let expected = if c2 == 1 { m2 } else { vals[0] };
                compile_and_verify(
                    source,
                    &[
                        ("c0", fe(c0)),
                        ("c1", fe(c1)),
                        ("c2", fe(c2)),
                        ("v0", vals[0]),
                        ("v1", vals[1]),
                        ("v2", vals[2]),
                        ("v3", vals[3]),
                        ("out", expected),
                    ],
                );
            }
        }
    }
}

// ============================================================================
// 6. 4-to-1 multiplexer via nested mux
// Source: ZoKrates stdlib — Mux4 pattern: two selection bits select one of 4 inputs.
// gnark std — selector gadget for N-way selection.
// ============================================================================

const MUX4_SOURCE: &str = "\
witness s0\nwitness s1\n\
witness v0\nwitness v1\nwitness v2\nwitness v3\n\
public out\n\
let lo = mux(s0, v1, v0)\n\
let hi = mux(s0, v3, v2)\n\
assert_eq(mux(s1, hi, lo), out)";

#[test]
fn mux4_select_00() {
    // s1=0, s0=0 → v0
    compile_and_verify(
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
}

#[test]
fn mux4_select_01() {
    // s1=0, s0=1 → v1
    compile_and_verify(
        MUX4_SOURCE,
        &[
            ("s0", fe(1)),
            ("s1", fe(0)),
            ("v0", fe(10)),
            ("v1", fe(20)),
            ("v2", fe(30)),
            ("v3", fe(40)),
            ("out", fe(20)),
        ],
    );
}

#[test]
fn mux4_select_10() {
    // s1=1, s0=0 → v2
    compile_and_verify(
        MUX4_SOURCE,
        &[
            ("s0", fe(0)),
            ("s1", fe(1)),
            ("v0", fe(10)),
            ("v1", fe(20)),
            ("v2", fe(30)),
            ("v3", fe(40)),
            ("out", fe(30)),
        ],
    );
}

#[test]
fn mux4_select_11() {
    // s1=1, s0=1 → v3
    compile_and_verify(
        MUX4_SOURCE,
        &[
            ("s0", fe(1)),
            ("s1", fe(1)),
            ("v0", fe(10)),
            ("v1", fe(20)),
            ("v2", fe(30)),
            ("v3", fe(40)),
            ("out", fe(40)),
        ],
    );
}

#[test]
fn mux4_all_indices_boundary_values() {
    let vals = [fe(0), p_minus_1(), fe(1), p_minus_2()];
    for s1 in 0..2u64 {
        for s0 in 0..2u64 {
            let idx = (s1 * 2 + s0) as usize;
            compile_and_verify(
                MUX4_SOURCE,
                &[
                    ("s0", fe(s0)),
                    ("s1", fe(s1)),
                    ("v0", vals[0]),
                    ("v1", vals[1]),
                    ("v2", vals[2]),
                    ("v3", vals[3]),
                    ("out", vals[idx]),
                ],
            );
        }
    }
}

// ============================================================================
// 7. 8-to-1 multiplexer via 3 selection bits
// Source: ZoKrates stdlib — Mux8 pattern: binary-tree of mux.
// ============================================================================

#[test]
fn mux8_all_indices() {
    let source = "\
        witness s0\nwitness s1\nwitness s2\n\
        witness v0\nwitness v1\nwitness v2\nwitness v3\n\
        witness v4\nwitness v5\nwitness v6\nwitness v7\n\
        public out\n\
        let m00 = mux(s0, v1, v0)\n\
        let m01 = mux(s0, v3, v2)\n\
        let m10 = mux(s0, v5, v4)\n\
        let m11 = mux(s0, v7, v6)\n\
        let n0 = mux(s1, m01, m00)\n\
        let n1 = mux(s1, m11, m10)\n\
        assert_eq(mux(s2, n1, n0), out)";

    let vals: Vec<FieldElement> = (0..8).map(|i| fe((i + 1) * 100)).collect();
    for idx in 0..8usize {
        let s0 = (idx & 1) as u64;
        let s1 = ((idx >> 1) & 1) as u64;
        let s2 = ((idx >> 2) & 1) as u64;
        compile_and_verify(
            source,
            &[
                ("s0", fe(s0)),
                ("s1", fe(s1)),
                ("s2", fe(s2)),
                ("v0", vals[0]),
                ("v1", vals[1]),
                ("v2", vals[2]),
                ("v3", vals[3]),
                ("v4", vals[4]),
                ("v5", vals[5]),
                ("v6", vals[6]),
                ("v7", vals[7]),
                ("out", vals[idx]),
            ],
        );
    }
}
