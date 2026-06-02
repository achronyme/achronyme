use super::*;

// ============================================================================
// 13. Mux with if/else syntax (compiles to same Mux IR instruction)
// Source: Achronyme DSL — if/else in circuit mode → Mux lowering.
// ============================================================================

#[test]
fn if_else_sel_true() {
    compile_and_verify(
        "witness c\nwitness a\nwitness b\npublic out\nlet r = if c { a } else { b }\nassert_eq(r, out)",
        &[("c", fe(1)), ("a", fe(10)), ("b", fe(20)), ("out", fe(10))],
    );
}

#[test]
fn if_else_sel_false() {
    compile_and_verify(
        "witness c\nwitness a\nwitness b\npublic out\nlet r = if c { a } else { b }\nassert_eq(r, out)",
        &[("c", fe(0)), ("a", fe(10)), ("b", fe(20)), ("out", fe(20))],
    );
}

#[test]
fn if_else_nested() {
    // if c1 { if c0 { a } else { b } } else { d }
    compile_and_verify(
        "witness c0\nwitness c1\nwitness a\nwitness b\nwitness d\npublic out\n\
         let inner = if c0 { a } else { b }\nlet r = if c1 { inner } else { d }\nassert_eq(r, out)",
        &[
            ("c0", fe(1)),
            ("c1", fe(1)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("d", fe(30)),
            ("out", fe(10)),
        ],
    );
}

#[test]
fn if_else_with_arithmetic_in_branches() {
    // if c { a + b } else { a * b }
    // c=1, a=3, b=4 → 3+4=7
    compile_and_verify(
        "witness c\nwitness a\nwitness b\npublic out\n\
         let r = if c { a + b } else { a * b }\nassert_eq(r, out)",
        &[("c", fe(1)), ("a", fe(3)), ("b", fe(4)), ("out", fe(7))],
    );
}

#[test]
fn if_else_with_arithmetic_false_branch() {
    // c=0, a=3, b=4 → 3*4=12
    compile_and_verify(
        "witness c\nwitness a\nwitness b\npublic out\n\
         let r = if c { a + b } else { a * b }\nassert_eq(r, out)",
        &[("c", fe(0)), ("a", fe(3)), ("b", fe(4)), ("out", fe(12))],
    );
}

// ============================================================================
// 14. Mux linearity — mux(c, a, b) = c*(a-b) + b (algebraic verification)
// Tests that confirm the R1CS formula directly.
// ============================================================================

#[test]
fn mux_linearity_formula_sel1() {
    // mux(1, 100, 40) = 1*(100-40) + 40 = 100
    compile_and_verify(
        MUX_SOURCE,
        &[
            ("cond", fe(1)),
            ("a", fe(100)),
            ("b", fe(40)),
            ("out", fe(100)),
        ],
    );
}

#[test]
fn mux_linearity_formula_sel0() {
    // mux(0, 100, 40) = 0*(100-40) + 40 = 40
    compile_and_verify(
        MUX_SOURCE,
        &[
            ("cond", fe(0)),
            ("a", fe(100)),
            ("b", fe(40)),
            ("out", fe(40)),
        ],
    );
}

#[test]
fn mux_preserves_field_element_identity() {
    // mux should return the exact same field element, not a reduced version
    let large = fe_str("12345678901234567890123456789012345678");
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(1)), ("a", large), ("b", fe(0)), ("out", large)],
    );
}

#[test]
fn mux_preserves_field_element_identity_sel0() {
    let large = fe_str("12345678901234567890123456789012345678");
    compile_and_verify(
        MUX_SOURCE,
        &[("cond", fe(0)), ("a", fe(0)), ("b", large), ("out", large)],
    );
}

// ============================================================================
// 15. Mux stress — many consecutive mux operations
// Source: validates the compiler handles deep mux chains without overflow.
// ============================================================================

#[test]
fn mux_chain_depth_5() {
    let source = "\
        witness c\nwitness v0\nwitness v1\npublic out\n\
        let r0 = mux(c, v0, v1)\n\
        let r1 = mux(c, r0, v1)\n\
        let r2 = mux(c, r1, v1)\n\
        let r3 = mux(c, r2, v1)\n\
        let r4 = mux(c, r3, v1)\n\
        assert_eq(r4, out)";
    // c=1: r0=v0, r1=r0=v0, ..., r4=v0
    compile_and_verify(
        source,
        &[
            ("c", fe(1)),
            ("v0", fe(42)),
            ("v1", fe(99)),
            ("out", fe(42)),
        ],
    );
}

#[test]
fn mux_chain_depth_5_sel0() {
    let source = "\
        witness c\nwitness v0\nwitness v1\npublic out\n\
        let r0 = mux(c, v0, v1)\n\
        let r1 = mux(c, r0, v1)\n\
        let r2 = mux(c, r1, v1)\n\
        let r3 = mux(c, r2, v1)\n\
        let r4 = mux(c, r3, v1)\n\
        assert_eq(r4, out)";
    // c=0: r0=v1, r1=v1, ..., r4=v1
    compile_and_verify(
        source,
        &[
            ("c", fe(0)),
            ("v0", fe(42)),
            ("v1", fe(99)),
            ("out", fe(99)),
        ],
    );
}

#[test]
fn mux_chain_alternating_conditions() {
    // Different conditions at each level
    let source = "\
        witness c0\nwitness c1\nwitness c2\nwitness c3\n\
        witness a\nwitness b\npublic out\n\
        let r0 = mux(c0, a, b)\n\
        let r1 = mux(c1, a, r0)\n\
        let r2 = mux(c2, r1, b)\n\
        let r3 = mux(c3, r2, a)\n\
        assert_eq(r3, out)";
    // c0=1→a=10, c1=0→r0=10, c2=1→r1=10, c3=0→a=10
    compile_and_verify(
        source,
        &[
            ("c0", fe(1)),
            ("c1", fe(0)),
            ("c2", fe(1)),
            ("c3", fe(0)),
            ("a", fe(10)),
            ("b", fe(20)),
            ("out", fe(10)),
        ],
    );
}
