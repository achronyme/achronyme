//! Phase III — Mux/Select Circuit Vectors (R1CS, BN254 Fr)
//!
//! Exhaustive truth table and algebraic property validation for the Mux instruction.
//! Formula: result = cond * (if_true - if_false) + if_false
//!   cond=1 → if_true, cond=0 → if_false
//!
//! Industry sources:
//!   - ZoKrates stdlib (LGPL-3.0): N-way multiplexer patterns
//!     https://zokrates.github.io/toolbox/stdlib.html
//!   - gnark std (Apache-2.0): frontend.Variable selector gadget
//!     https://github.com/Consensys/gnark
//!   - arkworks r1cs-std (MIT/Apache-2.0): CondSelectGadget
//!     https://github.com/arkworks-rs/r1cs-std
//!   - 0xPARC zk-bug-tracker: under-constrained mux vulnerabilities
//!     https://github.com/0xPARC/zk-bug-tracker
//!
//! Reference: "Análisis Integral de Vectores de Prueba y Evaluación de Rendimiento
//! para Entornos de Compilación de Conocimiento Cero" (2026), §Pruebas de
//! Complejidad Moderada — Multiplexores (Mux/Select).
//!
//! Note: only numerical test vectors (not code) are used here.
//! These are facts, not copyrightable expression — compatible with our Apache-2.0.

use std::collections::HashMap;

use zkc::r1cs_backend::R1CSCompiler;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

/// BN254 scalar field order minus 1 (the maximum field element).
fn p_minus_1() -> FieldElement {
    fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616")
}

/// BN254 scalar field order minus 2.
fn p_minus_2() -> FieldElement {
    fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495615")
}

fn compile_and_verify(source: &str, inputs: &[(&str, FieldElement)]) -> usize {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let witness = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("R1CS compilation failed");
    compiler
        .cs
        .verify(&witness)
        .expect("R1CS witness verification failed");
    compiler.cs.num_constraints()
}

fn compile_expect_fail(source: &str, inputs: &[(&str, FieldElement)]) {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let result = compiler.compile_ir_with_witness(&program, &input_map);
    if let Ok(witness) = result {
        let verify = compiler.cs.verify(&witness);
        assert!(
            verify.is_err(),
            "expected verification failure but it passed"
        );
    }
}

const MUX_SOURCE: &str =
    "witness cond\nwitness a\nwitness b\npublic out\nassert_eq(mux(cond, a, b), out)";

/// Macro for parameterized mux tests with explicit expected value.
macro_rules! mux_tests {
    ($(($name:ident, $cond:expr, $a:expr, $b:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a_val: FieldElement = $a;
                let b_val: FieldElement = $b;
                let cond_val: u64 = $cond;
                let expected = if cond_val == 1 { a_val } else { b_val };
                compile_and_verify(
                    MUX_SOURCE,
                    &[("cond", fe(cond_val)), ("a", a_val), ("b", b_val), ("out", expected)],
                );
            }
        )*
    };
}

/// Macro for mux property tests (no output — uses assert_eq internally).
macro_rules! mux_property_tests {
    ($(($name:ident, $source:expr, $inputs:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify($source, &$inputs);
            }
        )*
    };
}

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
