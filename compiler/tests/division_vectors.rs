//! Phase III — Division / Modular Inverse Circuit Vectors (R1CS, BN254 Fr)
//!
//! Exhaustive validation of the Div instruction which computes modular
//! multiplicative inverse: a / b = a * b^{-1} mod r.
//!
//! Achronyme does NOT have integer division. All division is field inversion.
//! Div(x, 0) must induce catastrophic failure at witness generation time.
//!
//! Industry sources:
//!   - gnark std (Apache-2.0): Div gadget + modular inverse
//!     https://github.com/Consensys/gnark
//!   - arkworks r1cs-std (MIT/Apache-2.0): AllocatedFp::inverse()
//!     https://github.com/arkworks-rs/r1cs-std
//!   - Noir stdlib (MIT/Apache-2.0): field div + inverse
//!     https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!   - circomspect (trailofbits): under-constrained division analysis
//!     https://github.com/trailofbits/circomspect
//!
//! Reference: "Análisis Integral de Vectores de Prueba y Evaluación de Rendimiento
//! para Entornos de Compilación de Conocimiento Cero" (2026), §Inversión Multiplicativa.
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

/// BN254 scalar field order minus 1.
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

const DIV_SOURCE: &str = "public out\nwitness a\nwitness b\nassert_eq(a / b, out)";

/// Macro for parameterized division tests.
macro_rules! div_tests {
    ($(($name:ident, $a:expr, $b:expr, $expected:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    DIV_SOURCE,
                    &[("a", $a), ("b", $b), ("out", $expected)],
                );
            }
        )*
    };
}

/// Macro for division property tests (circuit with assert_eq, no public out).
macro_rules! div_property_tests {
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
// 1. Basic division — integer-like results
// Source: gnark std — frontend.Div with known quotients.
// ============================================================================

div_tests! {
    (div_42_by_7, fe(42), fe(7), fe(6)),
    (div_100_by_10, fe(100), fe(10), fe(10)),
    (div_6_by_3, fe(6), fe(3), fe(2)),
    (div_1_by_1, fe(1), fe(1), fe(1)),
    (div_0_by_1, fe(0), fe(1), fe(0)),
    (div_0_by_42, fe(0), fe(42), fe(0)),
    (div_0_by_pminus1, fe(0), p_minus_1(), fe(0)),
    (div_10_by_2, fe(10), fe(2), fe(5)),
    (div_12_by_4, fe(12), fe(4), fe(3)),
    (div_1000000_by_1000, fe(1_000_000), fe(1000), fe(1000)),
    (div_255_by_5, fe(255), fe(5), fe(51)),
    (div_256_by_16, fe(256), fe(16), fe(16)),
    (div_65536_by_256, fe(65536), fe(256), fe(256)),
}

// ============================================================================
// 2. Identity property: a / 1 = a
// Source: field axiom — multiplicative identity inverse is 1.
// ============================================================================

div_tests! {
    (div_by_one_zero, fe(0), fe(1), fe(0)),
    (div_by_one_one, fe(1), fe(1), fe(1)),
    (div_by_one_42, fe(42), fe(1), fe(42)),
    (div_by_one_255, fe(255), fe(1), fe(255)),
    (div_by_one_u32max, fe(u32::MAX as u64), fe(1), fe(u32::MAX as u64)),
    (div_by_one_u64max, fe(u64::MAX), fe(1), fe(u64::MAX)),
    (div_by_one_pminus1, p_minus_1(), fe(1), p_minus_1()),
    (div_by_one_pminus2, p_minus_2(), fe(1), p_minus_2()),
}

#[test]
fn div_by_one_exhaustive() {
    let values = [
        fe(0),
        fe(1),
        fe(2),
        fe(42),
        fe(255),
        fe(256),
        fe(65535),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &v in &values {
        compile_and_verify(DIV_SOURCE, &[("a", v), ("b", fe(1)), ("out", v)]);
    }
}

// ============================================================================
// 3. Self-division: a / a = 1 (for a ≠ 0)
// Source: field axiom — a * a^{-1} = 1.
// ============================================================================

div_tests! {
    (div_self_1, fe(1), fe(1), fe(1)),
    (div_self_2, fe(2), fe(2), fe(1)),
    (div_self_42, fe(42), fe(42), fe(1)),
    (div_self_255, fe(255), fe(255), fe(1)),
    (div_self_u32max, fe(u32::MAX as u64), fe(u32::MAX as u64), fe(1)),
    (div_self_u64max, fe(u64::MAX), fe(u64::MAX), fe(1)),
    (div_self_pminus1, p_minus_1(), p_minus_1(), fe(1)),
    (div_self_pminus2, p_minus_2(), p_minus_2(), fe(1)),
}

#[test]
fn div_self_exhaustive() {
    let values = [
        fe(1),
        fe(2),
        fe(3),
        fe(42),
        fe(100),
        fe(255),
        fe(256),
        fe(65535),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &v in &values {
        compile_and_verify(DIV_SOURCE, &[("a", v), ("b", v), ("out", fe(1))]);
    }
}

// ============================================================================
// 4. Zero numerator: 0 / b = 0 (for b ≠ 0)
// Source: field axiom — 0 * b^{-1} = 0.
// ============================================================================

#[test]
fn div_zero_numerator_exhaustive() {
    let divisors = [
        fe(1),
        fe(2),
        fe(3),
        fe(42),
        fe(255),
        fe(256),
        fe(65535),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &d in &divisors {
        compile_and_verify(DIV_SOURCE, &[("a", fe(0)), ("b", d), ("out", fe(0))]);
    }
}

// ============================================================================
// 5. Division by zero — must fail
// Source: circomspect analysis — Div(x, 0) produces under-constrained circuits.
// Achronyme catches this at witness generation time (catastrophic failure).
// ============================================================================

#[test]
fn div_by_zero_one() {
    compile_expect_fail(DIV_SOURCE, &[("a", fe(1)), ("b", fe(0)), ("out", fe(0))]);
}

#[test]
fn div_by_zero_42() {
    compile_expect_fail(DIV_SOURCE, &[("a", fe(42)), ("b", fe(0)), ("out", fe(0))]);
}

#[test]
fn div_by_zero_zero() {
    compile_expect_fail(DIV_SOURCE, &[("a", fe(0)), ("b", fe(0)), ("out", fe(0))]);
}

#[test]
fn div_by_zero_pminus1() {
    compile_expect_fail(
        DIV_SOURCE,
        &[("a", p_minus_1()), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn div_by_zero_large() {
    compile_expect_fail(
        DIV_SOURCE,
        &[("a", fe(u64::MAX)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn div_by_zero_in_expression() {
    // Division by zero within a larger expression
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a / b + 1, out)",
        &[("a", fe(10)), ("b", fe(0)), ("out", fe(0))],
    );
}

// ============================================================================
// 6. Modular inverse properties
// Source: gnark-crypto field element tests — Fermat's little theorem: a^{-1} = a^{p-2}.
// Key identities:
//   inv(1) = 1
//   inv(p-1) = p-1  (because (p-1)*(p-1) = p^2-2p+1 ≡ 1 mod p)
//   inv(2) = (p+1)/2
// ============================================================================

#[test]
fn inv_one_is_one() {
    // 1 / 1 = 1
    compile_and_verify(DIV_SOURCE, &[("a", fe(1)), ("b", fe(1)), ("out", fe(1))]);
}

#[test]
fn inv_pminus1_is_pminus1() {
    // (p-1) * (p-1) = p^2 - 2p + 1 ≡ 1 mod p
    // So 1 / (p-1) = p-1
    compile_and_verify(
        DIV_SOURCE,
        &[("a", fe(1)), ("b", p_minus_1()), ("out", p_minus_1())],
    );
}

#[test]
fn inv_2_is_half_p_plus_1() {
    // inv(2) = (p+1)/2
    let inv2 =
        fe_str("10944121435919637611123202872628637544274182200208017171849102093287904247809");
    compile_and_verify(DIV_SOURCE, &[("a", fe(1)), ("b", fe(2)), ("out", inv2)]);
}

#[test]
fn inv_3() {
    // Verify 1/3 by checking 3 * (1/3) = 1
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", fe(3)), ("out", fe(1))],
    );
}

#[test]
fn inv_7() {
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", fe(7)), ("out", fe(1))],
    );
}

#[test]
fn inv_pminus2() {
    // Verify 1/(p-2) by roundtrip
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", p_minus_2()), ("out", fe(1))],
    );
}

// ============================================================================
// 7. Roundtrip property: (a / b) * b = a
// Source: field axiom — a * b^{-1} * b = a for b ≠ 0.
// gnark std — Div + Mul roundtrip verification.
// ============================================================================

const ROUNDTRIP_SOURCE: &str =
    "witness a\nwitness b\npublic expected\nlet q = a / b\nassert_eq(q * b, expected)";

div_property_tests! {
    (roundtrip_42_7, ROUNDTRIP_SOURCE, [("a", fe(42)), ("b", fe(7)), ("expected", fe(42))]),
    (roundtrip_1_1, ROUNDTRIP_SOURCE, [("a", fe(1)), ("b", fe(1)), ("expected", fe(1))]),
    (roundtrip_100_10, ROUNDTRIP_SOURCE, [("a", fe(100)), ("b", fe(10)), ("expected", fe(100))]),
    (roundtrip_0_5, ROUNDTRIP_SOURCE, [("a", fe(0)), ("b", fe(5)), ("expected", fe(0))]),
    (roundtrip_pminus1_1, ROUNDTRIP_SOURCE, [("a", p_minus_1()), ("b", fe(1)), ("expected", p_minus_1())]),
    (roundtrip_pminus1_pminus1, ROUNDTRIP_SOURCE, [("a", p_minus_1()), ("b", p_minus_1()), ("expected", p_minus_1())]),
    (roundtrip_pminus2_2, ROUNDTRIP_SOURCE, [("a", p_minus_2()), ("b", fe(2)), ("expected", p_minus_2())]),
    (roundtrip_1_pminus1, ROUNDTRIP_SOURCE, [("a", fe(1)), ("b", p_minus_1()), ("expected", fe(1))]),
}

#[test]
fn roundtrip_exhaustive() {
    let numerators = [
        fe(0),
        fe(1),
        fe(2),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        p_minus_1(),
    ];
    let denominators = [
        fe(1),
        fe(2),
        fe(3),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        p_minus_1(),
        p_minus_2(),
    ];
    for &a in &numerators {
        for &b in &denominators {
            compile_and_verify(ROUNDTRIP_SOURCE, &[("a", a), ("b", b), ("expected", a)]);
        }
    }
}

// ============================================================================
// 8. Inverse roundtrip: b * (1 / b) = 1
// Source: field axiom — multiplicative inverse.
// ============================================================================

const INV_ROUNDTRIP_SOURCE: &str = "witness b\npublic out\nassert_eq(b * (1 / b), out)";

div_property_tests! {
    (inv_roundtrip_1, INV_ROUNDTRIP_SOURCE, [("b", fe(1)), ("out", fe(1))]),
    (inv_roundtrip_2, INV_ROUNDTRIP_SOURCE, [("b", fe(2)), ("out", fe(1))]),
    (inv_roundtrip_3, INV_ROUNDTRIP_SOURCE, [("b", fe(3)), ("out", fe(1))]),
    (inv_roundtrip_7, INV_ROUNDTRIP_SOURCE, [("b", fe(7)), ("out", fe(1))]),
    (inv_roundtrip_42, INV_ROUNDTRIP_SOURCE, [("b", fe(42)), ("out", fe(1))]),
    (inv_roundtrip_255, INV_ROUNDTRIP_SOURCE, [("b", fe(255)), ("out", fe(1))]),
    (inv_roundtrip_u32max, INV_ROUNDTRIP_SOURCE, [("b", fe(u32::MAX as u64)), ("out", fe(1))]),
    (inv_roundtrip_u64max, INV_ROUNDTRIP_SOURCE, [("b", fe(u64::MAX)), ("out", fe(1))]),
    (inv_roundtrip_pminus1, INV_ROUNDTRIP_SOURCE, [("b", p_minus_1()), ("out", fe(1))]),
    (inv_roundtrip_pminus2, INV_ROUNDTRIP_SOURCE, [("b", p_minus_2()), ("out", fe(1))]),
}

#[test]
fn inv_roundtrip_exhaustive() {
    let values = [
        fe(1),
        fe(2),
        fe(3),
        fe(5),
        fe(7),
        fe(11),
        fe(13),
        fe(17),
        fe(19),
        fe(23),
        fe(42),
        fe(100),
        fe(255),
        fe(256),
        fe(1000),
        fe(65535),
        fe(65536),
        fe(u32::MAX as u64),
        fe(u64::MAX),
        p_minus_1(),
        p_minus_2(),
    ];
    for &v in &values {
        compile_and_verify(INV_ROUNDTRIP_SOURCE, &[("b", v), ("out", fe(1))]);
    }
}

// ============================================================================
// 9. Double inverse: 1 / (1 / a) = a
// Source: field axiom — (a^{-1})^{-1} = a.
// ============================================================================

const DOUBLE_INV_SOURCE: &str = "witness a\npublic out\nlet inv = 1 / a\nassert_eq(1 / inv, out)";

div_property_tests! {
    (double_inv_1, DOUBLE_INV_SOURCE, [("a", fe(1)), ("out", fe(1))]),
    (double_inv_2, DOUBLE_INV_SOURCE, [("a", fe(2)), ("out", fe(2))]),
    (double_inv_42, DOUBLE_INV_SOURCE, [("a", fe(42)), ("out", fe(42))]),
    (double_inv_pminus1, DOUBLE_INV_SOURCE, [("a", p_minus_1()), ("out", p_minus_1())]),
    (double_inv_pminus2, DOUBLE_INV_SOURCE, [("a", p_minus_2()), ("out", p_minus_2())]),
    (double_inv_u64max, DOUBLE_INV_SOURCE, [("a", fe(u64::MAX)), ("out", fe(u64::MAX))]),
}

#[test]
fn double_inv_exhaustive() {
    let values = [
        fe(1),
        fe(2),
        fe(3),
        fe(7),
        fe(42),
        fe(255),
        fe(u32::MAX as u64),
        p_minus_1(),
    ];
    for &v in &values {
        compile_and_verify(DOUBLE_INV_SOURCE, &[("a", v), ("out", v)]);
    }
}

// ============================================================================
// 10. Distributive property: (a + b) / c = a/c + b/c
// Source: field axiom — distributivity of multiplication over addition.
// ============================================================================

const DISTRIBUTIVE_SOURCE: &str = "\
witness a\nwitness b\nwitness c\n\
assert_eq((a + b) / c, a / c + b / c)";

div_property_tests! {
    (distributive_6_4_2, DISTRIBUTIVE_SOURCE, [("a", fe(6)), ("b", fe(4)), ("c", fe(2))]),
    (distributive_10_20_5, DISTRIBUTIVE_SOURCE, [("a", fe(10)), ("b", fe(20)), ("c", fe(5))]),
    (distributive_100_200_10, DISTRIBUTIVE_SOURCE, [("a", fe(100)), ("b", fe(200)), ("c", fe(10))]),
    (distributive_1_pminus1_2, DISTRIBUTIVE_SOURCE, [("a", fe(1)), ("b", p_minus_1()), ("c", fe(2))]),
    (distributive_42_0_7, DISTRIBUTIVE_SOURCE, [("a", fe(42)), ("b", fe(0)), ("c", fe(7))]),
    (distributive_pminus1_1_pminus1, DISTRIBUTIVE_SOURCE, [("a", p_minus_1()), ("b", fe(1)), ("c", p_minus_1())]),
}

#[test]
fn distributive_exhaustive() {
    let values = [fe(1), fe(2), fe(3), fe(7), fe(42), fe(100), p_minus_1()];
    let divisors = [fe(1), fe(2), fe(3), fe(7), fe(42), p_minus_1()];
    for &a in &values {
        for &b in &values {
            for &c in &divisors {
                compile_and_verify(DISTRIBUTIVE_SOURCE, &[("a", a), ("b", b), ("c", c)]);
            }
        }
    }
}

// ============================================================================
// 11. Non-trivial modular results (a / b where result is not a small integer)
// Source: gnark-crypto field element tests — verifying modular arithmetic.
// ============================================================================

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
// 16. Wrong witness rejection
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

// ============================================================================
// 17. Boundary value division
// Source: arkworks test-templates — boundary values for field operations.
// ============================================================================

#[test]
fn div_pminus1_by_pminus1() {
    // (p-1)/(p-1) = 1
    compile_and_verify(
        DIV_SOURCE,
        &[("a", p_minus_1()), ("b", p_minus_1()), ("out", fe(1))],
    );
}

#[test]
fn div_pminus2_by_pminus1() {
    // (p-2)/(p-1) — verify via roundtrip
    compile_and_verify(
        ROUNDTRIP_SOURCE,
        &[
            ("a", p_minus_2()),
            ("b", p_minus_1()),
            ("expected", p_minus_2()),
        ],
    );
}

#[test]
fn div_1_by_pminus2() {
    compile_and_verify(
        "witness b\npublic out\nlet inv = 1 / b\nassert_eq(b * inv, out)",
        &[("b", p_minus_2()), ("out", fe(1))],
    );
}

#[test]
fn div_u64max_by_u64max() {
    compile_and_verify(
        DIV_SOURCE,
        &[("a", fe(u64::MAX)), ("b", fe(u64::MAX)), ("out", fe(1))],
    );
}

#[test]
fn div_large_by_small() {
    // (p-1) / 2 — result * 2 should equal p-1
    compile_and_verify(
        ROUNDTRIP_SOURCE,
        &[("a", p_minus_1()), ("b", fe(2)), ("expected", p_minus_1())],
    );
}

// ============================================================================
// 18. Negation via division: a / (p-1) = -a (since p-1 ≡ -1 mod p)
// Source: field axiom — (p-1) is the additive inverse of 1.
// ============================================================================

#[test]
fn div_by_neg1_is_negation() {
    // 5 / (p-1) = 5 * (p-1)^{-1} = 5 * (p-1) = -5 = p-5
    // Because (p-1)^{-1} = p-1 (since (p-1)^2 = 1 mod p)
    let p_minus_5 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495612");
    compile_and_verify(
        DIV_SOURCE,
        &[("a", fe(5)), ("b", p_minus_1()), ("out", p_minus_5)],
    );
}

#[test]
fn div_by_neg1_roundtrip() {
    // a / (p-1) * (p-1) = a
    compile_and_verify(
        ROUNDTRIP_SOURCE,
        &[("a", fe(42)), ("b", p_minus_1()), ("expected", fe(42))],
    );
}

// ============================================================================
// 19. Associativity of inverse: (a/b) / c = a / (b*c)
// Source: field axiom — a * b^{-1} * c^{-1} = a * (b*c)^{-1}
// ============================================================================

#[test]
fn div_associative_simple() {
    // (60/3)/4 = 5, and 60/(3*4) = 60/12 = 5
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\n\
         assert_eq(a / b / c, a / (b * c))",
        &[("a", fe(60)), ("b", fe(3)), ("c", fe(4)), ("out", fe(0))],
    );
}

#[test]
fn div_associative_primes() {
    compile_and_verify(
        "witness a\nwitness b\nwitness c\n\
         assert_eq(a / b / c, a / (b * c))",
        &[("a", fe(210)), ("b", fe(7)), ("c", fe(5))],
    );
}

#[test]
fn div_associative_large() {
    compile_and_verify(
        "witness a\nwitness b\nwitness c\n\
         assert_eq(a / b / c, a / (b * c))",
        &[("a", p_minus_1()), ("b", fe(42)), ("c", fe(7))],
    );
}

// ============================================================================
// 20. Fully constant division — compile-time folding
// ============================================================================

#[test]
fn div_all_const_42_7() {
    compile_and_verify("public out\nassert_eq(42 / 7, out)", &[("out", fe(6))]);
}

#[test]
fn div_all_const_100_10() {
    compile_and_verify("public out\nassert_eq(100 / 10, out)", &[("out", fe(10))]);
}

#[test]
fn div_all_const_reduces_constraints() {
    let n = compile_and_verify("public out\nassert_eq(42 / 7, out)", &[("out", fe(6))]);
    assert!(
        n <= 2,
        "fully constant div should produce minimal constraints: {n}"
    );
}
