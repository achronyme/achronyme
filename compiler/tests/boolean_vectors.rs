//! Phase II — Boolean Logic Truth Table Vectors (R1CS, BN254 Fr)
//!
//! Exhaustive truth table validation for And, Or, Not instructions with
//! algebraic property verification following industry methodologies.
//!
//! Industry sources:
//!   - arkworks r1cs-std Boolean<F>:  https://github.com/arkworks-rs/r1cs-std
//!     Canonical boolean enforcement gadget: b*(1-b)=0. (MIT/Apache-2.0)
//!   - Noir stdlib field/mod.nr:      https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!     Boolean operations and truth table patterns. (MIT/Apache-2.0)
//!   - 0xPARC zk-bug-tracker:        https://github.com/0xPARC/zk-bug-tracker
//!     Under-constrained boolean vulnerability catalog.
//!
//! Reference: "Análisis Integral de Vectores de Prueba y Evaluación de Rendimiento
//! para Entornos de Compilación de Conocimiento Cero" (2026), §Vulnerabilidades y
//! Restricciones en Desigualdades Lógicas.
//!
//! License compatibility: all sources MIT/Apache-2.0, compatible with GPL-3.0.

use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

#[allow(dead_code)]
fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
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

/// Macro for parameterized binary boolean tests.
macro_rules! bool_binary_tests {
    ($(($name:ident, $source:expr, $a:expr, $b:expr, $expected:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    $source,
                    &[("a", fe($a)), ("b", fe($b)), ("out", fe($expected))],
                );
            }
        )*
    };
}

/// Macro for parameterized binary boolean property tests (no output, uses assert_eq internally).
macro_rules! bool_property_tests {
    ($(($name:ident, $source:expr, $a:expr, $b:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    $source,
                    &[("a", fe($a)), ("b", fe($b))],
                );
            }
        )*
    };
}

/// Macro for parameterized ternary boolean property tests (three witnesses).
macro_rules! bool_ternary_property_tests {
    ($(($name:ident, $source:expr, $a:expr, $b:expr, $c:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    $source,
                    &[("a", fe($a)), ("b", fe($b)), ("c", fe($c))],
                );
            }
        )*
    };
}

// ============================================================================
// NOT truth table (2 rows)
// Source: arkworks r1cs-std Boolean<F>::not() — result = 1 - operand
// ============================================================================

#[test]
fn not_0_is_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn not_1_is_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(1)), ("out", fe(0))],
    );
}

// ============================================================================
// AND truth table (4 rows)
// Source: arkworks r1cs-std Boolean<F>::and() — result = lhs * rhs
// Noir: noir_stdlib/src/field/mod.nr — boolean AND via multiplication
// ============================================================================

bool_binary_tests! {
    (and_0_0_is_0, "witness a\nwitness b\npublic out\nassert_eq(a && b, out)", 0, 0, 0),
    (and_0_1_is_0, "witness a\nwitness b\npublic out\nassert_eq(a && b, out)", 0, 1, 0),
    (and_1_0_is_0, "witness a\nwitness b\npublic out\nassert_eq(a && b, out)", 1, 0, 0),
    (and_1_1_is_1, "witness a\nwitness b\npublic out\nassert_eq(a && b, out)", 1, 1, 1),
}

// ============================================================================
// OR truth table (4 rows)
// Source: arkworks r1cs-std Boolean<F>::or() — result = a + b - a*b
// ============================================================================

bool_binary_tests! {
    (or_0_0_is_0, "witness a\nwitness b\npublic out\nassert_eq(a || b, out)", 0, 0, 0),
    (or_0_1_is_1, "witness a\nwitness b\npublic out\nassert_eq(a || b, out)", 0, 1, 1),
    (or_1_0_is_1, "witness a\nwitness b\npublic out\nassert_eq(a || b, out)", 1, 0, 1),
    (or_1_1_is_1, "witness a\nwitness b\npublic out\nassert_eq(a || b, out)", 1, 1, 1),
}

// ============================================================================
// Double negation: !!a == a
// Source: arkworks r1cs-std — Not(Not(b)) == b for Boolean<F>
// ============================================================================

#[test]
fn double_negation_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(!!a, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn double_negation_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(!!a, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

// ============================================================================
// De Morgan's first law: !(a && b) == !a || !b
// Source: Noir stdlib boolean assertion patterns; arkworks r1cs-std test suite.
// All 4 input combinations must satisfy the identity.
// ============================================================================

bool_property_tests! {
    (de_morgan_and_0_0, "witness a\nwitness b\nassert_eq(!(a && b), !a || !b)", 0, 0),
    (de_morgan_and_0_1, "witness a\nwitness b\nassert_eq(!(a && b), !a || !b)", 0, 1),
    (de_morgan_and_1_0, "witness a\nwitness b\nassert_eq(!(a && b), !a || !b)", 1, 0),
    (de_morgan_and_1_1, "witness a\nwitness b\nassert_eq(!(a && b), !a || !b)", 1, 1),
}

// ============================================================================
// De Morgan's second law: !(a || b) == !a && !b
// Source: Noir stdlib boolean assertion patterns; arkworks r1cs-std test suite.
// ============================================================================

bool_property_tests! {
    (de_morgan_or_0_0, "witness a\nwitness b\nassert_eq(!(a || b), !a && !b)", 0, 0),
    (de_morgan_or_0_1, "witness a\nwitness b\nassert_eq(!(a || b), !a && !b)", 0, 1),
    (de_morgan_or_1_0, "witness a\nwitness b\nassert_eq(!(a || b), !a && !b)", 1, 0),
    (de_morgan_or_1_1, "witness a\nwitness b\nassert_eq(!(a || b), !a && !b)", 1, 1),
}

// ============================================================================
// Idempotence: a && a == a, a || a == a
// Source: Boolean algebra axiom; validated in arkworks r1cs-std.
// ============================================================================

bool_property_tests! {
    (idempotent_and_0, "witness a\nwitness b\nassert_eq(a && a, a)", 0, 0),
    (idempotent_and_1, "witness a\nwitness b\nassert_eq(a && a, a)", 1, 0),
    (idempotent_or_0,  "witness a\nwitness b\nassert_eq(a || a, a)", 0, 0),
    (idempotent_or_1,  "witness a\nwitness b\nassert_eq(a || a, a)", 1, 0),
}

// ============================================================================
// Identity: a && 1 == a, a || 0 == a
// Source: Boolean algebra axiom; arkworks r1cs-std Boolean<F> constants.
// ============================================================================

#[test]
fn identity_and_true_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && 1, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn identity_and_true_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && 1, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn identity_or_false_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || 0, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn identity_or_false_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || 0, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

// ============================================================================
// Annihilation: a && 0 == 0, a || 1 == 1
// Source: Boolean algebra axiom.
// ============================================================================

#[test]
fn annihilation_and_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && 0, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn annihilation_and_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && 0, out)",
        &[("a", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn annihilation_or_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || 1, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn annihilation_or_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || 1, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

// ============================================================================
// Complement: a && !a == 0, a || !a == 1
// Source: Boolean algebra axiom; critical for ZK circuit soundness.
// ============================================================================

#[test]
fn complement_and_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && !a, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn complement_and_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && !a, out)",
        &[("a", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn complement_or_0() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || !a, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn complement_or_1() {
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || !a, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

// ============================================================================
// Commutativity: a && b == b && a, a || b == b || a
// Source: Boolean algebra axiom.
// ============================================================================

bool_property_tests! {
    (commutative_and_0_1, "witness a\nwitness b\nassert_eq(a && b, b && a)", 0, 1),
    (commutative_and_1_0, "witness a\nwitness b\nassert_eq(a && b, b && a)", 1, 0),
    (commutative_or_0_1,  "witness a\nwitness b\nassert_eq(a || b, b || a)", 0, 1),
    (commutative_or_1_0,  "witness a\nwitness b\nassert_eq(a || b, b || a)", 1, 0),
}

// ============================================================================
// Associativity: (a && b) && c == a && (b && c)
// Source: Boolean algebra axiom.
// ============================================================================

bool_ternary_property_tests! {
    (associative_and_0_0_0, "witness a\nwitness b\nwitness c\nassert_eq((a && b) && c, a && (b && c))", 0, 0, 0),
    (associative_and_0_1_1, "witness a\nwitness b\nwitness c\nassert_eq((a && b) && c, a && (b && c))", 0, 1, 1),
    (associative_and_1_0_1, "witness a\nwitness b\nwitness c\nassert_eq((a && b) && c, a && (b && c))", 1, 0, 1),
    (associative_and_1_1_1, "witness a\nwitness b\nwitness c\nassert_eq((a && b) && c, a && (b && c))", 1, 1, 1),
    (associative_or_0_0_0,  "witness a\nwitness b\nwitness c\nassert_eq((a || b) || c, a || (b || c))", 0, 0, 0),
    (associative_or_0_1_0,  "witness a\nwitness b\nwitness c\nassert_eq((a || b) || c, a || (b || c))", 0, 1, 0),
    (associative_or_1_0_0,  "witness a\nwitness b\nwitness c\nassert_eq((a || b) || c, a || (b || c))", 1, 0, 0),
    (associative_or_1_1_1,  "witness a\nwitness b\nwitness c\nassert_eq((a || b) || c, a || (b || c))", 1, 1, 1),
}

// ============================================================================
// Absorption: a && (a || b) == a, a || (a && b) == a
// Source: Boolean algebra axiom.
// ============================================================================

bool_property_tests! {
    (absorption_and_or_0_0, "witness a\nwitness b\nassert_eq(a && (a || b), a)", 0, 0),
    (absorption_and_or_0_1, "witness a\nwitness b\nassert_eq(a && (a || b), a)", 0, 1),
    (absorption_and_or_1_0, "witness a\nwitness b\nassert_eq(a && (a || b), a)", 1, 0),
    (absorption_and_or_1_1, "witness a\nwitness b\nassert_eq(a && (a || b), a)", 1, 1),
    (absorption_or_and_0_0, "witness a\nwitness b\nassert_eq(a || (a && b), a)", 0, 0),
    (absorption_or_and_0_1, "witness a\nwitness b\nassert_eq(a || (a && b), a)", 0, 1),
    (absorption_or_and_1_0, "witness a\nwitness b\nassert_eq(a || (a && b), a)", 1, 0),
    (absorption_or_and_1_1, "witness a\nwitness b\nassert_eq(a || (a && b), a)", 1, 1),
}

// ============================================================================
// Distributivity: a && (b || c) == (a && b) || (a && c)
// Source: Boolean algebra axiom.
// ============================================================================

bool_ternary_property_tests! {
    (distributive_and_over_or_0_0_0, "witness a\nwitness b\nwitness c\nassert_eq(a && (b || c), (a && b) || (a && c))", 0, 0, 0),
    (distributive_and_over_or_0_1_0, "witness a\nwitness b\nwitness c\nassert_eq(a && (b || c), (a && b) || (a && c))", 0, 1, 0),
    (distributive_and_over_or_1_0_1, "witness a\nwitness b\nwitness c\nassert_eq(a && (b || c), (a && b) || (a && c))", 1, 0, 1),
    (distributive_and_over_or_1_1_0, "witness a\nwitness b\nwitness c\nassert_eq(a && (b || c), (a && b) || (a && c))", 1, 1, 0),
    (distributive_and_over_or_1_1_1, "witness a\nwitness b\nwitness c\nassert_eq(a && (b || c), (a && b) || (a && c))", 1, 1, 1),
    (distributive_or_over_and_0_0_0, "witness a\nwitness b\nwitness c\nassert_eq(a || (b && c), (a || b) && (a || c))", 0, 0, 0),
    (distributive_or_over_and_0_1_0, "witness a\nwitness b\nwitness c\nassert_eq(a || (b && c), (a || b) && (a || c))", 0, 1, 0),
    (distributive_or_over_and_1_0_1, "witness a\nwitness b\nwitness c\nassert_eq(a || (b && c), (a || b) && (a || c))", 1, 0, 1),
    (distributive_or_over_and_1_1_1, "witness a\nwitness b\nwitness c\nassert_eq(a || (b && c), (a || b) && (a || c))", 1, 1, 1),
}

// ============================================================================
// Chained / nested operations
// Source: validates correct precedence and evaluation order in the compiler.
// ============================================================================

#[test]
fn nested_not_and_or() {
    // !(a && b) || (c && !a) with a=1, b=0, c=1
    // !(1 && 0) || (1 && !1) = !0 || (1 && 0) = 1 || 0 = 1
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(!(a && b) || (c && !a), out)",
        &[("a", fe(1)), ("b", fe(0)), ("c", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn nested_xor_via_boolean() {
    // XOR(a, b) = (a || b) && !(a && b)
    // a=1, b=0 → (1||0) && !(1&&0) = 1 && 1 = 1
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a || b) && !(a && b), out)",
        &[("a", fe(1)), ("b", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn nested_xor_0_0() {
    // XOR(0, 0) = 0
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a || b) && !(a && b), out)",
        &[("a", fe(0)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn nested_xor_1_1() {
    // XOR(1, 1) = 0
    compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a || b) && !(a && b), out)",
        &[("a", fe(1)), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn triple_and_chain() {
    // a && b && c with all true
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(a && b && c, out)",
        &[("a", fe(1)), ("b", fe(1)), ("c", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn triple_and_one_false() {
    // a && b && c with one false → 0
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(a && b && c, out)",
        &[("a", fe(1)), ("b", fe(0)), ("c", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn triple_or_chain() {
    // a || b || c with all false
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(a || b || c, out)",
        &[("a", fe(0)), ("b", fe(0)), ("c", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn triple_or_one_true() {
    // a || b || c with one true → 1
    compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq(a || b || c, out)",
        &[("a", fe(0)), ("b", fe(1)), ("c", fe(0)), ("out", fe(1))],
    );
}

// ============================================================================
// Soundness — non-boolean witness rejection
// Source: 0xPARC zk-bug-tracker — under-constrained boolean attacks.
// The boolean enforcement gadget b*(1-b)=0 must reject values ∉ {0, 1}.
// Source: arkworks r1cs-std Boolean<F> — enforces_in_scope() constraint.
// ============================================================================

#[test]
fn soundness_not_rejects_2() {
    compile_expect_fail(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(2)), ("out", fe(0))],
    );
}

#[test]
fn soundness_not_rejects_large() {
    compile_expect_fail(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(42)), ("out", fe(0))],
    );
}

#[test]
fn soundness_and_rejects_non_boolean_lhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(2)), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn soundness_and_rejects_non_boolean_rhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(1)), ("b", fe(5)), ("out", fe(0))],
    );
}

#[test]
fn soundness_or_rejects_non_boolean_lhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(3)), ("b", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn soundness_or_rejects_non_boolean_rhs() {
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(0)), ("b", fe(100)), ("out", fe(0))],
    );
}

#[test]
fn soundness_and_rejects_p_minus_1() {
    // p-1 is not boolean despite being a valid field element
    let p_minus_1 =
        fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616");
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", p_minus_1), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_not_result() {
    // !0 should be 1, not 0 — wrong output must fail
    compile_expect_fail(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(0)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_and_result() {
    // 1 && 1 should be 1, not 0 — wrong output must fail
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(1)), ("b", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn soundness_wrong_or_result() {
    // 0 || 1 should be 1, not 0 — wrong output must fail
    compile_expect_fail(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(0)), ("b", fe(1)), ("out", fe(0))],
    );
}

// ============================================================================
// Constraint count regression
// Source: arkworks r1cs-std constraint cost analysis.
// Not: 0-1 constraints (0 if operand is proven boolean)
// And: 1-3 constraints (1 mul + 0-2 boolean enforcement)
// Or:  1-3 constraints (1 mul + 0-2 boolean enforcement)
// ============================================================================

#[test]
fn constraint_count_not() {
    let n = compile_and_verify(
        "witness a\npublic out\nassert_eq(!a, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
    // Not of a raw witness: 1 boolean enforcement + 1 assert_eq
    assert!(n <= 3, "Not constraint count too high: {n}");
}

#[test]
fn constraint_count_and() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(1)), ("b", fe(1)), ("out", fe(1))],
    );
    // And: 2 boolean enforcement + 1 multiplication + 1 assert_eq
    assert!(n <= 5, "And constraint count too high: {n}");
}

#[test]
fn constraint_count_or() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(0)), ("b", fe(1)), ("out", fe(1))],
    );
    // Or: 2 boolean enforcement + 1 multiplication + 1 assert_eq
    assert!(n <= 5, "Or constraint count too high: {n}");
}

#[test]
fn constraint_count_chained_and_or() {
    let n = compile_and_verify(
        "witness a\nwitness b\nwitness c\npublic out\nassert_eq((a && b) || c, out)",
        &[("a", fe(1)), ("b", fe(1)), ("c", fe(0)), ("out", fe(1))],
    );
    // Chained: boolean enforcement + 2 multiplications + 1 assert_eq
    assert!(n <= 8, "chained And-Or constraint count too high: {n}");
}

#[test]
fn constraint_count_xor() {
    let n = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq((a || b) && !(a && b), out)",
        &[("a", fe(1)), ("b", fe(0)), ("out", fe(1))],
    );
    // XOR via boolean: multiple operations
    assert!(n <= 10, "XOR constraint count too high: {n}");
}

// ============================================================================
// Constant folding — boolean operations with pure constants
// Source: validates the compiler's constant propagation pass (DCE) for
// boolean expressions. When both operands are constants, the optimizer
// should resolve the expression at compile time, emitting fewer constraints
// than the equivalent circuit with witness inputs.
// ============================================================================

#[test]
fn const_fold_not_false() {
    compile_and_verify("public out\nassert_eq(!false, out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_not_true() {
    compile_and_verify("public out\nassert_eq(!true, out)", &[("out", fe(0))]);
}

#[test]
fn const_fold_and_1_0() {
    compile_and_verify("public out\nassert_eq(1 && 0, out)", &[("out", fe(0))]);
}

#[test]
fn const_fold_and_1_1() {
    compile_and_verify("public out\nassert_eq(1 && 1, out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_and_0_0() {
    compile_and_verify("public out\nassert_eq(0 && 0, out)", &[("out", fe(0))]);
}

#[test]
fn const_fold_or_0_0() {
    compile_and_verify("public out\nassert_eq(0 || 0, out)", &[("out", fe(0))]);
}

#[test]
fn const_fold_or_1_0() {
    compile_and_verify("public out\nassert_eq(1 || 0, out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_or_1_1() {
    compile_and_verify("public out\nassert_eq(1 || 1, out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_de_morgan_lhs() {
    // !(1 && 0) = !(false) = true = 1
    compile_and_verify("public out\nassert_eq(!(1 && 0), out)", &[("out", fe(1))]);
}

#[test]
fn const_fold_de_morgan_rhs() {
    // !true || !false = false || true = 1
    compile_and_verify(
        "public out\nassert_eq(!true || !false, out)",
        &[("out", fe(1))],
    );
}

#[test]
fn const_fold_and_reduces_constraints() {
    // Pure constant And should use fewer constraints than witness And.
    let n_const = compile_and_verify("public out\nassert_eq(1 && 0, out)", &[("out", fe(0))]);
    let n_witness = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a && b, out)",
        &[("a", fe(1)), ("b", fe(0)), ("out", fe(0))],
    );
    assert!(
        n_const <= n_witness,
        "constant folding should not increase constraints: const={n_const}, witness={n_witness}"
    );
}

#[test]
fn const_fold_or_reduces_constraints() {
    let n_const = compile_and_verify("public out\nassert_eq(0 || 1, out)", &[("out", fe(1))]);
    let n_witness = compile_and_verify(
        "witness a\nwitness b\npublic out\nassert_eq(a || b, out)",
        &[("a", fe(0)), ("b", fe(1)), ("out", fe(1))],
    );
    assert!(
        n_const <= n_witness,
        "constant folding should not increase constraints: const={n_const}, witness={n_witness}"
    );
}

// ============================================================================
// Mixed constant-witness boolean operations
// Source: exercises the code path where one operand is a LinearCombination
// from a constant and the other from a witness variable.
// ============================================================================

#[test]
fn mixed_and_witness_const_true() {
    // a && 1 with witness a=1 → 1
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && 1, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}

#[test]
fn mixed_and_witness_const_false() {
    // a && 0 with witness a=1 → 0 (annihilation)
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && 0, out)",
        &[("a", fe(1)), ("out", fe(0))],
    );
}

#[test]
fn mixed_or_witness_const_true() {
    // a || 1 with witness a=0 → 1 (annihilation)
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a || 1, out)",
        &[("a", fe(0)), ("out", fe(1))],
    );
}

#[test]
fn mixed_not_of_const_in_expr() {
    // a && !false → a && true → a
    compile_and_verify(
        "witness a\npublic out\nassert_eq(a && !false, out)",
        &[("a", fe(1)), ("out", fe(1))],
    );
}
