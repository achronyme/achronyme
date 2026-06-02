use super::*;

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
