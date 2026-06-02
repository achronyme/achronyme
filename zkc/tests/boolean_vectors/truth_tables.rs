use super::*;

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
