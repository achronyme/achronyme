use super::*;

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
