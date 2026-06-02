use super::*;

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
