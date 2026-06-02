use super::*;

// ============================================================================
// Basic arithmetic
// ============================================================================

#[test]
fn ir_simple_add() {
    ir_pipeline_verify(
        &[("out", 30)],
        &[("x", 10), ("y", 20)],
        "assert_eq(x + y, out)",
    );
}

#[test]
fn ir_simple_sub() {
    ir_pipeline_verify(
        &[("out", 5)],
        &[("x", 15), ("y", 10)],
        "assert_eq(x - y, out)",
    );
}

#[test]
fn ir_simple_mul() {
    ir_pipeline_verify(
        &[("out", 42)],
        &[("x", 6), ("y", 7)],
        "assert_eq(x * y, out)",
    );
}

#[test]
fn ir_simple_div() {
    ir_pipeline_verify(
        &[("out", 5)],
        &[("x", 30), ("y", 6)],
        "assert_eq(x / y, out)",
    );
}

#[test]
fn ir_negation() {
    // -x + y = out → x=10, y=15, out=5
    ir_pipeline_verify(
        &[("out", 5)],
        &[("x", 10), ("y", 15)],
        "assert_eq(-x + y, out)",
    );
}

#[test]
fn ir_power() {
    // x^3 = out → x=3, out=27
    ir_pipeline_verify(&[("out", 27)], &[("x", 3)], "assert_eq(x ^ 3, out)");
}

// ============================================================================
// Let bindings
// ============================================================================

#[test]
fn ir_let_binding() {
    ir_pipeline_verify(
        &[("out", 50)],
        &[("x", 5), ("y", 10)],
        "let z = x * y\nassert_eq(z, out)",
    );
}

#[test]
fn ir_let_chain() {
    ir_pipeline_verify(
        &[("out", 50)],
        &[("x", 5)],
        "let y = x * x\nlet z = y + y\nassert_eq(z, out)",
    );
}

// ============================================================================
// Constants
// ============================================================================

#[test]
fn ir_constant_mul() {
    // x * 3 = out → x=7, out=21
    ir_pipeline_verify(&[("out", 21)], &[("x", 7)], "assert_eq(x * 3, out)");
}

#[test]
fn ir_constant_add() {
    ir_pipeline_verify(&[("out", 15)], &[("x", 10)], "assert_eq(x + 5, out)");
}
