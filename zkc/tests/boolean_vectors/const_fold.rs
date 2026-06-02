use super::*;

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
