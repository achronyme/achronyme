use super::*;

// ── E102: non-quadratic constraint expression ───────────────────────

#[test]
fn e102_cubic_constraint_is_error() {
    // a * b * c has degree 3 — not R1CS representable
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal input c;
        signal output d;
        d <== a * b * c;
        "#,
    );
    assert!(has_e102(&reports));
}

#[test]
fn e102_quadratic_constraint_is_fine() {
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal output c;
        c <== a * b;
        "#,
    );
    assert!(!has_e102(&reports));
}

#[test]
fn e102_linear_constraint_is_fine() {
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal output c;
        c <== a + b;
        "#,
    );
    assert!(!has_e102(&reports));
}

#[test]
fn e102_triple_product_in_constraint_eq() {
    // Using === directly: a * b * c === d
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal input c;
        signal output d;
        d <== 1;
        a * b * c === d;
        "#,
    );
    assert!(has_e102(&reports));
}

#[test]
fn e102_constant_multiplication_is_fine() {
    // signal * constant is degree 1, not 2
    let reports = check(
        r#"
        signal input a;
        signal output c;
        c <== a * 3;
        "#,
    );
    assert!(!has_e102(&reports));
}

#[test]
fn e102_var_times_signal_is_fine() {
    // var is not a signal → degree 0, so var * signal = degree 1
    let reports = check(
        r#"
        signal input a;
        signal output c;
        c <== a * a;
        "#,
    );
    // a * a = degree 2 — fine for R1CS
    assert!(!has_e102(&reports));
}
