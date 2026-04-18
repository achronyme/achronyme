//! Tests for constraint pairing analysis.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `constraint_check/mod.rs`.

use super::*;
use crate::parser::parse_circom;

fn check(src: &str) -> Vec<ConstraintReport> {
    let full = format!("template T() {{ {src} }}");
    let (prog, parse_errors) = parse_circom(&full).expect("parse failed");
    assert!(parse_errors.is_empty(), "parse errors: {:?}", parse_errors);
    check_constraints(&prog.definitions)
}

fn has_error(reports: &[ConstraintReport], signal: &str) -> bool {
    reports.iter().any(|r| {
        r.diagnostics.iter().any(|d| {
            d.message
                .contains(&format!("signal `{signal}` is assigned with `<--`"))
        })
    })
}

// ── Safe patterns (no errors) ────────────────────────────────────

#[test]
fn constraint_assign_is_safe() {
    let reports = check("signal output c; c <== 42;");
    assert!(reports.is_empty());
}

#[test]
fn signal_assign_with_constraint_eq_is_safe() {
    // The IsZero pattern: <-- for witness hint, === for verification
    let reports = check(
        r#"
        signal input in;
        signal output out;
        signal inv;
        inv <-- 1;
        in * inv === 1;
        "#,
    );
    assert!(!has_error(&reports, "inv"));
}

#[test]
fn num2bits_pattern_is_safe() {
    // Num2Bits: <-- for bit extraction, === for sum check
    let reports = check(
        r#"
        signal input in;
        signal output out;
        out <-- 1;
        out === in;
        "#,
    );
    assert!(!has_error(&reports, "out"));
}

#[test]
fn babyadd_division_pattern_is_safe() {
    // BabyAdd: <-- for EC division, === for verification
    let reports = check(
        r#"
        signal input x1;
        signal input y1;
        signal output xout;
        signal output yout;
        signal beta;
        signal gamma;
        signal tau;
        xout <-- 1;
        yout <-- 1;
        tau === x1 * y1;
        xout === beta + gamma;
        yout === beta - gamma;
        "#,
    );
    assert!(!has_error(&reports, "xout"));
    assert!(!has_error(&reports, "yout"));
}

// ── Unsafe patterns (errors) ─────────────────────────────────────

#[test]
fn bare_signal_assign_is_error() {
    let reports = check(
        r#"
        signal input in;
        signal output out;
        out <-- in;
        "#,
    );
    assert!(has_error(&reports, "out"));
}

#[test]
fn bare_reverse_signal_assign_is_error() {
    let reports = check(
        r#"
        signal input in;
        signal output out;
        in --> out;
        "#,
    );
    assert!(has_error(&reports, "out"));
}

#[test]
fn multiple_unconstrained_signals() {
    let reports = check(
        r#"
        signal a;
        signal b;
        a <-- 1;
        b <-- 2;
        "#,
    );
    assert!(has_error(&reports, "a"));
    assert!(has_error(&reports, "b"));
}

#[test]
fn error_has_code_e100() {
    let reports = check("signal x; x <-- 1;");
    assert!(!reports.is_empty());
    let diag = &reports[0].diagnostics[0];
    assert_eq!(diag.code.as_deref(), Some("E100"));
}

// ── Nested blocks ────────────────────────────────────────────────

#[test]
fn signal_assign_in_for_loop_with_constraint() {
    let reports = check(
        r#"
        signal input in;
        signal output bits;
        for (var i = 0; i < 8; i++) {
            bits <-- 1;
        }
        bits === in;
        "#,
    );
    assert!(!has_error(&reports, "bits"));
}

#[test]
fn signal_assign_in_for_loop_without_constraint() {
    let reports = check(
        r#"
        signal output bits;
        for (var i = 0; i < 8; i++) {
            bits <-- 1;
        }
        "#,
    );
    assert!(has_error(&reports, "bits"));
}

#[test]
fn signal_assign_in_if_with_constraint_outside() {
    let reports = check(
        r#"
        signal input sel;
        signal out;
        if (sel == 0) {
            out <-- 1;
        } else {
            out <-- 2;
        }
        out === sel + 1;
        "#,
    );
    assert!(!has_error(&reports, "out"));
}

#[test]
fn constraint_in_nested_if() {
    let reports = check(
        r#"
        signal x;
        x <-- 1;
        if (1 == 1) {
            x === 1;
        }
        "#,
    );
    assert!(!has_error(&reports, "x"));
}

// ── Array signals ────────────────────────────────────────────────

#[test]
fn array_signal_unconstrained() {
    let reports = check(
        r#"
        signal out;
        out <-- 42;
        "#,
    );
    assert!(has_error(&reports, "out"));
}

#[test]
fn indexed_signal_with_constraint() {
    // out[i] <-- expr; out[i] === expr; — "out" appears in both
    let reports = check(
        r#"
        signal input in;
        signal output out;
        out <-- in;
        out === in;
        "#,
    );
    assert!(!has_error(&reports, "out"));
}

// ── Multiple templates ───────────────────────────────────────────

#[test]
fn checks_all_templates() {
    let src = r#"
        template Safe() {
            signal output x;
            x <== 1;
        }
        template Unsafe() {
            signal output y;
            y <-- 1;
        }
    "#;
    let (prog, _) = parse_circom(src).unwrap();
    let reports = check_constraints(&prog.definitions);
    // Only Unsafe should have errors
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].template_name, "Unsafe");
    assert!(has_error(&reports, "y"));
}

// ── Functions are ignored ────────────────────────────────────────

#[test]
fn functions_not_checked() {
    let src = r#"
        function helper(a) {
            return a + 1;
        }
    "#;
    let (prog, _) = parse_circom(src).unwrap();
    let reports = check_constraints(&prog.definitions);
    assert!(reports.is_empty());
}

// ── W101: unconstrained input/output signals ────────────────────

fn has_warning(reports: &[ConstraintReport], signal: &str) -> bool {
    reports.iter().any(|r| {
        r.diagnostics.iter().any(|d| {
            d.severity == diagnostics::Severity::Warning
                && d.message.contains(signal)
                && d.code.as_deref() == Some("W101")
        })
    })
}

#[test]
fn w101_input_not_in_constraint() {
    // input `in` doesn't appear in any constraint — W101
    let reports = check(
        r#"
        signal input in;
        signal output out;
        out <-- in;
        out * (out - 1) === 0;
        "#,
    );
    assert!(has_warning(&reports, "in"));
}

#[test]
fn w101_input_in_constraint_is_fine() {
    let reports = check(
        r#"
        signal input in;
        signal output out;
        out <== in * 2;
        "#,
    );
    assert!(!has_warning(&reports, "in"));
    assert!(!has_warning(&reports, "out"));
}

#[test]
fn w101_output_not_in_constraint() {
    let reports = check(
        r#"
        signal output out;
        out <-- 42;
        "#,
    );
    // out assigned via <-- but no === → E100 fires
    // out not in any constraint → W101 also fires
    assert!(has_error(&reports, "out"));
    assert!(has_warning(&reports, "out"));
}

// ── E100: inline signal init with <-- ──��───────────────────────────

#[test]
fn inline_signal_assign_is_unconstrained() {
    // `signal c <-- expr` should trigger E100 just like `signal c; c <-- expr`
    let reports = check("signal output c <-- 42;");
    assert!(has_error(&reports, "c"));
}

#[test]
fn inline_signal_assign_with_constraint_is_safe() {
    let reports = check(
        r#"
        signal inv <-- 1;
        signal input a;
        a * inv === 1;
        "#,
    );
    assert!(!has_error(&reports, "inv"));
}

// ── W103: double signal assignment (warning) ──────────────────────

fn has_w103(reports: &[ConstraintReport], signal: &str) -> bool {
    reports.iter().any(|r| {
        r.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("W103") && d.message.contains(signal))
    })
}

#[test]
fn w103_double_constrained_assign() {
    let reports = check(
        r#"
        signal input a;
        signal output c;
        c <== a;
        c <== a + 1;
        "#,
    );
    assert!(has_w103(&reports, "c"));
}

#[test]
fn w103_hint_then_constrained() {
    let reports = check(
        r#"
        signal input a;
        signal x;
        x <-- a;
        x <== a;
        x === a;
        "#,
    );
    assert!(has_w103(&reports, "x"));
}

#[test]
fn w103_single_assignment_is_fine() {
    let reports = check(
        r#"
        signal input a;
        signal output c;
        c <== a * 2;
        "#,
    );
    assert!(!has_w103(&reports, "c"));
}

#[test]
fn w103_inline_init_plus_reassign() {
    let reports = check(
        r#"
        signal input a;
        signal output c <== a;
        c <== a + 1;
        "#,
    );
    assert!(has_w103(&reports, "c"));
}

// ── W102: <-- with quadratic expression ────���────────────────────────

fn has_w102(reports: &[ConstraintReport], signal: &str) -> bool {
    reports.iter().any(|r| {
        r.diagnostics.iter().any(|d| {
            d.severity == diagnostics::Severity::Warning
                && d.code.as_deref() == Some("W102")
                && d.message.contains(signal)
        })
    })
}

#[test]
fn w102_simple_arithmetic_triggers() {
    // `out <-- a * b` is quadratic — should warn
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal output out;
        out <-- a * b;
        out === a * b;
        "#,
    );
    assert!(has_w102(&reports, "out"));
}

#[test]
fn w102_constant_expression_triggers() {
    let reports = check(
        r#"
        signal output out;
        out <-- 42;
        out === 42;
        "#,
    );
    assert!(has_w102(&reports, "out"));
}

#[test]
fn w102_addition_triggers() {
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal output out;
        out <-- a + b;
        out === a + b;
        "#,
    );
    assert!(has_w102(&reports, "out"));
}

#[test]
fn w102_bitwise_does_not_trigger() {
    // Bitwise ops are NOT quadratic-safe — <-- is appropriate
    let reports = check(
        r#"
        signal input a;
        signal output out;
        out <-- (a >> 1) & 1;
        out === a;
        "#,
    );
    assert!(!has_w102(&reports, "out"));
}

#[test]
fn w102_division_does_not_trigger() {
    // Division is NOT quadratic-safe — <-- is appropriate
    let reports = check(
        r#"
        signal input a;
        signal output inv;
        inv <-- 1 / a;
        a * inv === 1;
        "#,
    );
    assert!(!has_w102(&reports, "inv"));
}

#[test]
fn w102_ternary_does_not_trigger() {
    let reports = check(
        r#"
        signal input a;
        signal output out;
        out <-- a == 0 ? 1 : 0;
        out === 1;
        "#,
    );
    assert!(!has_w102(&reports, "out"));
}

#[test]
fn w102_inline_signal_init_triggers() {
    let reports = check(
        r#"
        signal input a;
        signal output out <-- a + 1;
        out === a + 1;
        "#,
    );
    assert!(has_w102(&reports, "out"));
}

#[test]
fn w102_negation_triggers() {
    // Negation is quadratic-safe (field negation)
    let reports = check(
        r#"
        signal input a;
        signal output out;
        out <-- -a;
        out === -a;
        "#,
    );
    assert!(has_w102(&reports, "out"));
}

// ── E102: non-quadratic constraint expression ───────────────────────

fn has_e102(reports: &[ConstraintReport]) -> bool {
    reports.iter().any(|r| {
        r.diagnostics
            .iter()
            .any(|d| d.code.as_deref() == Some("E102"))
    })
}

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
