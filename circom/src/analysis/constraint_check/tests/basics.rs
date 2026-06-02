use super::*;

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
