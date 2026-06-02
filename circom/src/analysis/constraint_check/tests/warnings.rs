use super::*;

// ── W101: unconstrained input/output signals ────────────────────

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
