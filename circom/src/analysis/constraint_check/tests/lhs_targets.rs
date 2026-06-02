use super::*;

// ── FN-1: tuple-destructured `<--` ────────────────────────────────
//
// Before the extractor returned a `Vec`, `(a, b) <-- expr;` silently
// produced no entries in `unconstrained_assigns` — the analyzer
// dropped both names and accepted the under-constrained shape.

#[test]
fn fn1_tuple_destructured_signal_assign_flags_every_name() {
    // `check` wraps the source in `template T() { ... }`, so the
    // diagnostic name becomes `T::a` / `T::b`.
    let reports = check(
        r#"
        signal a;
        signal b;
        (a, b) <-- (1, 2);
        "#,
    );
    assert!(
        has_error(&reports, "a"),
        "left-hand tuple element `a` should trigger E100"
    );
    assert!(
        has_error(&reports, "b"),
        "left-hand tuple element `b` should trigger E100"
    );
}

#[test]
fn fn1_tuple_with_one_constrained_still_flags_other() {
    // Make sure adding a `===` for one of the destructured names
    // doesn't blanket-clear E100 on the *other* — the unconstrained
    // half should still surface.
    let reports = check(
        r#"
        signal input x;
        signal a;
        signal b;
        (a, b) <-- (1, 2);
        a === x;
        "#,
    );
    assert!(!has_error(&reports, "a"), "`a` is constrained via ===");
    assert!(has_error(&reports, "b"), "`b` remains unconstrained");
}

// ── FN-2: DotAccess targets in `<--` (`c.out <-- v`) ──────────────
//
// Sub-template outputs are constrained inside the sub-template, so
// overwriting them with a `<--` from the parent shadows soundness.
// Before the extractor handled DotAccess, the assignment slipped
// past tracking entirely.

#[test]
fn fn2_dotaccess_signal_assign_flags_qualified_name() {
    // The reports are wrapped in `template T() { ... }`. The
    // diagnostic name becomes `T::c.out`.
    let reports = check(
        r#"
        component c = Sub();
        c.out <-- 5;
        "#,
    );
    assert!(
        has_error(&reports, "c.out"),
        "`c.out <-- 5` should trigger E100 on the qualified name"
    );
}

#[test]
fn fn2_dotaccess_assign_with_paired_eq_is_safe() {
    // If the user does add a paired `c.out === expr` constraint, the
    // qualified `c.out` lands in CONSTRAINED via the extended
    // `collect_signal_refs` and E100 stays silent. This guarantees the
    // FN-2 fix doesn't regress legitimate (if unusual) hand-rolled
    // sub-template-output constraints.
    let reports = check(
        r#"
        signal input x;
        component c = Sub();
        c.out <-- 5;
        c.out === x;
        "#,
    );
    assert!(
        !has_error(&reports, "c.out"),
        "paired `c.out === x` constraint should clear E100"
    );
}
