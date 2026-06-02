use super::*;

// ── Polynomial-fingerprint accumulator pattern ────────────────────
//
// `BigMultNoCarry` and its friends encode the constraint on a
// `<--`-assigned signal array via a compile-time `var` polynomial:
//
//     for (i) out[i] <-- prod_val[i];
//     for (i) for (j) poly[i] = poly[i] + out[j] * coef(i, j);
//     for (i) poly[i] === expected[i];
//
// The validator must recognise that `poly[i] === ...` transitively
// pins `out` because `poly` aggregates `out`. A purely-syntactic
// E100 check rejects every bigint-emulation circuit otherwise.

#[test]
fn poly_accumulator_with_constraint_clears_e100() {
    let reports = check(
        r#"
        signal input a;
        signal output out[3];
        var prod_val[3] = [1, 2, 3];
        for (var i = 0; i < 3; i++) {
            out[i] <-- prod_val[i];
        }
        var poly[3];
        for (var i = 0; i < 3; i++) {
            poly[i] = 0;
            for (var j = 0; j < 3; j++) {
                poly[i] = poly[i] + out[j] * (i ** j);
            }
        }
        for (var i = 0; i < 3; i++) {
            poly[i] === a;
        }
        "#,
    );
    assert!(
        !has_error(&reports, "out"),
        "`poly[i] === a` transitively pins `out` via the var aggregator"
    );
}

#[test]
fn poly_compound_assign_clears_e100() {
    // Same shape but using `+=` instead of an explicit
    // `poly[i] = poly[i] + ...` rewrite. Both AST forms must be
    // tracked or BigMultShortLong-style hand-coded fingerprints (which
    // some libraries do write with `+=`) would still false-positive.
    let reports = check(
        r#"
        signal input a;
        signal output out[3];
        var prod_val[3] = [1, 2, 3];
        for (var i = 0; i < 3; i++) {
            out[i] <-- prod_val[i];
        }
        var poly[3];
        for (var i = 0; i < 3; i++) {
            poly[i] = 0;
            for (var j = 0; j < 3; j++) {
                poly[i] += out[j] * (i ** j);
            }
        }
        for (var i = 0; i < 3; i++) {
            poly[i] === a;
        }
        "#,
    );
    assert!(!has_error(&reports, "out"));
}

#[test]
fn transitive_var_through_var_clears_e100() {
    // `poly === ...` constrains `q`, which constrains `out`.
    let reports = check(
        r#"
        signal input a;
        signal output out;
        out <-- 1;
        var q = out + 0;
        var poly = q * 2;
        poly === a;
        "#,
    );
    assert!(!has_error(&reports, "out"));
}

#[test]
fn var_in_branches_collects_from_all_arms() {
    // `if/else` should fan deps from both arms — the validator can't
    // know which branch fires at instantiate time.
    let reports = check(
        r#"
        signal input flag;
        signal input a;
        signal s;
        s <-- 1;
        var poly;
        if (flag == 1) {
            poly = s + 0;
        } else {
            poly = s * 2;
        }
        poly === a;
        "#,
    );
    assert!(!has_error(&reports, "s"));
}

#[test]
fn var_declared_unassigned_does_not_clear_e100() {
    // Soundness regression guard: a `var P[N]` that's never assigned
    // from any signal must NOT clear E100 on a `<--`-only signal,
    // even if the user references the var in a constraint. The
    // matcher only relaxes when the var actually aggregates the signal.
    let reports = check(
        r#"
        signal input a;
        signal s;
        s <-- 1;
        var poly[3];
        poly[0] = 0;
        poly[1] = 0;
        poly[2] = 0;
        poly[0] === a;
        "#,
    );
    assert!(
        has_error(&reports, "s"),
        "`poly` never reads `s`; the constraint on `poly[0]` cannot pin `s`"
    );
}

#[test]
fn unrelated_var_does_not_clear_e100() {
    // Two separate vars: `q` aggregates `s`, but the constraint is on
    // `r` (which doesn't reference `s`). E100 should still fire on
    // `s` — the constraint chain doesn't reach it.
    let reports = check(
        r#"
        signal input a;
        signal input b;
        signal s;
        s <-- 1;
        var q = s + 0;
        var r = b + 0;
        r === a;
        "#,
    );
    assert!(
        has_error(&reports, "s"),
        "constraint is on `r` not `q`; `s` remains unconstrained"
    );
}
