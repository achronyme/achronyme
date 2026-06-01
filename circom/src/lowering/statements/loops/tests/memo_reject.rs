use super::*;

/// Soundness pin.
///
/// Num2Bits's body has two state-carrying mutations that memoization
/// CANNOT correctly replay: `lc1 += out[i] * e2` (an accumulator with
/// no in-body reset, so iter 0's final `lc1` would leak into iter 1)
/// and `e2 = e2 + e2` (a self-referential SubAssignIdent that doubles
/// across iters — iter N's value depends on iter (N-1)'s). Either
/// alone is sufficient to make the body unsafe.
///
/// `is_memoizable` MUST return `None` on this shape. The contract
/// holds today via the blanket `body_has_state_carrying_var_mutation`
/// rule. A future loosening (Follow-up D) refines that gate to admit
/// Mix's outer-i body (which DOES have an in-body reset of `lc`); the
/// refinement MUST continue to reject this Num2Bits shape — both the
/// CompoundAssign-without-reset and the self-referential SubAssign.
#[test]
fn is_memoizable_rejects_num2bits_state_carrying_body() {
    let stmts = extract_template_body(
        r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
                var lc1 = 0;
                var e2 = 1;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    out[i] * (out[i] - 1) === 0;
                    lc1 += out[i] * e2;
                    e2 = e2 + e2;
                }
                lc1 === in;
            }
            "#,
    );
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    // n=8 — well above the iter_count gate (4); strategy chosen to
    // bypass the strategy gate so the rejection is attributable to
    // the state-carrying-var-mutation rule, not the strategy gate.
    assert!(
        is_memoizable(LoopLowering::IndexedAssignmentLoop, &for_body, "i", 0, 8).is_none(),
        "is_memoizable MUST reject Num2Bits's body. `lc1 += out[i] * e2` \
             is an accumulator without an in-body reset, AND `e2 = e2 + e2` \
             is a self-referential SubAssignIdent. Either makes the body \
             unsafe to memoize: iter-0's final lc1/e2 would leak into \
             iter 1's emission, breaking soundness. If this test fails, a \
             loosening of body_has_state_carrying_var_mutation regressed."
    );
}

/// Soundness pin.
///
/// Mix's inner-j body in isolation (`lc += M[j][i]*in[j]`) has a
/// CompoundAssign on `lc` with NO in-body reset. Memoizing it alone
/// would leak iter-(j-1)'s value of `lc` into iter j, accumulating
/// the wrong sum. The outer-i body has the reset (`lc = 0` before
/// the inner for), so when outer-i is memoized, the inner-j body
/// gets unrolled normally during iter-0 capture — but the inner-j
/// body alone, classified independently, MUST still reject.
///
/// This rejection ALSO prevents nested `memoize_loop` placeholder
/// collision: token=0 is shared, and a nested memoize would clobber
/// the outer's placeholder.
#[test]
fn is_memoizable_rejects_inner_j_compoundassign_without_reset() {
    let stmts = extract_template_body(
        r#"
            template T(t) {
                signal input in[t];
                signal output out[t];
                var lc = 0;
                for (var j = 0; j < t; j++) {
                    lc += in[j];
                }
                out[0] <== lc;
            }
            "#,
    );
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    assert!(
        is_memoizable(LoopLowering::IndexedAssignmentLoop, &for_body, "j", 0, 8).is_none(),
        "is_memoizable MUST reject a body that has CompoundAssign on \
             a var without an in-body reset of that var. The reset must \
             appear within the loop's own body — a template-scope reset \
             outside the loop does not count, because the accumulator \
             would still carry across this loop's iters."
    );
}

/// Soundness pin.
///
/// MixS's first loop (`for(i) lc += S[(t*2-1)*r+i]*in[i]`) is
/// structurally identical to inner-j: CompoundAssign without an
/// in-body reset. The reset (`var lc = 0`) lives at template scope,
/// outside this loop. MUST stay rejected.
/// Admit pin.
///
/// Mix's outer-i body has a CompoundAssign on `lc` inside a nested
/// for, BUT with a top-level `lc = 0` reset before that. The reset
/// makes each outer iter start fresh, so memoization is sound. The
/// loosened `body_has_state_carrying_var_mutation` rule must admit
/// this shape; before Follow-up D the blanket rule rejected it.
///
/// This test would have FAILED on the pre-loosening code (with a
/// `None` from is_memoizable), confirming the loosening is the
/// load-bearing change. See plan-D-results.md for the counter-
/// factual trace.
#[test]
fn is_memoizable_accepts_mix_outer_i_with_in_body_reset() {
    use crate::lowering::utils::bigval::BigVal;
    use crate::lowering::utils::EvalValue;

    let stmts = extract_template_body(
        r#"
            template Mix(t) {
                signal input in[t];
                signal output out[t];
                var lc;
                for (var i = 0; i < t; i++) {
                    lc = 0;
                    for (var j = 0; j < t; j++) {
                        lc += M[j][i] * in[j];
                    }
                    out[i] <== lc;
                }
            }
            "#,
    );
    // Pick the outer-i for loop (first For statement).
    let outer_for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected an outer for loop"),
    };

    // For Mix to classify as KnownArrayRefs (the strategy gate
    // requires this), `M` must be in env.known_array_values. The
    // POSEIDON_M is t×t; for t=6 it's a 6×6 uniform matrix.
    let mut env = LoweringEnv::new();
    let row: Vec<EvalValue> = (0..6)
        .map(|v| EvalValue::Scalar(BigVal::from_u64(v)))
        .collect();
    let m: Vec<EvalValue> = (0..6).map(|_| EvalValue::Array(row.clone())).collect();
    env.known_array_values
        .insert("M".to_string(), EvalValue::Array(m));

    let strategy = classify_loop_body(&outer_for_body, &env, "i");
    assert_eq!(
        strategy,
        Some(LoopLowering::KnownArrayRefs),
        "Mix's outer-i body must classify as KnownArrayRefs (M is \
             in env.known_array_values, no signals branched in if/else, \
             no component decls). A different classification means the \
             precondition for the admit assertion below is invalid."
    );

    assert!(
        is_memoizable(LoopLowering::KnownArrayRefs, &outer_for_body, "i", 0, 6).is_some(),
        "Follow-up D contract: is_memoizable MUST admit Mix's \
             outer-i body. The CompoundAssign on `lc` inside the nested \
             for is offset by the in-body reset `lc = 0` at the top of \
             the body, so each outer iter starts with `lc` cleared and \
             memoization replay is sound. A `None` here means the \
             loosening regressed or the reset-tracking logic missed \
             the top-level Substitution Assign on Ident lc with RHS 0."
    );
}

#[test]
fn is_memoizable_rejects_mixs_first_loop_compoundassign_without_reset() {
    let stmts = extract_template_body(
        r#"
            template MixS(t, r) {
                signal input in[t];
                signal output out[t];
                var lc = 0;
                for (var i = 0; i < t; i++) {
                    lc += in[i];
                }
                out[0] <== lc;
                for (var i = 1; i < t; i++) {
                    out[i] <== in[i];
                }
            }
            "#,
    );
    // Pick the FIRST For (the accumulator loop), not the second
    // (which is the already-memoizable signal-only loop).
    let for_body = match stmts.iter().find_map(|s| match s {
        Stmt::For { body, .. } => Some(&body.stmts),
        _ => None,
    }) {
        Some(b) => b.clone(),
        None => panic!("expected a for loop"),
    };
    assert!(
        is_memoizable(LoopLowering::IndexedAssignmentLoop, &for_body, "i", 0, 8).is_none(),
        "is_memoizable MUST reject MixS's first-pass accumulator \
             loop. Its single CompoundAssign on `lc` with no in-body \
             reset means iter (i-1)'s lc value leaks into iter i, \
             breaking the per-iter independence memoization needs."
    );
}
