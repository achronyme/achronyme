use super::*;

/// Body has a multi-dim signal-array read (`c[i][0]`, `c[i][7]`)
/// with the loop var in the outer slot. With the placeholder-
/// aware `lower_multi_index` and no multi-dim disqualifier in
/// `is_memoizable`, this shape must be admitted. A future
/// regression that re-introduces a multi-dim gate or loosens
/// the placeholder mechanism upstream trips this test
/// immediately.
#[test]
fn is_memoizable_accepts_multi_dim_signal_array_body() {
    let stmts = extract_template_body(
        r#"
            template T(n) {
                signal input c[n][8];
                signal input s;
                signal output out[n];
                for (var i = 0; i < n; i++) {
                    out[i] <== c[i][0] + c[i][7] * s;
                }
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
        is_memoizable(LoopLowering::IndexedAssignmentLoop, &for_body, "i", 0, 8).is_some(),
        "is_memoizable must accept multi-dim signal-array bodies \
             after R1″ Follow-up A — placeholder propagation through \
             lower_multi_index handles `c[i][k]` correctly. A None here \
             means a regression re-introduced the multi-dim gate or \
             tripped a different MVP gate."
    );
}

/// Add-slot in placeholder index.
///
/// Body shape `c[i+1][k]` puts the loop variable inside an `Add`
/// expression in the outer index slot. `placeholder_appears_in`
/// recurses through `BinOp` so it correctly returns `true`, the
/// const-fold fast path is skipped, and the symbolic linearisation
/// emits `BinOp(Add, LoopVar(token), Const(1))` for the slot.
/// `substitute_loop_var` rewrites `LoopVar(token) → Const(v)` per
/// iter; instantiate's eval_const_expr collapses `Const(v)+Const(1)`
/// to `Const(v+1)` and the final ArrayIndex resolves correctly.
/// This test pins the classifier-side acceptance — the
/// substitute-then-late-fold path is exercised at lowering time
/// when the body actually compiles, but ensuring the gate accepts
/// the shape is the first step.
#[test]
fn is_memoizable_accepts_add_slot_in_placeholder_index() {
    let stmts = extract_template_body(
        r#"
            template T(n) {
                signal input c[n][8];
                signal output out[n];
                for (var i = 0; i < n - 1; i++) {
                    out[i] <== c[i + 1][0] + c[i + 1][7];
                }
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
        is_memoizable(LoopLowering::IndexedAssignmentLoop, &for_body, "i", 0, 8).is_some(),
        "is_memoizable must accept multi-dim bodies whose placeholder \
             slot is wrapped in an arithmetic expression like `c[i+1][k]`. \
             Substitution + late fold handles the rewrite per iter; this \
             test ensures the classifier doesn't reject upstream."
    );
}

/// Compile-time outer slot with placeholder in inner slot.
///
/// Body shape `c[k][i]` for compile-time `k` (template param)
/// resolved at lowering via `param_values` / `known_constants`. With
/// `any_slot_has_placeholder = true` (slot 1 is the placeholder),
/// the const-fold fast path is skipped. Symbolic linearisation
/// lowers slot 0 to `Const(k_value)` and slot 1 to `LoopVar(token)`.
/// Stride 0 = inner-dim size; the result is
/// `Const(k*inner_size) + LoopVar(token)` which the
/// substitute-then-late-fold path collapses to
/// `Const(k*inner_size + v)` per iter. The test substitutes `k`
/// with a literal (`3`) since classifier-level gates don't see
/// template params.
#[test]
fn is_memoizable_accepts_compile_time_outer_with_placeholder_inner() {
    let stmts = extract_template_body(
        r#"
            template T(n) {
                signal input c[8][n];
                signal output out[n];
                for (var i = 0; i < n; i++) {
                    out[i] <== c[3][i];
                }
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
        is_memoizable(LoopLowering::IndexedAssignmentLoop, &for_body, "i", 0, 8).is_some(),
        "is_memoizable must accept multi-dim bodies where the \
             placeholder is in an inner slot (`c[k][i]` shape). \
             Symbolic linearisation lowers k to Const + i to LoopVar; \
             substitution per iter resolves the index correctly."
    );
}

/// Strategy-gate acceptance for `KnownArrayRefs`.
///
/// The strategy gate accepts `IndexedAssignmentLoop |
/// KnownArrayRefs`. This test pins the contract using an
/// Ark-shaped synthetic body — `out[i] <== in[i] + C[i+r]` —
/// that classifies as `KnownArrayRefs` (because of the `C[i+r]`
/// reference into a compile-time array) and passes all
/// downstream gates (no component / call / dot-access /
/// state-carrying var mutation). A future regression that
/// re-tightens the strategy gate or that
/// trips one of the downstream gates on this minimal shape would
/// fail this assertion.
///
/// Note: the synthetic env has C registered in `known_array_values`
/// to make `body_references_known_arrays` fire, mirroring what
/// `inline_component_body` does at `components.rs:212` when Ark is
/// inlined inside its parent (PoseidonEx). The classifier consults
/// `env.known_array_values` so the test must populate it explicitly
/// — without that the body would classify as `IndexedAssignmentLoop`
/// (catch-all signal-ops branch) and the test would pass for the
/// wrong reason.
#[test]
fn is_memoizable_accepts_known_array_refs_strategy_with_const_array() {
    use crate::lowering::utils::bigval::BigVal;
    use crate::lowering::utils::EvalValue;

    let stmts = extract_template_body(
        r#"
            template Ark(t, r) {
                signal input in[t];
                signal output out[t];
                for (var i = 0; i < t; i++) {
                    out[i] <== in[i] + C[i + r];
                }
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

    // Verify the classifier picks KnownArrayRefs given the kav
    // binding for C — this is the precondition for the strategy
    // gate test below.
    let mut env = LoweringEnv::new();
    env.known_array_values.insert(
        "C".to_string(),
        EvalValue::Array(
            (0..16)
                .map(|v| EvalValue::Scalar(BigVal::from_u64(v)))
                .collect(),
        ),
    );
    let strategy = classify_loop_body(&for_body, &env, "i");
    assert_eq!(
        strategy,
        Some(LoopLowering::KnownArrayRefs),
        "Ark-shape body (`out[i] <== in[i] + C[i+r]`) must classify \
             as KnownArrayRefs when C lives in known_array_values. A \
             different classification breaks the precondition for the \
             strategy-gate test below."
    );

    // The Option II contract: KnownArrayRefs strategy is now
    // accepted by `is_memoizable` alongside `IndexedAssignmentLoop`.
    // 6 iters > 4 (iter_count gate); no components, calls, dot-
    // access, var mutations in the body — all downstream gates
    // pass.
    assert!(
        is_memoizable(LoopLowering::KnownArrayRefs, &for_body, "i", 0, 6).is_some(),
        "Option II contract: is_memoizable must accept the \
             `KnownArrayRefs` strategy on bodies that pass all other \
             MVP gates. A `None` here means the strategy gate was \
             re-tightened or one of the downstream gates rejected \
             this minimal Ark-shaped body."
    );
}
