use super::*;

/// `true` unless `R1PP_ENABLED=0` (or `false`) is set in the process
/// environment. The memoized unroll path is the default; set
/// `R1PP_ENABLED=0` to force the direct unroll path. The two
/// modes are byte-identical on every benchmark template and pinned
/// across modes by the adversarial cross-mode tests in
/// `circom/tests/adversarial.rs`.
pub(super) fn r1pp_enabled() -> bool {
    std::env::var("R1PP_ENABLED")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false")))
        .unwrap_or(true)
}

/// A go-ahead from the memoization classifier.
///
/// Carries the LoopVar token to mint for the placeholder. The token is
/// a single 32-bit slot per active capture window; nested memoized
/// loops would need to allocate distinct tokens, but this MVP only
/// memoizes the outermost eligible loop and bails on nested cases via
/// the disqualifier set in [`is_memoizable`].
///
/// `strategy` records which classifier branch admitted the loop so
/// `memoize_loop` can skip work that is only meaningful for one of
/// them — e.g. cloning `pre_env.known_array_values` for the post-
/// substitute kav fold pass, which is a no-op for the
/// `IndexedAssignmentLoop` path.
#[derive(Debug, Clone, Copy)]
pub(super) struct MemoPlan {
    pub(super) token: u32,
    pub(super) strategy: LoopLowering,
}

/// Decide whether this for-loop is safe to memoize.
///
/// Returns `Some(plan)` if every iteration's emission is either:
///   1. Independent of the loop var entirely (the substitute pass is a
///      no-op for those nodes), or
///   2. Differs only by names containing `loop_var_placeholder(token)`
///      and `CircuitExpr::LoopVar(token)` leaves that
///      `substitute_loop_var` will rewrite uniformly, AND
///   3. Reads of compile-time arrays (`KnownArrayRefs` strategy) whose
///      `ArrayIndex { array: <kav-name>, index: <symbolic> }` shape is
///      collapsed to `Const(fc)` per iteration by the post-substitute
///      [`crate::lowering::known_array_fold::fold_known_array_indices`]
///      pass wired into `memoize_loop`.
///
/// Disqualifiers — each rejects the loop and falls back to the legacy
/// unroll. Tightening this set is safer than loosening it; once the
/// classifier returns `Some`, the memoization branch trusts it
/// completely.
///
///   - **`ComponentArrayOps` strategy**: instantiating sub-components
///     per iter requires `EnvFootprint` to mirror more state than it
///     does today (component arrays, pending wiring). Separate widening.
///   - **`MixedSignalVar` strategy**: the body interleaves compile-
///     time `var` mutations with branched signal expressions.
///     Footprint replay can't re-execute the var arithmetic. Note:
///     Mix's outer-i body does NOT classify here empirically (its
///     signal ops are linear, not branched) — it classifies as
///     `KnownArrayRefs` and is rejected downstream by
///     `body_has_state_carrying_var_mutation` instead.
///   - **Iteration count < 4**: memoization overhead (capture clone +
///     N substitutes) likely exceeds the savings on a small loop.
///   - **WitnessCall in body**: `program_bytes` is opaque Artik
///     bytecode; `substitute_loop_var` deliberately does NOT walk
///     into it. Any iter-dependent witness logic embedded in
///     bytecode would replay iter-0 semantics for every iter.
///   - **`var x = …` whose RHS references the loop var**: replaying
///     iter-0's footprint would seed `known_constants` with iter-0's
///     value of `x`, then every replay iter would read the stale value
///     instead of recomputing.
///   - **Nested for/while bound depending on the loop var**: the
///     bound resolves to a `Capture(loop_var)` or expression — under
///     memoization it would carry `LoopVar(token)`, which
///     `eval_const_expr_u64` at instantiate time cannot fold.
pub(super) fn is_memoizable(
    strategy: LoopLowering,
    body: &[Stmt],
    loop_var: &str,
    start: u64,
    end: u64,
) -> Option<MemoPlan> {
    // `KnownArrayRefs` is accepted alongside `IndexedAssignmentLoop`.
    // Memoizing a KnownArrayRefs body — Poseidon's Ark (`out[i] <==
    // in[i] + C[i+r]`), MixS's second-pass loop, etc. — relies on
    // the post-substitute fold pass
    // [`crate::lowering::known_array_fold::fold_known_array_indices`]
    // wired into `memoize_loop` below. The fold collapses
    // `ArrayIndex { array: <kav-name>, index: <fully-const after
    // substitute> }` to `Const(fc)`, mirroring what `lower_index`
    // Case 0 emits for non-placeholder shapes.
    //
    // `ComponentArrayOps` is rejected: instantiating sub-components
    // per iter requires `EnvFootprint` to mirror more state than it
    // does today (component arrays, pending wiring). That's a
    // separate widening with its own state machinery.
    //
    // `MixedSignalVar` is rejected by definition (the body interleaves
    // compile-time `var` mutations with signal expressions that the
    // footprint can't replay). Note that Mix's outer-i body does NOT
    // classify as MixedSignalVar empirically — it classifies as
    // KnownArrayRefs because Mix's signal ops are linear, not
    // branched; `body_mixes_signals_and_vars` only fires on if/else-
    // branched signal ops.
    //
    // `body_has_state_carrying_var_mutation` admits Mix's outer-i
    // body (`lc = 0; for(j) lc += M[j][i]*in[j]; out[i] <== lc;`).
    // The discriminator is whether each name with a CompoundAssign
    // or self-referential SubAssignIdent in the body has a
    // corresponding **in-body reset** (a non-self-referential
    // `Substitution { Assign, Ident(name), value }` earlier in the
    // same body). Mix's `lc = 0` is the reset; Num2Bits's body has
    // neither a reset for `lc1` nor a non-self-referential assign
    // for `e2 = e2 + e2`, so it stays rejected.
    if !matches!(
        strategy,
        LoopLowering::IndexedAssignmentLoop | LoopLowering::KnownArrayRefs
    ) {
        return None;
    }
    // Indexed writes to template-local var arrays (`prod_val[i] = 0;`,
    // `prod_val[i+j] += a[i] * b[j];`) need real iter constants to
    // resolve the flat element name at capture time. The memoize path
    // holds the loop var as a `LoopVar(token)` placeholder and re-runs
    // only `substitute_loop_var` per replay — there is no `const_eval_ctx`
    // pass after substitution that would re-resolve the var-array
    // element write. Bail to the direct unroll path, which seeds
    // `env.known_constants[loop_var]` per iter. Uses the shape-only
    // variant — the memoize gate runs without an `env` snapshot, and
    // both var-array and component-array indexed writes share the
    // same disqualifying shape.
    if body_has_indexed_assign_shape(body) {
        return None;
    }
    if end <= start || (end - start) < 4 {
        return None;
    }
    if body_has_witness_call(body) {
        return None;
    }
    if body_has_loop_var_dependent_var_decl(body, loop_var) {
        return None;
    }
    if body_has_nested_loop_with_loop_var_bound(body, loop_var) {
        return None;
    }
    if body_has_state_carrying_var_mutation(body) {
        return None;
    }
    // MVP-conservative gates. Each one excludes a class of bodies that
    // exposes a soundness or instantiation gap in the current
    // capture+substitute model. Loosening any of these requires a
    // matching extension elsewhere — see the comment per-gate.
    //
    // - Component decls / instantiations: D2 plumbed the placeholder
    //   through the AssignTarget side, but multi-step component-of-
    //   component patterns (`escalarMuls[i].windows[j].table` in
    //   Pedersen_old) and the post-iter env-state mirroring for
    //   complex sub-template registrations have edge cases that
    //   produce `is not an array` errors at instantiate. Reject for
    //   now; widen once a regression test pins the exact missing
    //   `apply_substituted` field.
    // - Function calls: const-eval-via-function-evaluation paths
    //   (e.g. `var nb = nbits(maxval);` returning loop-var-dependent
    //   shapes) are out of scope for the MVP; the
    //   `body_has_state_carrying_var_mutation` rule covers most
    //   call-via-var-decl shapes, but bare expression calls in signal
    //   positions still need analysis.
    // - Multi-dim signal-array reads (`c[i][k]`): the placeholder
    //   breaks the const-fold chain in `lower_multi_index`, so a
    //   phantom-`ArrayIndex` + missing-strides defence-in-depth (E213)
    //   blocks the unsafe shape at lower time. The simpler MVP gates
    //   below (component_or_call, dot_access, capture_array, iter < 4)
    //   already exclude every body that exercises the multi-dim path,
    //   so no separate disqualifier is needed for it. Widening any of
    //   those gates re-exposes the question whether the placeholder +
    //   phantom-ArrayIndex + strides guards cover the new shape —
    //   re-validate end-to-end before loosening.
    if body_has_component_or_call(body) {
        return None;
    }
    // Exclude any DotAccess (`comp.sig`, `arr.field`). The placeholder
    // path through component-scoped reads still has gaps for inlined
    // sub-template's array-typed signal captures (`verifier.hash.pEx.ark_0.C`
    // in EdDSAPoseidon hits these). Until the env-state mirroring for
    // sub-template array CaptureArrayDef bindings is complete, the
    // safe call is to refuse memoization for any body that reads
    // through a `.field` chain.
    if body_has_dot_access(body) {
        return None;
    }
    // No `body_reads_capture_array` gate is needed — array template
    // params land in `env.known_array_values` (`components.rs:212`),
    // NOT `env.captures` (which only carries scalars per
    // `components.rs:204-208`), so a `captures.contains(name)` check
    // would never trip on a real array binding. The originally
    // motivating shape (`verifier.hash.pEx.ark_0.C is not an array`
    // at instantiate) is rejected at lower time by the E213
    // phantom-`ArrayIndex` guard. Limitation noted: `EnvFootprint`
    // does not mirror `env.captures` mutations — see
    // `env_footprint.rs:47-65`. This matters only if a future
    // widening admits bodies that mutate captures across iters;
    // until then it's a documented blind spot.
    Some(MemoPlan { token: 0, strategy })
}
