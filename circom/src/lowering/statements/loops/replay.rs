use super::*;

/// Capture iter `start` with the loop-var placeholder, then clone +
/// substitute for each remaining iter `n in (start+1)..end`.
///
/// The captured node slice and `EnvFootprint` together describe one
/// iteration's complete effect on the parent scope. Replay re-applies
/// the env diff (with placeholder substituted) and clones the captured
/// nodes (with `LoopVar(token)` → `Const(n)` and `$LV{token}$` → `n`
/// substituted). Constraint downstream sees structurally identical IR
/// to the legacy unroll, so `eval_const_expr` on `LetIndexed` /
/// `ArrayIndex` resolves indices and instantiate's existing path picks
/// up `array_slots[n]`.
#[allow(clippy::too_many_arguments)]
pub(super) fn memoize_loop<'a>(
    var_name: &str,
    start: u64,
    end: u64,
    body: &'a ast::Block,
    _span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    plan: MemoPlan,
) -> Result<(), LoweringError> {
    let token = plan.token;

    // Snapshot the env *before* the iter-0 capture so the footprint
    // diff isolates exactly the mutations this iteration caused.
    let pre_env = env.clone();

    // Snapshot the parent-scope kav for the post-substitute fold
    // pass. Ark's `known_array_values["C"]` was inserted at
    // sub-template inlining time (`components.rs:212`), i.e. BEFORE
    // entering this for-loop body, so the snapshot is the
    // authoritative source. Late-bound additions during body lowering
    // (none observed empirically) would not be reflected — if a
    // future widening admits bodies that mutate
    // `known_array_values` mid-iteration, swap to referencing the
    // live `env.known_array_values` after the post-capture
    // `*env = pre_env` reset.
    //
    // The clone is gated on `KnownArrayRefs` because the fold pass that
    // consumes the snapshot only fires kav-named `ArrayIndex` residuals,
    // which classify exclusively under that strategy
    // (`body_references_known_arrays` is the predicate). The
    // `IndexedAssignmentLoop` path admits no kav reads, so an empty map
    // is sound — the fold pass walks the body once and finds nothing to
    // collapse, byte-identical output.
    let kav_snapshot: HashMap<String, EvalValue> =
        if matches!(plan.strategy, LoopLowering::KnownArrayRefs) {
            pre_env.known_array_values.clone()
        } else {
            HashMap::new()
        };

    // Capture iter `start`. The placeholder takes precedence over
    // `known_constants` for `Ident(loop_var)` lowering (Phase D1) AND
    // we deliberately do NOT seed `known_constants[loop_var]` with
    // the iter value. Two reasons:
    //
    //  1. `lower_multi_index`'s fast path tries `const_eval_u64` /
    //     `const_eval_with_params` on each index expression. The
    //     latter consults `known_constants`. If the loop var were
    //     present, multi-dim shapes like `c[i][k]` would fold the
    //     `i` slot to a numeric, take the
    //     `resolve_array_element` → `Var("c_<linear>")` branch, and
    //     bake iter-`start`'s numeric into the emitted name — which
    //     `substitute_loop_var` cannot rewrite (no placeholder
    //     substring), producing a wrong reference for every replay
    //     iter. MultiMux3's `c[i][k]` is the canonical case.
    //
    //  2. Component-array name resolution (D2) already consults the
    //     placeholder before falling through to the numeric path, so
    //     the absence of `known_constants[loop_var]` doesn't lose
    //     coverage there — the placeholder branch always wins for the
    //     bare-Ident shape.
    //
    // Consequence: any helper that resolves the loop var via
    // `known_constants` during the capture window will see `None`.
    // The `is_memoizable` classifier is responsible for rejecting any
    // body shape that would have needed that fallback (e.g. nested
    // loops with bounds that depend on the outer loop var, var decls
    // whose RHS reads the loop var via const-eval).
    ctx.placeholder_loop_var = Some((var_name.to_string(), token));

    let body_start = nodes.len();
    for stmt in &body.stmts {
        super::super::lower_stmt(stmt, env, nodes, ctx, pending)?;
    }
    let body_end = nodes.len();

    // Capture the footprint *before* clearing the placeholder so any
    // post-cleanup mutations don't pollute the diff.
    let footprint = EnvFootprint::from_diff(&pre_env, env, var_name);

    // Clear the placeholder before replay — nothing in the replay
    // path needs it (replay clones already-substituted node templates,
    // and `apply_substituted` substitutes env names directly).
    ctx.placeholder_loop_var = None;

    // Snapshot the captured iter-`start` body so the per-iter clones
    // don't see the new nodes pushed by replays. Without the snapshot
    // a 64-iter SHA-256 round body would clone iter `start`'s body,
    // then iter `start+1`'s body, etc. — quadratic blowup.
    let body_template: Vec<CircuitNode> = nodes[body_start..body_end].to_vec();

    // Substitute the iter-`start` nodes IN PLACE — they're still in
    // `nodes` carrying `LoopVar(token)` literals and `$LV{token}$`
    // name fragments. Substituting the iter value here matches what
    // a legacy unroll would have emitted for iter `start` byte-for-
    // byte; without this step the placeholders would reach
    // instantiate and trip the `LoopVar` exhaustive-match panic.
    substitute_loop_var(&mut nodes[body_start..body_end], token, start);

    // R1″ Option II: fold any `ArrayIndex { array: <kav-name>, index:
    // <now-foldable> }` residuals into `Const(fc)`. No-op for
    // KnownArrayRefs-free bodies (the dominant SHA-256 / Pedersen
    // case); Ark/MixS bodies see their `C[N+r]` / `S[N]` collapse to
    // the same `Const` leaves a legacy `lower_index` Case 0 emit would
    // produce. Without this fold the kav-named ArrayIndex would dangle
    // at instantiate (no env binding for `C`).
    crate::lowering::known_array_fold::fold_known_array_indices(
        &mut nodes[body_start..body_end],
        &kav_snapshot,
        Some(&*env),
    );

    // Reset env to its pre-iter state. Capture left placeholder-named
    // entries (`Sigma0_$LV0$`) in env; replay rewrites them to the
    // concrete iter names (`Sigma0_0`, `Sigma0_1`, …) by re-applying
    // the footprint with substitution. Without the reset, the
    // placeholder entries would linger AND coexist with the
    // substituted ones, leaking placeholder strings into post-loop
    // resolution (collect_value_component_refs, env.resolve, etc.).
    *env = pre_env;

    // Replay iters `start..end`. The iter-`start` re-application is
    // what the legacy unroll did at iter-`start` exit; we already
    // emitted those nodes (substituted in place above), but the env
    // state still needs to reflect them.
    for iter in start..end {
        footprint.apply_substituted(env, token, iter);
        env.known_constants
            .insert(var_name.to_string(), FieldConst::from_u64(iter));

        // iter `start`'s nodes are already in `nodes` (substituted
        // in place). Skip the clone for that one.
        if iter == start {
            continue;
        }

        let mut iter_nodes = body_template.clone();
        substitute_loop_var(&mut iter_nodes, token, iter);
        crate::lowering::known_array_fold::fold_known_array_indices(
            &mut iter_nodes,
            &kav_snapshot,
            Some(&*env),
        );
        nodes.extend(iter_nodes);
    }

    // Match legacy unroll's post-loop cleanup: the loop var stops
    // being a known constant once the loop ends.
    env.known_constants.remove(var_name);

    Ok(())
}

/// Evaluate a var-only statement at compile time inside
/// `CompileTimeEnv`. Returns `true` iff the stmt's effect was
/// captured (the loop unroll then skips the real `lower_stmt` call
/// for that stmt).
pub(super) fn try_eval_at_compile_time(
    stmt: &Stmt,
    cte: &mut CompileTimeEnv,
    ctx: &LoweringContext,
) -> bool {
    let functions: HashMap<&str, &crate::ast::FunctionDef> =
        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();
    crate::lowering::utils::try_eval_stmt_in_place(stmt, cte.as_bigval_map_mut(), &functions)
        .is_some()
}

/// If the most-recently-emitted node was a const-foldable `Let`
/// targeting the same name as the AST `Substitution`, mirror that
/// binding into `env.known_constants` and `cte` so the next
/// iteration's compile-time eval reads the fresh value. Handles the
/// MiMC7 `t = t7[i-1] + c[i]` case.
pub(super) fn sync_post_emission(
    stmt: &Stmt,
    nodes: &[CircuitNode],
    pre_len: usize,
    cte: &mut CompileTimeEnv,
    env: &mut LoweringEnv,
) {
    let Stmt::Substitution {
        op: AssignOp::Assign,
        target: Expr::Ident {
            name: target_name, ..
        },
        ..
    } = stmt
    else {
        return;
    };
    let Some(CircuitNode::Let { name, value, .. }) =
        nodes.get(pre_len..).and_then(|new_nodes| new_nodes.last())
    else {
        return;
    };
    if name != target_name {
        return;
    }
    match crate::lowering::const_fold::try_fold_const(value) {
        Some(fc) => {
            env.known_constants.insert(name.clone(), fc);
            cte.insert(name.clone(), BigVal::from_field_const(fc));
        }
        None => {
            env.known_constants.remove(name);
        }
    }
}
