use super::*;

/// Which unroll strategy applies to a given `for` loop body.
///
/// Computed once up-front by `classify_loop_body` and consumed by the
/// dispatch in `lower_for_loop`. Mutually exclusive and exhaustive:
/// exactly one variant applies to any loop we choose to unroll at
/// lowering time.
///
/// `None` from `classify_loop_body` means the loop stays as an
/// IR-level `CircuitNode::For` — the dispatch handles that in the
/// fall-through branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::lowering::statements) enum LoopLowering {
    /// Body contains `component c[i] = Template()` or similar, where
    /// component inlining needs a concrete numeric `i` at lowering time.
    ComponentArrayOps,

    /// Body references compile-time arrays (`C[i]`, `M[i][j]`) that
    /// must be resolved before emission.
    KnownArrayRefs,

    /// Body mixes signal statements with `var` mutations
    /// (`CompConstant`, `MiMC7`, `MiMCSponge`). Compile-time vars
    /// drive coefficients in signal expressions, so they need to
    /// be concrete constants, not circuit variables.
    MixedSignalVar,

    /// Body contains an array indexing expression `arr[idx]` whose
    /// index references the loop variable — either as an assignment
    /// target (`arr[i] <== ...`, `arr[i] <-- ...`) or as a read
    /// inside any expression (`acc += a[i]`, `mux.c[0][i]`, nested
    /// component `comp.in[i]`). The downstream emission pipeline
    /// (ProveIR `LetIndexed` / `WitnessHintIndexed` /
    /// `CircuitExpr::ArrayIndex`) needs a compile-time constant
    /// index at instantiate time; the Lysis Symbolic path in
    /// particular cannot resolve a loop-var SSA slot there. Unroll
    /// at lowering so every per-iteration expansion sees a concrete
    /// `i`. Example: SHA-256 `paddedIn[k] <-- 0` (write) and
    /// `sigmaPlus.sum.in[i] <== prior[i]` (read + write).
    IndexedAssignmentLoop,
}

/// Classify a `for` loop body into a [`LoopLowering`] strategy, or
/// return `None` if the body can stay as a `CircuitNode::For` node.
///
/// Priority chain: `MixedSignalVar`, `ComponentArrayOps`,
/// `KnownArrayRefs`, `IndexedAssignmentLoop`. The first three depend
/// on compile-time eval semantics that preempt a pure indexed-
/// assignment classification; `IndexedAssignmentLoop` is the
/// catch-all for loops whose only lowering-time requirement is
/// concrete indices in assignment targets.
pub(in crate::lowering::statements) fn classify_loop_body(
    stmts: &[Stmt],
    env: &LoweringEnv,
    loop_var: &str,
) -> Option<LoopLowering> {
    // Bodies that touch a template-local `var` array (writes or reads
    // through a registered base in `env.local_var_arrays`) need the
    // loop unroller to resolve `i` to a constant per iteration:
    //   - Writes (`prod_val[i] = 0;`, `prod_val[i+j] += a[i]*b[j];`)
    //     lower to one SSA `Let { name: "prod_val_<flat>", value: … }`
    //     per iter via `resolve_local_array_element_name`, which
    //     requires concrete indices to materialise the flat slot name.
    //   - Reads (`out[i] <== prod_val[i];`) resolve through
    //     `env.resolve_array_element` to a concrete `Var("prod_val_<i>")`;
    //     leaving the loop rolled would emit a phantom
    //     `ArrayIndex { array: "prod_val" }` that has no
    //     `WitnessArrayDecl` shape at instantiate time and would surface
    //     "the array is not declared in this scope".
    //
    // Preempts `MixedSignalVar` because that regime's `cte` path
    // consumes var-only stmts via `try_eval_at_compile_time` *without*
    // emitting the SSA-shadow Lets — a `prod_val[i] = 0` would silently
    // get dropped, leaving the later read pointing at an undefined Var.
    //
    // Discrimination from `ComponentArrayOps`: component-array element
    // instantiation (`muls[i] = T()`) shares the same outer AST shape
    // (`Substitution { op: Assign, target: Index{...} }`), so the
    // predicates filter by `env.local_var_arrays.contains(base)` — only
    // names declared via `var X[N];` route through here. The fall-
    // through still reaches `body_has_component_array_ops` for the
    // pure component-array bodies.
    if body_has_local_var_array_indexed_writes(stmts, env)
        || body_has_local_var_array_indexed_reads(stmts, env)
    {
        return Some(LoopLowering::IndexedAssignmentLoop);
    }
    if body_mixes_signals_and_vars(stmts) {
        return Some(LoopLowering::MixedSignalVar);
    }
    if body_has_component_array_ops(stmts, env) {
        return Some(LoopLowering::ComponentArrayOps);
    }
    if body_references_known_arrays(stmts, env) {
        return Some(LoopLowering::KnownArrayRefs);
    }
    // The rolled-loop path below cannot soundly represent two
    // body shapes; both must fall through to unrolling here.
    //
    // **Outer-scope `var` accumulator** — a `var` declared outside
    // the loop and updated inside (`acc += body[i] * coef`) escapes
    // the loop. The instantiator's body-once symbolic walk
    // collapses the accumulator's SSA chain (e.g. `0 + x*1 → x`)
    // and leaks the body-local SsaVar into the outer env, producing
    // a stream the walker rejects with `UndefinedSsaVar`.
    //
    // **Sub-component array write** — `<comp>.<arr>[i] <== ...` to
    // a scalar sub-component's input array. Sub-component arrays
    // are registered in `LoweringEnv` at component-decl lowering
    // but never emitted as `WitnessArrayDecl` IR nodes, so the
    // instantiator's `snapshot_array_slots` returns None and the
    // emit fails with "symbolic indexed write into <comp>.<arr>
    // but the array is not declared in this scope".
    //
    // Classifier-ordering invariant: BOTH predicates run *after*
    // `MixedSignalVar` / `ComponentArrayOps` / `KnownArrayRefs`
    // have already preempted. SHA-256's nested sub-component
    // wirings hit `ComponentArrayOps` on the outer `for(i)` and
    // never reach this gate; do not reorder.
    let writes_outer_var = body_writes_to_outer_scope_var(stmts, env, loop_var)
        || body_writes_to_subcomponent_array(stmts, env, loop_var);

    // Inlined sub-template bodies use a fresh `LoweringEnv` whose
    // signal-array declarations and component bindings are not
    // visible upstream. The `SymbolicIndexedEffect` path requires
    // the array to be in scope as a `WitnessArrayDecl` at the
    // *outer* template's instantiation time, which doesn't hold
    // across inline boundaries; force unroll for any indexed-
    // assignment loop in an inlined env. The outer template's own
    // loops are unaffected — they're classified with
    // `is_inlined = false` and follow the env-aware
    // `writes_outer_var` rule.
    let must_unroll_for_inline = env.is_inlined;

    if body_has_loop_var_indexed_assignments(stmts, loop_var) {
        // The SymbolicIndexedEffect path (instantiate Stage 2 + walker
        // Stage 3) carries loop-var-indexed signal writes through to
        // bytecode without unrolling at lowering time. Keep the loop
        // rolled and let `lower_for` emit a `CircuitNode::For` —
        // unless the body also writes outer-scope vars / sub-component
        // arrays, or we're in an inlined sub-template context, in
        // which case the symbolic path can't represent the write
        // (the array isn't a `WitnessArrayDecl` visible to the outer
        // instantiator).
        if must_unroll_for_inline || writes_outer_var {
            return Some(LoopLowering::IndexedAssignmentLoop);
        }
        return None;
    }
    // Catch-all: any loop whose body emits signal work (constraints,
    // witness hints, component wiring) follows the same gate. Loops
    // whose body is symbolic-clean stay rolled as `CircuitNode::For`
    // and the walker handles them via `SymbolicIndexedEffect` +
    // per-iter unrolling. Loops with only compile-time `var`
    // arithmetic (accumulators, counters) likewise remain rolled.
    if body_has_any_signal_ops(stmts) {
        if must_unroll_for_inline || writes_outer_var {
            return Some(LoopLowering::IndexedAssignmentLoop);
        }
        return None;
    }
    None
}
