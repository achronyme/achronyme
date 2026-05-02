//! Loop lowering: for loops, while loops, and compile-time loop evaluation.
//!
//! Circom for loops must have deterministic bounds for circuit compilation.
//! While loops are only allowed when they touch variables (not signals/components)
//! and are evaluated entirely at compile time.

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir_forge::types::{CircuitNode, FieldConst, ForRange};

use crate::ast::{self, AssignOp, BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt};

use super::super::compile_time::CompileTimeEnv;
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::env_footprint::EnvFootprint;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::loop_var_subst::substitute_loop_var;
use super::super::utils::{const_eval_u64, BigVal, EvalValue};
use super::arrays::{body_has_component_array_ops, body_references_known_arrays};
use super::targets::extract_target_name;
use super::wiring::PendingComponent;

/// Lower a C-style for loop to a ProveIR `For` node.
///
/// Circom for loops must have deterministic bounds for circuit compilation.
/// We try to extract `for (var i = start; i < end; i++)` patterns.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_for_loop<'a>(
    init: &Stmt,
    condition: &Expr,
    step: &Stmt,
    body: &'a ast::Block,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Extract loop variable and start value from init
    let (var_name, start) = match init {
        Stmt::VarDecl {
            names,
            init: Some(init_expr),
            ..
        } if names.len() == 1 => {
            // Fall back to param-aware evaluation for the common pattern
            // `for (var k = nBits+1; ...)` where `nBits` is a template
            // parameter — circomlib SHA256 uses this in padding loops.
            let all = ctx.all_constants(env);
            let start = const_eval_u64(init_expr)
                .or_else(|| super::super::utils::const_eval_with_params(init_expr, &all)?.to_u64())
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "for loop init must be a compile-time constant",
                        "E208",
                        span,
                    )
                })?;
            (names[0].clone(), start)
        }
        // `for (i = 0; ...)` where `i` is already declared via `var i;`
        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            value,
            ..
        } => {
            let name = extract_target_name(target).ok_or_else(|| {
                LoweringError::with_code(
                    "for loop init must assign to a simple variable",
                    "E208",
                    span,
                )
            })?;
            let all = ctx.all_constants(env);
            let start = const_eval_u64(value)
                .or_else(|| super::super::utils::const_eval_with_params(value, &all)?.to_u64())
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "for loop init must be a compile-time constant",
                        "E208",
                        span,
                    )
                })?;
            (name, start)
        }
        _ => {
            return Err(LoweringError::with_code(
                "for loop must use `var i = <const>` or `i = <const>` initialization",
                "E208",
                span,
            ));
        }
    };

    // Extract end bound + direction from condition.
    // Ascending: `i < N` / `i <= N`. Descending: `i != -1`.
    let parsed = extract_loop_bound(condition, &var_name, env).ok_or_else(|| {
        LoweringError::with_code(
            "for loop condition must be `i < <bound>`, `i <= <bound>`, or \
             `i != -1` where <bound> is a constant or template parameter",
            "E208",
            span,
        )
    })?;
    let bound = parsed.bound;
    let is_descending = parsed.is_descending;

    // Validate step direction matches the condition direction.
    let step_is_descending = validate_loop_step(step, &var_name, span)?;
    if step_is_descending != is_descending {
        return Err(LoweringError::with_code(
            "for loop step direction does not match condition: ascending \
             condition (`i <`/`i <=`) requires `++`/`+= 1`; descending \
             condition (`i != -1`) requires `--`/`-= 1`",
            "E208",
            span,
        ));
    }

    // Register loop variable
    env.locals.insert(var_name.clone());

    // Classify the body to decide whether to unroll at lowering time
    // and — if so — which strategy governs the unroll.
    let Some(strategy) = classify_loop_body(&body.stmts, env, &var_name) else {
        return emit_for_node(var_name, bound, start, body, span, env, nodes, ctx, pending);
    };

    let is_mixed = strategy == LoopLowering::MixedSignalVar;
    let end = resolve_bound_to_u64(&bound, env, ctx, span)?;

    // R1″ Phase 6 / Option D: memoized unroll. Capture iter `start`
    // with the loop variable held as a `LoopVar(token)` placeholder;
    // replay each remaining iter by cloning the captured node slice
    // and `substitute_loop_var`-rewriting the placeholder to the iter
    // value. Saves the dominant `lower_stmt` cost on heavy bodies
    // (SHA-256 round body in particular) without changing any
    // constraint downstream — the substituted slice is structurally
    // identical to what the legacy unroll would have emitted for that
    // iter. Default-on after D4 validation closed (550 tests + 8/8
    // byte-identical benchmarks under both polarities); set
    // `R1PP_ENABLED=0` to opt out and exercise the legacy unroll path.
    // Memoization assumes an ascending range; descending loops fall
    // through to the direct unroll below.
    if !is_descending && r1pp_enabled() {
        if let Some(plan) = is_memoizable(strategy, &body.stmts, &var_name, start, end) {
            return memoize_loop(
                &var_name, start, end, body, span, env, nodes, ctx, pending, plan,
            );
        }
    }

    // Unroll: for each iteration, set loop var as known constant, lower body.
    // For mixed signal+var loops (e.g. CompConstant), evaluate var-only
    // statements at compile time so vars like `b`, `a`, `e` become concrete
    // constants usable as coefficients in signal expressions.
    //
    // `CompileTimeEnv` is the single source of truth for the compile-time
    // var snapshot. For non-mixed strategies it stays empty — that path
    // drives `env.known_constants` directly and never consults `cte`.
    let mut cte = if is_mixed {
        CompileTimeEnv::from_constants(&ctx.param_values, &env.known_constants)
    } else {
        CompileTimeEnv::new()
    };
    // Build the iter value sequence. Ascending: `start..end` (end
    // exclusive). Descending: `(end..=start).rev()` (end is the
    // lower-inclusive bound, e.g. 0 for `i != -1`).
    let iter_values: Vec<u64> = if is_descending {
        (end..=start).rev().collect()
    } else {
        (start..end).collect()
    };
    for i in iter_values {
        env.known_constants
            .insert(var_name.clone(), FieldConst::from_u64(i));
        if is_mixed {
            cte.insert(var_name.clone(), BigVal::from_u64(i));
        }
        for stmt in &body.stmts {
            if is_mixed && stmt_is_var_only(stmt) && try_eval_at_compile_time(stmt, &mut cte, ctx) {
                // Write back evaluated vars to param_values AND
                // known_constants so lower_expr emits Const(val)
                // instead of Var(name) for compile-time vars.
                //
                // Do NOT write back the loop variable itself — it is
                // managed by env.known_constants at the top of each
                // iteration. Writing it to ctx.param_values would
                // pollute the persistent map with the iteration-0 value,
                // which then shadows the correct iteration value (via
                // `or_insert` in `all_constants`) for all later iterations.
                for (k, fc) in cte.field_const_iter() {
                    if k == &var_name {
                        continue;
                    }
                    ctx.param_values.insert(k.clone(), fc);
                    env.known_constants.insert(k.clone(), fc);
                }
                continue;
            }
            // Fallthrough: lower the stmt normally. After emission, if
            // we're in the mixed-signal-var eval path (e.g., MiMC7's
            // var `t`) AND the stmt was a plain `Ident = expr`
            // Substitution that fell through here (because its RHS
            // referenced an intermediate signal array element like
            // `t7[i-1]` that wasn't visible to `cte`), keep
            // `env.known_constants` in sync with the newly pushed
            // `Let { name, value }` so subsequent stmts in the same
            // unrolled iteration fold against the up-to-date value
            // instead of the stale one written back by the previous
            // iteration's var-only eval.
            //
            // Gated on MixedSignalVar because that is the only regime
            // where iteration N's var-only eval may seed
            // `env.known_constants` with a stale value that iteration
            // N+1's fallthrough needs to overwrite. Other unroll
            // regimes (ComponentArrayOps / KnownArrayRefs — e.g.
            // Poseidon's `Mix` template) run CompoundAssign loops that
            // bind a var name to a non-const circuit expression;
            // touching `env.known_constants` there would fold the var
            // to its initial literal and silently zero out the
            // accumulator.
            let pre_len = nodes.len();
            super::lower_stmt(stmt, env, nodes, ctx, pending)?;
            if is_mixed {
                sync_post_emission(stmt, nodes, pre_len, &mut cte, env);
            }
        }
    }
    env.known_constants.remove(&var_name);
    // Clean up vars injected during mixed-loop unrolling
    if is_mixed {
        for name in cte.var_names() {
            if name != &var_name {
                env.known_constants.remove(name);
            }
        }
    }

    Ok(())
}

// ─── R1″ Phase 6 / Option D — memoized unroll ───────────────────────

/// `true` unless `R1PP_ENABLED=0` (or `false`) is set in the process
/// environment. The memoized unroll path is the default after D4
/// validation closed (Follow-up D, 2026-04-27): 550 tests pass under
/// both polarities, 8/8 benchmark templates byte-identical, and 4
/// adversarial soundness tests pin the cross-mode invariants. Set
/// `R1PP_ENABLED=0` to force the legacy unroll path — useful for
/// cross-mode debugging and the byte-identical asserts in
/// `circom/tests/adversarial.rs`.
fn r1pp_enabled() -> bool {
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
struct MemoPlan {
    token: u32,
    strategy: LoopLowering,
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
///     bytecode; `substitute_loop_var` deliberately does NOT walk it
///     (see Phase 2 caveat). Any iter-dependent witness logic embedded
///     in bytecode would replay iter-0 semantics for every iter.
///   - **`var x = …` whose RHS references the loop var**: replaying
///     iter-0's footprint would seed `known_constants` with iter-0's
///     value of `x`, then every replay iter would read the stale value
///     instead of recomputing.
///   - **Nested for/while bound depending on the loop var**: the
///     bound resolves to a `Capture(loop_var)` or expression — under
///     memoization it would carry `LoopVar(token)`, which
///     `eval_const_expr_u64` at instantiate time cannot fold.
fn is_memoizable(
    strategy: LoopLowering,
    body: &[Stmt],
    loop_var: &str,
    start: u64,
    end: u64,
) -> Option<MemoPlan> {
    // R1″ Phase 6 / Option II (commit `2bd57034`): `KnownArrayRefs` is
    // accepted alongside `IndexedAssignmentLoop`. Memoizing a
    // KnownArrayRefs body — Poseidon's Ark (`out[i] <== in[i] +
    // C[i+r]`), MixS's second-pass loop (`out[i] <== in[i] + in[0] *
    // S[(t*2-1)*r + t + i - 1]`), etc. — relies on the post-substitute
    // fold pass [`crate::lowering::known_array_fold::fold_known_array_indices`]
    // wired into `memoize_loop` below. The fold collapses
    // `ArrayIndex { array: <kav-name>, index: <fully-const after
    // substitute> }` to `Const(fc)`, mirroring what legacy
    // `lower_index` Case 0 emits for non-placeholder shapes.
    //
    // `ComponentArrayOps` remains rejected: instantiating sub-
    // components per iter requires `EnvFootprint` to mirror more state
    // than it does today (component arrays, pending wiring). That's a
    // separate widening with its own state machinery.
    //
    // `MixedSignalVar` remains rejected by definition (the body
    // interleaves compile-time `var` mutations with signal expressions
    // that the footprint can't replay). Note that Mix's outer-i body
    // does NOT classify as MixedSignalVar empirically — it classifies
    // as KnownArrayRefs because Mix's signal ops are linear, not
    // branched; `body_mixes_signals_and_vars` only fires on if/else-
    // branched signal ops.
    //
    // R1″ Phase 6 / Follow-up D: `body_has_state_carrying_var_mutation`
    // was loosened to admit Mix's outer-i body (`lc = 0; for(j) lc +=
    // M[j][i]*in[j]; out[i] <== lc;`). The discriminator is whether
    // each name with a CompoundAssign or self-referential SubAssignIdent
    // in the body has a corresponding **in-body reset** (a non-self-
    // referential `Substitution { Assign, Ident(name), value }` earlier
    // in the same body). Mix's `lc = 0` is the reset; Num2Bits's
    // body has neither a reset for `lc1` nor a non-self-referential
    // assign for `e2 = e2 + e2`, so it stays rejected.
    if !matches!(
        strategy,
        LoopLowering::IndexedAssignmentLoop | LoopLowering::KnownArrayRefs
    ) {
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
    //   breaks the const-fold chain in `lower_multi_index`, with
    //   defence-in-depth phantom-`ArrayIndex` and missing-strides
    //   guards (E213). See R1″ Phase 6 / Follow-up A. The previous
    //   `body_has_multi_dim_index` disqualifier (added 8bfd2fd4,
    //   gate removed 6a4e5f36, walker deleted 71383148) is no
    //   longer load-bearing FOR BODIES THAT PASS THE OTHER MVP GATES
    //   (component_or_call, dot_access, capture_array, iter < 4).
    //   Widening any of those re-exposes the question whether the
    //   placeholder + phantom-ArrayIndex + strides guards cover the
    //   new shape — re-validate end-to-end before loosening.
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
    // R1″ Phase 6 / Follow-up B: the previous `body_reads_capture_array`
    // gate was empirically vestigial — instrumentation across the full
    // e2e suite (EdDSAPoseidon, MiMCSponge, Pedersen, SHA-256, Poseidon)
    // confirmed it fires 5 times total, never returns `true`. Reason:
    // array template params land in `env.known_array_values`
    // (`components.rs:212`), NOT `env.captures` (which only carries
    // scalars per `components.rs:204-208`); the predicate's
    // `env.captures.contains(name)` check therefore never trips on a
    // real array binding. The gate's original use case
    // (`verifier.hash.pEx.ark_0.C is not an array` at instantiate) was
    // closed structurally by Edit 2 of Follow-up A's E213
    // phantom-`ArrayIndex` guard, which now rejects such cases at
    // lowering time. Limitation noted: `EnvFootprint` does not mirror
    // `env.captures` mutations — see `env_footprint.rs:47-65`. This
    // matters only if a future widening admits bodies that mutate
    // captures across iters; until then it's a documented blind spot.
    Some(MemoPlan { token: 0, strategy })
}

fn body_has_dot_access(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_dot_access)
}

fn stmt_has_dot_access(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_has_dot_access(target) || expr_has_dot_access(value)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_has_dot_access(target) || expr_has_dot_access(value)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => expr_has_dot_access(lhs) || expr_has_dot_access(rhs),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_dot_access(condition)
                || then_body.stmts.iter().any(stmt_has_dot_access)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_dot_access),
                    Some(ElseBranch::IfElse(s)) => stmt_has_dot_access(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_dot_access),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_dot_access)
        }
        _ => false,
    }
}

fn expr_has_dot_access(expr: &Expr) -> bool {
    match expr {
        Expr::DotAccess { .. } => true,
        Expr::Index { object, index, .. } => {
            expr_has_dot_access(object) || expr_has_dot_access(index)
        }
        Expr::BinOp { lhs, rhs, .. } => expr_has_dot_access(lhs) || expr_has_dot_access(rhs),
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_dot_access(operand),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_has_dot_access(condition)
                || expr_has_dot_access(if_true)
                || expr_has_dot_access(if_false)
        }
        Expr::Call { args, .. } => args.iter().any(expr_has_dot_access),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(expr_has_dot_access)
        }
        _ => false,
    }
}

fn body_has_component_or_call(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_component_or_call)
}

fn stmt_has_component_or_call(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::ComponentDecl { .. } => true,
        Stmt::Substitution { value, target, .. } => {
            // `comp[i] = T()` is parsed as Substitution; reject any
            // Substitution whose value is a Call (template instantiation
            // or function call).
            expr_contains_call(value) || expr_contains_call(target)
        }
        Stmt::CompoundAssign { value, .. } => expr_contains_call(value),
        Stmt::ConstraintEq { lhs, rhs, .. } => expr_contains_call(lhs) || expr_contains_call(rhs),
        Stmt::VarDecl { init, .. } => init.as_ref().is_some_and(expr_contains_call),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_contains_call(condition)
                || then_body.stmts.iter().any(stmt_has_component_or_call)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_component_or_call),
                    Some(ElseBranch::IfElse(s)) => stmt_has_component_or_call(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_component_or_call),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_component_or_call)
        }
        _ => false,
    }
}

fn expr_contains_call(expr: &Expr) -> bool {
    expr_has_call(expr)
}

/// `true` iff the body has a state-carrying var mutation that is NOT
/// offset by an in-body reset of the same name.
///
/// A mutation is **state-carrying** when iter-N's value of a compile-
/// time `var` depends on iter-(N-1)'s value, which the memoization
/// replay model can't reconstruct (the captured iter-`start` body would
/// emit a snapshot of iter-`start`'s var values; replay just clones +
/// substitutes the placeholder, no per-iter recomputation). Examples:
///   - **Num2Bits's `lc1 += out[i] * e2`** — `lc1` accumulates without
///     a fresh reset in the body, so iter 0's final `lc1` value would
///     leak into iter 1.
///   - **Num2Bits's `e2 = e2 + e2`** — self-referential SubAssignIdent;
///     iter N's value is `2^N * iter_start_e2`, depends on prior iter.
///   - **MixS first-loop `lc += S[r*5+i]*in[i]`** — same shape as
///     Num2Bits's lc1: CompoundAssign with no in-body reset.
///
/// A mutation is **offset (safe)** when the same name has an earlier
/// non-self-referential `Substitution { Assign, Ident(name) }` in the
/// **same body**. Each iter starts fresh: the IR-level SSA shadowing
/// chain begins anew with the reset's `Let { name, value: <iter-
/// independent> }`, and subsequent CompoundAssigns build on top of
/// that reset rather than the prior iter's accumulator.
///
/// Mix's outer-i body is the canonical safe case:
/// ```text
///   lc = 0;                          // RESET (non-self-ref Subst on Ident)
///   for (j) { lc += M[j][i] * in[j]; }  // CompoundAssign in nested for
///   out[i] <== lc;                   // signal substitution (not flagged)
/// ```
/// `lc` has a CompoundAssign in the nested for, but `lc = 0` resets it
/// at the start of every outer iter, so the accumulator doesn't carry
/// across outer iters.
///
/// **Recursion semantics:**
///   - `IfElse` / `Block`: each branch starts with the current
///     `reset_names`. Resets inside a branch are scoped to that branch
///     and do NOT propagate to siblings (conservative — a reset only in
///     the `then` branch leaves `name` unsafe in the `else` branch).
///   - `For` / `While` / `DoWhile`: the nested body inherits the OUTER
///     reset_names. Resets inside the nested body apply only to that
///     body's own iters and do NOT propagate up.
///   - `CompoundAssign` whose target is not a bare `Ident` is rejected
///     uniformly (conservative; no current circuit hits this).
///
/// **Self-referential SubAssignIdent always state-carrying.**
/// `e2 = e2 + e2` is rejected even if `e2` is in `reset_names` from an
/// earlier reset in the same body. This is the conservative call:
/// loosening to "first SubAssignIdent counts as reset, subsequent
/// self-referential ones are safe under SSA shadowing" requires per-
/// stmt SSA tracking that's not worth the complexity for the MVP. No
/// real circuit hits the loosened pattern. If a future widening needs
/// it, the rule is local (this function) and the pattern is `lc = 0;
/// lc = lc + 1; …` — easy to extend.
///
/// **Signal substitutions excluded.** `out[i] <== …` / `out[i] <-- …`
/// target indexed signals (`Expr::Index`), not bare identifiers, and
/// route through `LetIndexed` / `WitnessHintIndexed` whose
/// `index: LoopVar(token)` substitutes uniformly.
///
/// Unit tests pinning the contract:
///   - `is_memoizable_rejects_num2bits_state_carrying_body` — Num2Bits
///     stays rejected (no in-body reset for lc1; e2 self-referential).
///   - `is_memoizable_rejects_inner_j_compoundassign_without_reset` —
///     Mix's inner-j body alone (CompoundAssign, no in-body reset).
///   - `is_memoizable_rejects_mixs_first_loop_compoundassign_without_reset`
///     — MixS's first-pass loop, structurally identical to inner-j.
///   - `is_memoizable_accepts_mix_outer_i_with_in_body_reset` —
///     positive pin for Mix's outer-i body (admit when reset is in
///     the same body).
fn body_has_state_carrying_var_mutation(stmts: &[Stmt]) -> bool {
    let mut reset_names: HashSet<String> = HashSet::new();
    body_has_state_carrying_var_mutation_with_resets(stmts, &mut reset_names)
}

/// Recursive worker. `reset_names` is mutated in place to track names
/// reset by non-self-referential `Substitution { Assign, Ident, … }`
/// stmts seen so far in the current body's stmt sequence. Nested
/// scopes (IfElse branches, Block, For/While/DoWhile bodies) clone
/// `reset_names` so resets inside them don't propagate out.
fn body_has_state_carrying_var_mutation_with_resets(
    stmts: &[Stmt],
    reset_names: &mut HashSet<String>,
) -> bool {
    for stmt in stmts {
        if stmt_carries_state(stmt, reset_names) {
            return true;
        }
        // Track non-self-referential SubAssignIdent as a reset for the
        // remainder of THIS body's stmt sequence.
        if let Stmt::Substitution {
            op: AssignOp::Assign,
            target: Expr::Ident { name, .. },
            value,
            ..
        } = stmt
        {
            if !expr_references_ident(value, name) {
                reset_names.insert(name.clone());
            }
        }
    }
    false
}

fn stmt_carries_state(stmt: &Stmt, reset_names: &HashSet<String>) -> bool {
    match stmt {
        Stmt::CompoundAssign { target, .. } => match target {
            Expr::Ident { name, .. } => !reset_names.contains(name),
            _ => true,
        },
        Stmt::Substitution {
            op: AssignOp::Assign,
            target: Expr::Ident { name, .. },
            value,
            ..
        } => expr_references_ident(value, name),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            let mut then_resets = reset_names.clone();
            if body_has_state_carrying_var_mutation_with_resets(&then_body.stmts, &mut then_resets)
            {
                return true;
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    let mut else_resets = reset_names.clone();
                    body_has_state_carrying_var_mutation_with_resets(&b.stmts, &mut else_resets)
                }
                Some(ElseBranch::IfElse(s)) => stmt_carries_state(s, reset_names),
                None => false,
            }
        }
        Stmt::Block(b) => {
            let mut block_resets = reset_names.clone();
            body_has_state_carrying_var_mutation_with_resets(&b.stmts, &mut block_resets)
        }
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            let mut body_resets = reset_names.clone();
            body_has_state_carrying_var_mutation_with_resets(&body.stmts, &mut body_resets)
        }
        _ => false,
    }
}

// `expr_references_ident` is defined later in this module (originally
// added by `body_has_loop_var_dependent_var_decl`). It walks the AST
// exhaustively for occurrences of an `Expr::Ident { name }`, which is
// exactly the predicate Follow-up D needs to detect self-referential
// `Substitution { Assign, Ident(name), value: <contains Ident(name)> }`
// shapes (Num2Bits's `e2 = e2 + e2`).

/// Walk the body looking for `Expr::Call` patterns that lift to
/// Artik witness bytecode. We don't have a typed marker on the AST for
/// these (the lift happens during lowering, not parsing), so the
/// conservative rule is: any function call whose callee is a
/// recognised function name might lift. Until the lift pass exposes
/// a "this would emit a `WitnessCall`" predicate, refuse to memoize
/// any loop that contains a call whose name matches the witness-lift
/// shape (`__artik_*`), or — more conservatively — any function call
/// that doesn't trivially const-fold. SHA-256's round body has no
/// witness-lifted calls, so this gate is a no-op for the perf target.
///
/// **MVP**: we use the loosest practical check — any explicit
/// `Call`. Tightening (recognise pure compile-time calls and exempt
/// them) is a follow-up if it's needed to widen the memoizable set.
fn body_has_witness_call(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_call)
}

fn stmt_has_call(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution { value, .. } => expr_has_call(value),
        Stmt::CompoundAssign { value, .. } => expr_has_call(value),
        Stmt::ConstraintEq { lhs, rhs, .. } => expr_has_call(lhs) || expr_has_call(rhs),
        Stmt::VarDecl { init, .. } => init.as_ref().is_some_and(expr_has_call),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_call(condition)
                || then_body.stmts.iter().any(stmt_has_call)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_call),
                    Some(ElseBranch::IfElse(s)) => stmt_has_call(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_call),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_call)
        }
        _ => false,
    }
}

fn expr_has_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call { .. } => true,
        Expr::BinOp { lhs, rhs, .. } => expr_has_call(lhs) || expr_has_call(rhs),
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_call(operand),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => expr_has_call(condition) || expr_has_call(if_true) || expr_has_call(if_false),
        Expr::Index { object, index, .. } => expr_has_call(object) || expr_has_call(index),
        Expr::DotAccess { object, .. } => expr_has_call(object),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(expr_has_call)
        }
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args.iter().any(expr_has_call)
                || signal_args.iter().any(|a| expr_has_call(&a.value))
        }
        _ => false,
    }
}

/// `true` iff the body declares a compile-time `var` whose initializer
/// references the loop variable. Replaying such a `var` from a
/// memoized iter-0 footprint would seed every replay iter with iter-0's
/// computed value (Phase 5 caveat).
fn body_has_loop_var_dependent_var_decl(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var))
}

fn stmt_has_loop_var_dependent_var_decl(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::VarDecl { init: Some(v), .. } => expr_references_ident(v, loop_var),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => {
                        stmt_has_loop_var_dependent_var_decl(s, loop_var)
                    }
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_var_decl(s, loop_var)),
        _ => false,
    }
}

/// `true` iff the body contains a nested for/while/do-while whose
/// bound or condition references the outer loop var.
fn body_has_nested_loop_with_loop_var_bound(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
}

fn stmt_has_nested_loop_with_loop_var_bound(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::For {
            condition, body, ..
        } => {
            // Inner-loop bound mentions the outer loop var.
            expr_references_ident(condition, loop_var)
                || body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
        }
        Stmt::While {
            condition, body, ..
        }
        | Stmt::DoWhile {
            condition, body, ..
        } => {
            expr_references_ident(condition, loop_var)
                || body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => {
                        stmt_has_nested_loop_with_loop_var_bound(s, loop_var)
                    }
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_nested_loop_with_loop_var_bound(s, loop_var)),
        _ => false,
    }
}

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
fn memoize_loop<'a>(
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

    // R1″ Phase 6 / Option II: snapshot the parent-scope kav for the
    // post-substitute fold pass. Ark's `known_array_values["C"]` was
    // inserted at sub-template inlining time (`components.rs:212`),
    // i.e. BEFORE entering this for-loop body, so the snapshot is the
    // authoritative source. Late-bound additions during body lowering
    // (none observed under EdDSAPoseidon today, but a documented risk
    // in plan §7) would not be reflected — if a future widening admits
    // bodies that mutate `known_array_values` mid-iteration, swap to
    // referencing the live `env.known_array_values` after the post-
    // capture `*env = pre_env` reset (§5 risk #1).
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
        super::lower_stmt(stmt, env, nodes, ctx, pending)?;
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
    super::super::known_array_fold::fold_known_array_indices(
        &mut nodes[body_start..body_end],
        &kav_snapshot,
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
        super::super::known_array_fold::fold_known_array_indices(&mut iter_nodes, &kav_snapshot);
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
fn try_eval_at_compile_time(stmt: &Stmt, cte: &mut CompileTimeEnv, ctx: &LoweringContext) -> bool {
    let functions: HashMap<&str, &crate::ast::FunctionDef> =
        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();
    super::super::utils::try_eval_stmt_in_place(stmt, cte.as_bigval_map_mut(), &functions).is_some()
}

/// If the most-recently-emitted node was a const-foldable `Let`
/// targeting the same name as the AST `Substitution`, mirror that
/// binding into `env.known_constants` and `cte` so the next
/// iteration's compile-time eval reads the fresh value. Handles the
/// MiMC7 `t = t7[i-1] + c[i]` case.
fn sync_post_emission(
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
    match super::super::const_fold::try_fold_const(value) {
        Some(fc) => {
            env.known_constants.insert(name.clone(), fc);
            cte.insert(name.clone(), BigVal::from_field_const(fc));
        }
        None => {
            env.known_constants.remove(name);
        }
    }
}

/// Resolve a [`LoopBound`] to a concrete `u64` end value. Used by the
/// lowering-time unroll paths where iteration counts must be known
/// before emission. Literal bounds are returned as-is; captures and
/// expressions are looked up in `ctx.all_constants(env)`.
fn resolve_bound_to_u64(
    bound: &LoopBound,
    env: &LoweringEnv,
    ctx: &LoweringContext,
    span: &diagnostics::Span,
) -> Result<u64, LoweringError> {
    match bound {
        LoopBound::Literal(n) => Ok(*n),
        LoopBound::Capture(name) => {
            let all = ctx.all_constants(env);
            all.get(name).and_then(|fc| fc.to_u64()).ok_or_else(|| {
                LoweringError::new(
                    format!(
                        "component array loop bound `{name}` must be resolvable \
                         at compile time"
                    ),
                    span,
                )
            })
        }
        LoopBound::Expr(expr) => {
            let all = ctx.all_constants(env);
            super::super::utils::const_eval_with_params(expr, &all)
                .and_then(|fc| fc.to_u64())
                .ok_or_else(|| {
                    LoweringError::new(
                        "component array loop bound expression must be resolvable \
                         at compile time",
                        span,
                    )
                })
        }
    }
}

/// Emit a `CircuitNode::For` node for the fall-through case (no
/// lowering-time unroll needed). Propagates `pending` so component
/// wirings inside the loop (like `mux.c[0][i] <== c[i]`) update the
/// parent's pending map — we deliberately do NOT flush remaining
/// wirings at the end because that is the parent scope's job.
#[allow(clippy::too_many_arguments)]
fn emit_for_node<'a>(
    var_name: String,
    bound: LoopBound,
    start: u64,
    body: &'a ast::Block,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    let body_nodes = {
        let mut lowered = Vec::new();
        for stmt in &body.stmts {
            super::lower_stmt(stmt, env, &mut lowered, ctx, pending)?;
        }
        lowered
    };

    let range = match bound {
        LoopBound::Literal(end) => ForRange::Literal { start, end },
        LoopBound::Capture(name) => ForRange::WithCapture {
            start,
            end_capture: name,
        },
        LoopBound::Expr(ast_expr) => {
            // Try to resolve the expression to a constant using known param values
            // (e.g., `nb` from `var nb = nbits(n)` where n is known)
            if let Some(end) =
                super::super::utils::const_eval_with_params(&ast_expr, &ctx.param_values)
                    .and_then(|fc| fc.to_u64())
            {
                ForRange::Literal { start, end }
            } else {
                let circuit_expr = lower_expr(&ast_expr, env, ctx)?;
                ForRange::WithExpr {
                    start,
                    end_expr: Box::new(circuit_expr),
                }
            }
        }
    };

    nodes.push(CircuitNode::For {
        var: var_name,
        range,
        body: body_nodes,
        span: Some(SpanRange::from_span(span)),
    });

    Ok(())
}

/// Check if a list of statements only touches variables (no signals, components,
/// or constraint operations). Used to determine if a while loop can be evaluated
/// at compile time.
pub(super) fn stmts_are_var_only(stmts: &[Stmt]) -> bool {
    stmts.iter().all(stmt_is_var_only)
}

fn stmt_is_var_only(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::VarDecl { .. } => true,
        Stmt::CompoundAssign { .. } => true,
        Stmt::Expr { .. } => true,
        Stmt::Substitution {
            op: AssignOp::Assign,
            ..
        } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            stmts_are_var_only(&then_body.stmts)
                && match else_body {
                    Some(ElseBranch::Block(b)) => stmts_are_var_only(&b.stmts),
                    Some(ElseBranch::IfElse(s)) => stmt_is_var_only(s),
                    None => true,
                }
        }
        Stmt::For { body, .. } => stmts_are_var_only(&body.stmts),
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => stmts_are_var_only(&body.stmts),
        Stmt::Block(b) => stmts_are_var_only(&b.stmts),
        Stmt::Return { .. } => true,
        Stmt::Assert { .. } => true,
        Stmt::Log { .. } => true,
        Stmt::Error { .. } => false,
        // Signal ops, component decls, constraint ops → not var-only
        Stmt::SignalDecl { .. } | Stmt::ComponentDecl { .. } | Stmt::ConstraintEq { .. } => false,
        Stmt::Substitution { .. } => false, // <==, <--, ==>, --> ops
    }
}

/// Check if a loop body contains if/else branches with signal operations
/// inside AND var mutations outside those branches.
///
/// This detects the CompConstant pattern:
/// ```circom
/// if ((cmsb==0)&&(clsb==0)) {
///     parts[i] <== -b*smsb*slsb + b*smsb + b*slsb;  // signal op inside if
/// } ...
/// b = b - e;  // var mutation outside if
/// ```
///
/// These loops MUST be unrolled because:
/// 1. The if/else condition depends on compile-time vars → needs constant folding
/// 2. The vars used as coefficients must be concrete constants for valid R1CS
///
/// Does NOT match simple loops like Num2Bits where `lc1 += out[i] * 2**i`
/// is a direct var mutation (no if-branched signal ops).
fn body_mixes_signals_and_vars(stmts: &[Stmt]) -> bool {
    // Pattern: if/else containing signal ops + var mutations at the same level
    let has_branched_signal_ops = stmts.iter().any(|s| match s {
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            let then_has = then_body.stmts.iter().any(stmt_has_signal_ops);
            let else_has = match else_body {
                Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_signal_ops),
                Some(ElseBranch::IfElse(s)) => stmt_has_signal_ops(s),
                None => false,
            };
            then_has || else_has
        }
        _ => false,
    });
    let has_var_mutations = stmts.iter().any(|s| {
        matches!(
            s,
            Stmt::CompoundAssign { .. }
                | Stmt::Substitution {
                    op: AssignOp::Assign,
                    target: Expr::Ident { .. },
                    ..
                }
        )
    });
    has_branched_signal_ops && has_var_mutations
}

fn stmt_has_signal_ops(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution {
            op:
                AssignOp::ConstraintAssign
                | AssignOp::SignalAssign
                | AssignOp::RConstraintAssign
                | AssignOp::RSignalAssign,
            ..
        } => true,
        Stmt::ConstraintEq { .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.stmts.iter().any(stmt_has_signal_ops)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_signal_ops),
                    Some(ElseBranch::IfElse(s)) => stmt_has_signal_ops(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_signal_ops),
        _ => false,
    }
}

/// Evaluate a while or do-while loop at compile time.
///
/// All variables referenced must be in `env.known_constants` or
/// `ctx.param_values`. Results are written back to `env.known_constants`.
pub(super) fn eval_while_compile_time(
    condition: &Expr,
    body_stmts: &[Stmt],
    do_while: bool,
    env: &mut LoweringEnv,
    ctx: &LoweringContext,
    span: &diagnostics::Span,
) -> Result<(), LoweringError> {
    // Build evaluation environment from known constants + param values
    let mut vars: HashMap<String, BigVal> = HashMap::new();
    for (k, v) in &env.known_constants {
        vars.insert(k.clone(), BigVal::from_field_const(*v));
    }
    for (k, v) in &ctx.param_values {
        vars.insert(k.clone(), BigVal::from_field_const(*v));
    }

    let functions: HashMap<&str, &ast::FunctionDef> =
        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();

    const MAX_WHILE_ITERS: usize = 10_000;

    if do_while {
        for _ in 0..MAX_WHILE_ITERS {
            for stmt in body_stmts {
                if super::super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions)
                    .is_none()
                {
                    return Err(LoweringError::with_code(
                        "do-while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        "E209",
                        span,
                    ));
                }
            }
            let cond = super::super::utils::try_eval_expr(condition, &vars, &functions)
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "do-while loop condition could not be evaluated at compile time",
                        "E209",
                        span,
                    )
                })?;
            if cond.is_zero() {
                // Write back computed vars
                for (k, v) in &vars {
                    if !v.is_negative() {
                        env.known_constants.insert(k.clone(), v.to_field_const());
                    }
                }
                return Ok(());
            }
        }
    } else {
        for _ in 0..MAX_WHILE_ITERS {
            let cond = super::super::utils::try_eval_expr(condition, &vars, &functions)
                .ok_or_else(|| {
                    LoweringError::with_code(
                        "while loop condition could not be evaluated at compile time",
                        "E209",
                        span,
                    )
                })?;
            if cond.is_zero() {
                // Write back computed vars
                for (k, v) in &vars {
                    if !v.is_negative() {
                        env.known_constants.insert(k.clone(), v.to_field_const());
                    }
                }
                return Ok(());
            }
            for stmt in body_stmts {
                if super::super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions)
                    .is_none()
                {
                    return Err(LoweringError::with_code(
                        "while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        "E209",
                        span,
                    ));
                }
            }
        }
    }

    Err(LoweringError::with_code(
        format!(
            "while loop did not terminate within {MAX_WHILE_ITERS} iterations \
             during compile-time evaluation"
        ),
        "E209",
        span,
    ))
}

/// A loop bound: literal constant, template parameter, or AST expression.
pub(super) enum LoopBound {
    Literal(u64),
    Capture(String),
    /// Expression bound (e.g., `n + 1`) — the AST Expr, lowered in lower_for_loop.
    Expr(Expr),
}

/// Result of parsing a for-loop condition: the bound plus the
/// iteration direction. Ascending loops match `i < N` / `i <= N`;
/// descending loops match `i != -1` (the canonical circomlib SMT
/// pattern, semantically equivalent to `i >= 0`).
pub(super) struct ParsedLoopCond {
    pub bound: LoopBound,
    pub is_descending: bool,
}

/// Extract the upper bound from a loop condition.
///
/// Ascending: `i < N` or `i <= N`. `N` can be a numeric literal or a
/// template parameter (capture). Returns `bound` as the
/// upper-exclusive end.
///
/// Descending: `i != -1`. Returns `bound = LoopBound::Literal(0)`
/// (lower-inclusive end) and `is_descending = true`. The unroll path
/// iterates the loop variable from `start` down to `0` inclusive.
fn extract_loop_bound(
    condition: &Expr,
    var_name: &str,
    env: &LoweringEnv,
) -> Option<ParsedLoopCond> {
    match condition {
        Expr::BinOp { op, lhs, rhs, .. } => {
            // Check that LHS is the loop variable
            if let Expr::Ident { name, .. } = lhs.as_ref() {
                if name != var_name {
                    return None;
                }
            } else {
                return None;
            }

            // Descending shapes — recognise the canonical circomlib SMT
            // patterns. `bound` here is the lower-inclusive end of the
            // iteration; the unroll runs `(bound..=start).rev()`.
            //
            //   `i != -1` ≡ `i >= 0`   → bound = 0
            //   `i >= 0`               → bound = 0
            //   `i > -1`               → bound = 0
            //   `i > 0`                → bound = 1 (stops one before 0)
            //   `i >= N` (literal N)   → bound = N
            //   `i > N` (literal N)    → bound = N + 1
            let rhs_signed = super::super::utils::const_eval_signed(rhs);
            match (op, rhs_signed) {
                (BinOp::Neq, Some(-1)) | (BinOp::Gt, Some(-1)) | (BinOp::Ge, Some(0)) => {
                    return Some(ParsedLoopCond {
                        bound: LoopBound::Literal(0),
                        is_descending: true,
                    });
                }
                (BinOp::Gt, Some(n)) if n >= 0 => {
                    return Some(ParsedLoopCond {
                        bound: LoopBound::Literal((n as u64) + 1),
                        is_descending: true,
                    });
                }
                (BinOp::Ge, Some(n)) if n > 0 => {
                    return Some(ParsedLoopCond {
                        bound: LoopBound::Literal(n as u64),
                        is_descending: true,
                    });
                }
                _ => {}
            }

            // Try literal constant first (ascending paths only)
            if let Some(bound) = const_eval_u64(rhs) {
                return match op {
                    BinOp::Lt => Some(ParsedLoopCond {
                        bound: LoopBound::Literal(bound),
                        is_descending: false,
                    }),
                    BinOp::Le => Some(ParsedLoopCond {
                        bound: LoopBound::Literal(bound + 1),
                        is_descending: false,
                    }),
                    _ => None,
                };
            }

            // Try template parameter (capture)
            if let Expr::Ident { name, .. } = rhs.as_ref() {
                if env.captures.contains(name) {
                    return match op {
                        BinOp::Lt => Some(ParsedLoopCond {
                            bound: LoopBound::Capture(name.clone()),
                            is_descending: false,
                        }),
                        // i <= capture: not directly representable as WithCapture
                        // (would need capture + 1). For now, only support <.
                        _ => None,
                    };
                }
            }

            // Expression bound (e.g., `i < n + 1`) — defer lowering to caller
            if matches!(op, BinOp::Lt) {
                return Some(ParsedLoopCond {
                    bound: LoopBound::Expr(rhs.as_ref().clone()),
                    is_descending: false,
                });
            }

            None
        }
        _ => None,
    }
}

/// Validate the loop step.
///
/// Returns `false` for ascending steps (`i++`, `i += 1`) and `true`
/// for descending steps (`i--`, `i -= 1`). The caller cross-checks
/// the direction against the condition shape.
fn validate_loop_step(
    step: &Stmt,
    var_name: &str,
    span: &diagnostics::Span,
) -> Result<bool, LoweringError> {
    match step {
        // i++
        Stmt::Expr {
            expr:
                Expr::PostfixOp {
                    op: PostfixOp::Increment,
                    operand,
                    ..
                },
            ..
        } => {
            if let Expr::Ident { name, .. } = operand.as_ref() {
                if name == var_name {
                    return Ok(false);
                }
            }
            Err(LoweringError::new(
                format!("for loop step must increment `{var_name}`"),
                span,
            ))
        }
        // i--
        Stmt::Expr {
            expr:
                Expr::PostfixOp {
                    op: PostfixOp::Decrement,
                    operand,
                    ..
                },
            ..
        } => {
            if let Expr::Ident { name, .. } = operand.as_ref() {
                if name == var_name {
                    return Ok(true);
                }
            }
            Err(LoweringError::new(
                format!("for loop step must decrement `{var_name}`"),
                span,
            ))
        }
        // i += 1 or i -= 1
        Stmt::CompoundAssign {
            target,
            op,
            value,
            ..
        } => {
            if let Expr::Ident { name, .. } = target {
                if name == var_name {
                    if let Some(1) = const_eval_u64(value) {
                        match op {
                            CompoundOp::Add => return Ok(false),
                            CompoundOp::Sub => return Ok(true),
                            _ => {}
                        }
                    }
                }
            }
            Err(LoweringError::new(
                format!(
                    "for loop step must be `{var_name}++`, `{var_name}--`, \
                     `{var_name} += 1`, or `{var_name} -= 1`"
                ),
                span,
            ))
        }
        _ => Err(LoweringError::new(
            "for loop step must be `i++`, `i--`, `i += 1`, or `i -= 1` in circuit context",
            span,
        )),
    }
}

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
pub(super) enum LoopLowering {
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
pub(super) fn classify_loop_body(
    stmts: &[Stmt],
    env: &LoweringEnv,
    loop_var: &str,
) -> Option<LoopLowering> {
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

/// `true` if the body contains a write (`=` or `+=`/`-=`/`*=`/...) to
/// a simple-identifier target whose name is bound in the enclosing
/// scope (`env.locals`) and is not declared inside this body.
///
/// Bug Class A trigger. The instantiator's `LoopUnrollMode::Symbolic`
/// path emits the body exactly once and propagates `var` updates
/// through the env. When the update RHS reads a `SymbolicArrayRead`,
/// arithmetic peephole simplification (`0 + x*1 → x`,
/// `0 + x → x`) can collapse the chain to the SymArrRead's
/// loop-local `result_var`. The env binding for the outer `var` then
/// holds a body-local SsaVar; any post-loop reference resolves to
/// that var outside its `LoopUnroll` scope and the walker rejects it
/// as undefined. Forcing eager unroll for these bodies routes them
/// through the Legacy path that materialises a fresh per-iteration
/// SSA chain in the outer scope, sidestepping the env-leak entirely.
///
/// Detection is local: walk the body once collecting body-local
/// `var` decl names, then scan for assignment/compound-assign
/// statements whose target is a simple identifier in `env.locals`
/// that wasn't declared inside the body. Signals (`<==`, `<--`,
/// `==>`, `-->`) are skipped because they don't propagate through
/// the env binding mechanism.
fn body_writes_to_outer_scope_var(stmts: &[Stmt], env: &LoweringEnv, loop_var: &str) -> bool {
    let mut body_decls: HashSet<String> = HashSet::new();
    for s in stmts {
        collect_var_decls_in_stmt(s, &mut body_decls);
    }
    stmts
        .iter()
        .any(|s| stmt_writes_to_outer_var(s, env, &body_decls, loop_var))
}

fn collect_var_decls_in_stmt(stmt: &Stmt, acc: &mut HashSet<String>) {
    match stmt {
        Stmt::VarDecl { names, .. } => {
            for n in names {
                acc.insert(n.clone());
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            for s in &then_body.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        collect_var_decls_in_stmt(s, acc);
                    }
                }
                Some(ElseBranch::IfElse(s)) => collect_var_decls_in_stmt(s, acc),
                None => {}
            }
        }
        Stmt::Block(b) => {
            for s in &b.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
        }
        Stmt::For { init, body, .. } => {
            collect_var_decls_in_stmt(init, acc);
            for s in &body.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            for s in &body.stmts {
                collect_var_decls_in_stmt(s, acc);
            }
        }
        _ => {}
    }
}

fn stmt_writes_to_outer_var(
    stmt: &Stmt,
    env: &LoweringEnv,
    body_decls: &HashSet<String>,
    loop_var: &str,
) -> bool {
    match stmt {
        Stmt::CompoundAssign { target, .. } => simple_ident_name(target)
            .map(|name| {
                name != loop_var && env.locals.contains(&name) && !body_decls.contains(&name)
            })
            .unwrap_or(false),
        Stmt::Substitution {
            target,
            op: AssignOp::Assign,
            ..
        } => simple_ident_name(target)
            .map(|name| {
                name != loop_var && env.locals.contains(&name) && !body_decls.contains(&name)
            })
            .unwrap_or(false),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var)),
                    Some(ElseBranch::IfElse(s)) => {
                        stmt_writes_to_outer_var(s, env, body_decls, loop_var)
                    }
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_writes_to_outer_var(s, env, body_decls, loop_var)),
        _ => false,
    }
}

fn simple_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// `true` if the body contains a signal/var write whose target is
/// `<comp>.<arr>[<idx>]...` (one or more `Index`-wrappings around a
/// `DotAccess`) where `<comp>` is bound in `env.locals` as a *scalar*
/// component (not in `env.component_arrays`) AND any index in the
/// chain references `loop_var`.
///
/// **Bug Class B trigger.** The instantiator's
/// `LoopUnrollMode::Symbolic` path emits a `SymbolicIndexedEffect`
/// for `comp.arr[i] <== ...` and immediately calls
/// `snapshot_array_slots("comp.arr")`, which fails because no
/// `WitnessArrayDecl` was emitted for sub-component input arrays at
/// component-decl lowering time (`statements/mod.rs::lower_component_decl`
/// only registers the names in `env.locals` / `env.arrays`, not in
/// the IR stream). Forcing eager unroll for these bodies routes the
/// writes through the const-index `LetIndexed` path, which lazily
/// allocates slots via `ensure_array_slot` and works fine.
///
/// Classifier-ordering invariant: this predicate must run AFTER
/// `body_has_component_array_ops` (line 1566) and
/// `body_references_known_arrays` (line 1569). SHA-256's nested
/// sub-component wirings (`sha256compression_0.hin[k] <== ...`)
/// match the syntactic shape post-unroll, but the post-unroll only
/// happens because the outer `for(i)` already eager-unrolled via
/// `ComponentArrayOps`. By the time this predicate could run on
/// SHA-256's inner loop, control has already taken a different
/// branch. Empirically verified by `bug_class_b_discriminate.rs`:
/// SHA-256(64) shows 3 SymIndEff total, all over `paddedIn` (parent-
/// owned), zero over sub-component arrays. Do not reorder this
/// predicate ahead of the higher-priority strategies.
fn body_writes_to_subcomponent_array(stmts: &[Stmt], env: &LoweringEnv, loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_writes_subcomp_array(s, env, loop_var))
}

fn stmt_writes_subcomp_array(stmt: &Stmt, env: &LoweringEnv, loop_var: &str) -> bool {
    match stmt {
        Stmt::Substitution {
            target,
            op:
                AssignOp::ConstraintAssign
                | AssignOp::SignalAssign
                | AssignOp::RConstraintAssign
                | AssignOp::RSignalAssign
                | AssignOp::Assign,
            ..
        } => target_is_subcomp_array_with_loop_idx(target, env, loop_var),
        Stmt::CompoundAssign { target, .. } => {
            target_is_subcomp_array_with_loop_idx(target, env, loop_var)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            target_is_subcomp_array_with_loop_idx(lhs, env, loop_var)
                || target_is_subcomp_array_with_loop_idx(rhs, env, loop_var)
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(|s| stmt_writes_subcomp_array(s, env, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_writes_subcomp_array(s, env, loop_var)),
                    Some(ElseBranch::IfElse(s)) => stmt_writes_subcomp_array(s, env, loop_var),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_writes_subcomp_array(s, env, loop_var)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_writes_subcomp_array(s, env, loop_var)),
        _ => false,
    }
}

/// `true` if `expr` matches `<chain of Index>(DotAccess { Ident(c), f })`
/// where `c` is a scalar component (in `env.locals`, NOT in
/// `env.component_arrays`) and any of the indices along the chain
/// references `loop_var`.
fn target_is_subcomp_array_with_loop_idx(expr: &Expr, env: &LoweringEnv, loop_var: &str) -> bool {
    let mut indices_have_loop_var = false;
    let mut cur = expr;
    loop {
        match cur {
            Expr::Index { object, index, .. } => {
                if expr_references_ident(index, loop_var) {
                    indices_have_loop_var = true;
                }
                cur = object;
            }
            Expr::DotAccess { object, .. } => match object.as_ref() {
                Expr::Ident { name, .. } => {
                    return indices_have_loop_var
                        && env.locals.contains(name)
                        && !env.component_arrays.contains(name);
                }
                _ => return false,
            },
            _ => return false,
        }
    }
}

/// `true` if the body contains any signal-level statement —
/// constraint/signal assignment, constraint-eq, signal-decl init,
/// or component-decl init. Walks into `IfElse`, nested `Block`, and
/// nested loop bodies (those loops get their own classification
/// when lowered, but a signal op *somewhere* in the tree means we
/// cannot leave the current loop rolled for Lysis Symbolic v1).
fn body_has_any_signal_ops(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_any_signal_op)
}

fn stmt_has_any_signal_op(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution {
            op:
                AssignOp::ConstraintAssign
                | AssignOp::SignalAssign
                | AssignOp::RConstraintAssign
                | AssignOp::RSignalAssign,
            ..
        } => true,
        Stmt::ConstraintEq { .. } => true,
        Stmt::SignalDecl {
            init: Some((AssignOp::ConstraintAssign | AssignOp::SignalAssign, _)),
            ..
        } => true,
        Stmt::ComponentDecl { init: Some(_), .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.stmts.iter().any(stmt_has_any_signal_op)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_any_signal_op),
                    Some(ElseBranch::IfElse(s)) => stmt_has_any_signal_op(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_any_signal_op),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_any_signal_op)
        }
        _ => false,
    }
}

/// `true` if the body contains any `arr[idx]` expression — as an
/// assignment target or anywhere inside an expression — whose
/// `idx` references `loop_var`. Covers reads (`in[i]`,
/// `comp.x[i]`), writes (`out[i] <== ...`), and mixed uses
/// (`sum += in[i] * K[i]`).
///
/// Walks into `IfElse`, nested `Block`, `CompoundAssign` and
/// `Substitution` RHS expressions. Does not descend into nested
/// `For` loops — those are classified separately when they are
/// lowered.
fn body_has_loop_var_indexed_assignments(stmts: &[Stmt], loop_var: &str) -> bool {
    stmts
        .iter()
        .any(|s| stmt_has_loop_var_dependent_index(s, loop_var))
}

fn stmt_has_loop_var_dependent_index(stmt: &Stmt, loop_var: &str) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_has_loop_var_indexed(target, loop_var)
                || expr_has_loop_var_indexed(value, loop_var)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_has_loop_var_indexed(target, loop_var)
                || expr_has_loop_var_indexed(value, loop_var)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_has_loop_var_indexed(lhs, loop_var) || expr_has_loop_var_indexed(rhs, loop_var)
        }
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .is_some_and(|v| expr_has_loop_var_indexed(v, loop_var)),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_loop_var_indexed(condition, loop_var)
                || then_body
                    .stmts
                    .iter()
                    .any(|s| stmt_has_loop_var_dependent_index(s, loop_var))
                || match else_body {
                    Some(ElseBranch::Block(b)) => b
                        .stmts
                        .iter()
                        .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
                    Some(ElseBranch::IfElse(s)) => stmt_has_loop_var_dependent_index(s, loop_var),
                    None => false,
                }
        }
        Stmt::Block(b) => b
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
        // Descend into nested `for` / `while` / `do-while` bodies
        // keeping the same target `loop_var`. A nested loop's own
        // iterator is a different name, so references to the outer
        // `loop_var` inside the inner body are exactly what we need
        // to detect (e.g., BinSum's
        // `for (k) { for (j) { lin += in[j][k] * e2 } }`).
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => body
            .stmts
            .iter()
            .any(|s| stmt_has_loop_var_dependent_index(s, loop_var)),
        _ => false,
    }
}

/// `true` if `expr` contains an `Expr::Index { index }` anywhere in
/// its subtree whose `index` references `loop_var`.
fn expr_has_loop_var_indexed(expr: &Expr, loop_var: &str) -> bool {
    match expr {
        Expr::Index { object, index, .. } => {
            expr_references_ident(index, loop_var) || expr_has_loop_var_indexed(object, loop_var)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            expr_has_loop_var_indexed(lhs, loop_var) || expr_has_loop_var_indexed(rhs, loop_var)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_loop_var_indexed(operand, loop_var),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_has_loop_var_indexed(condition, loop_var)
                || expr_has_loop_var_indexed(if_true, loop_var)
                || expr_has_loop_var_indexed(if_false, loop_var)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_has_loop_var_indexed(a, loop_var)),
        Expr::DotAccess { object, .. } => expr_has_loop_var_indexed(object, loop_var),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => elements
            .iter()
            .any(|e| expr_has_loop_var_indexed(e, loop_var)),
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args
                .iter()
                .any(|a| expr_has_loop_var_indexed(a, loop_var))
                || signal_args
                    .iter()
                    .any(|a| expr_has_loop_var_indexed(&a.value, loop_var))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Ident { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
}

fn expr_references_ident(expr: &Expr, name: &str) -> bool {
    match expr {
        Expr::Ident { name: n, .. } => n == name,
        Expr::BinOp { lhs, rhs, .. } => {
            expr_references_ident(lhs, name) || expr_references_ident(rhs, name)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_references_ident(operand, name),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_references_ident(condition, name)
                || expr_references_ident(if_true, name)
                || expr_references_ident(if_false, name)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_references_ident(a, name)),
        Expr::Index { object, index, .. } => {
            expr_references_ident(object, name) || expr_references_ident(index, name)
        }
        Expr::DotAccess { object, .. } => expr_references_ident(object, name),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(|e| expr_references_ident(e, name))
        }
        Expr::AnonComponent {
            template_args,
            signal_args,
            ..
        } => {
            template_args.iter().any(|a| expr_references_ident(a, name))
                || signal_args
                    .iter()
                    .any(|a| expr_references_ident(&a.value, name))
        }
        Expr::Number { .. }
        | Expr::HexNumber { .. }
        | Expr::Underscore { .. }
        | Expr::Error { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::test_helpers::parse_program;
    use super::*;
    use crate::ast::Definition;

    fn extract_template_body(src: &str) -> Vec<Stmt> {
        let prog = parse_program(src);
        for def in prog.definitions {
            if let Definition::Template(t) = def {
                return t.body.stmts;
            }
        }
        panic!("expected a template definition");
    }

    #[test]
    fn classify_num2bits_loop_with_outer_acc_unrolls() {
        // Num2Bits-style loop with an outer-scope accumulator: the
        // body writes both the indexed signal `out[i]` AND mutates
        // the outer-scope `lc1`. The SymbolicIndexedEffect path can't
        // carry the cross-iteration `lc1 += ...` shape, so the
        // classifier escalates to `IndexedAssignmentLoop` (unroll at
        // lowering).
        let stmts = extract_template_body(
            r#"
            template T(n) {
                signal input in;
                signal output out[n];
                var lc1 = 0;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    lc1 += out[i];
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
        let env = env_with_locals(&["lc1", "out"]);
        assert_eq!(
            classify_loop_body(&for_body, &env, "i"),
            Some(LoopLowering::IndexedAssignmentLoop),
        );
    }

    #[test]
    fn classify_noindex_var_only_loop_is_none() {
        // Loop body has no array indexing on the loop var — stays
        // as `CircuitNode::For`. Instantiate time still unrolls per
        // iteration, but nothing needs the loop var as a const at
        // emission time.
        let stmts = extract_template_body(
            r#"
            template T(n) {
                signal output s;
                var sum = 0;
                for (var i = 0; i < n; i++) {
                    sum = sum + 1;
                }
                s <== sum;
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
        let env = LoweringEnv::new();
        assert_eq!(classify_loop_body(&for_body, &env, "i"), None);
    }

    #[test]
    fn classify_mixed_signal_var_wins_over_other_signals() {
        // CompConstant-style: if/else containing signal op + var mutation
        // at same level → MixedSignalVar.
        let stmts = extract_template_body(
            r#"
            template T(n) {
                signal input in[n];
                signal output out[n];
                var b = 1;
                for (var i = 0; i < n; i++) {
                    if (i == 0) {
                        out[i] <== in[i] * b;
                    } else {
                        out[i] <== in[i];
                    }
                    b = b + 1;
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
        let env = LoweringEnv::new();
        assert_eq!(
            classify_loop_body(&for_body, &env, "i"),
            Some(LoopLowering::MixedSignalVar),
        );
    }

    // ──── Class B predicate pre-flight tests ────────────────────────
    //
    // The four tests below pin `body_writes_to_subcomponent_array`'s
    // exact match shape. Run before wiring the predicate into
    // `classify_loop_body` to verify (a) it fires on the four failing
    // wrapper templates' canonical body, (b) it does NOT fire on
    // Pedersen_old's const-index sub-component writes,
    // SHA-256-style component-array writes, or parent-owned signal
    // array writes. A regression here means the classifier may
    // re-route templates that currently pass Lysis.

    fn extract_first_for_body(src: &str) -> (Vec<Stmt>, String) {
        let stmts = extract_template_body(src);
        // Scan until the first `for` and return its body + var name.
        for s in &stmts {
            if let Stmt::For { init, body, .. } = s {
                let var = match init.as_ref() {
                    Stmt::VarDecl { names, .. } if !names.is_empty() => names[0].clone(),
                    Stmt::Substitution { target, .. } => {
                        super::extract_target_name(target).unwrap_or_default()
                    }
                    _ => panic!("can't extract loop var"),
                };
                return (body.stmts.clone(), var);
            }
        }
        panic!("no for loop");
    }

    fn env_with_locals(locals: &[&str]) -> LoweringEnv {
        let mut env = LoweringEnv::new();
        for n in locals {
            env.locals.insert((*n).to_string());
        }
        env
    }

    #[test]
    fn class_b_predicate_fires_on_pedersen_wrapper_shape() {
        // Canonical Pedersen wrapper:
        //   component ped = ...;
        //   for (i) { ped.in[i] <== in[i]; }
        // `ped` is a scalar component (in env.locals, NOT in
        // component_arrays); `in[i]` would be a parent-owned write.
        let (body, var) = extract_first_for_body(
            r#"
            template T(n) {
                signal input in[n];
                for (var i = 0; i < n; i++) {
                    ped.in[i] <== in[i];
                }
            }
            "#,
        );
        let env = env_with_locals(&["ped", "ped.in", "in"]);
        assert!(body_writes_to_subcomponent_array(&body, &env, &var));
    }

    #[test]
    fn class_b_predicate_does_not_fire_on_const_index_subcomp_write() {
        // Pedersen_old's Window4 shape: const-index writes to a
        // sub-component array. Loop var doesn't appear in the index.
        let (body, var) = extract_first_for_body(
            r#"
            template T(n) {
                signal input in[n];
                for (var i = 0; i < 4; i++) {
                    mux.c[0][i] <== in[i];
                }
            }
            "#,
        );
        // Even though `i` is in `mux.c[0][i]`, the predicate's job is
        // to detect *any* index referencing loop_var. This shape DOES
        // contain `i`. So it would fire — except `mux` is a scalar
        // component sub-component-array write that the bug fires on.
        // Distinct from Pedersen_old's actual mux.c[0][k] where `k`
        // is from an outer scope (not the inner loop var). Adjust:
        let env = env_with_locals(&["mux", "in"]);
        // Predicate fires on this shape because i is in env.locals
        // (loop var) and mux is local non-component-array. This
        // matches the failing pattern, so the assertion is "fires".
        assert!(body_writes_to_subcomponent_array(&body, &env, &var));

        // Genuine const-index Pedersen_old shape — index is a literal,
        // not the loop var:
        let (body2, var2) = extract_first_for_body(
            r#"
            template T(n) {
                signal input in[n];
                for (var i = 0; i < 4; i++) {
                    mux.c[0][3] <== in[i];
                }
            }
            "#,
        );
        let env2 = env_with_locals(&["mux", "in"]);
        assert!(!body_writes_to_subcomponent_array(&body2, &env2, &var2));
    }

    #[test]
    fn class_b_predicate_does_not_fire_on_component_array() {
        // SHA-256-style: `sha256compression[i].inp[k]` — the outer
        // component is an array (`component sha256compression[n]`),
        // tracked in env.component_arrays. Predicate must NOT fire.
        let (body, var) = extract_first_for_body(
            r#"
            template T(n) {
                signal input inp[n][512];
                for (var i = 0; i < n; i++) {
                    for (var k = 0; k < 512; k++) {
                        sha256compression[i].inp[k] <== inp[i][k];
                    }
                }
            }
            "#,
        );
        let mut env = env_with_locals(&["sha256compression", "inp"]);
        env.component_arrays.insert("sha256compression".into());
        assert!(!body_writes_to_subcomponent_array(&body, &env, &var));
    }

    #[test]
    fn class_b_predicate_does_not_fire_on_parent_array() {
        // Parent-owned `paddedIn[k] <== 0` — target is `Index(Ident,
        // ...)`, not `Index(DotAccess, ...)`. Predicate must NOT fire.
        let (body, var) = extract_first_for_body(
            r#"
            template T(n) {
                signal paddedIn[512];
                for (var k = 0; k < 512; k++) {
                    paddedIn[k] <-- 0;
                }
            }
            "#,
        );
        let env = env_with_locals(&["paddedIn"]);
        assert!(!body_writes_to_subcomponent_array(&body, &env, &var));
    }

    #[test]
    fn classify_sha256_padding_loop_stays_rolled() {
        // Reproduces SHA-256 padding: `paddedIn[k] <-- 0` in a
        // for-loop whose index depends on the loop var. The body has
        // a single indexed-signal write, no outer-scope mutation —
        // the SymbolicIndexedEffect path can carry it, so the
        // classifier returns `None` (stay rolled as
        // `CircuitNode::For`) and the walker handles per-iteration
        // unfolding at bytecode emission time.
        //
        // Pre-Phase-2.A this returned `IndexedAssignmentLoop` under
        // the deleted Legacy frontend; the SHA-256 hard gate's 6.4 GB
        // OOM regression that the lowering keeps avoiding was driven
        // by exactly that eager-unroll classification.
        let stmts = extract_template_body(
            r#"
            template T(nBits, nBlocks) {
                signal input in[nBits];
                signal paddedIn[nBlocks * 512];
                for (var k = nBits + 1; k < nBlocks * 512 - 64; k++) {
                    paddedIn[k] <-- 0;
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
        let env = env_with_locals(&["paddedIn"]);
        assert_eq!(classify_loop_body(&for_body, &env, "k"), None);
    }

    /// R1″ Phase 6 / Follow-up A — Edit 5.
    ///
    /// Body has a multi-dim signal-array read (`c[i][0]`, `c[i][7]`)
    /// with the loop var in the outer slot. Pre-Edit 4 the
    /// `body_has_multi_dim_index` disqualifier rejected this. With
    /// Edit 4 dropped and Edits 1+2's placeholder-aware
    /// `lower_multi_index` in place, `is_memoizable` must accept it.
    /// A future regression that re-introduces the multi-dim gate (or
    /// loosens any of the placeholder mechanism upstream) trips this
    /// test immediately.
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

    /// R1″ Phase 6 / Follow-up A deferred risk — Add-slot in placeholder index.
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

    /// R1″ Phase 6 / Follow-up A deferred risk — compile-time outer slot
    /// with placeholder in inner slot.
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

    /// R1″ Phase 6 / Option II.
    ///
    /// Pre-Option II the strategy gate at `loops.rs:292-294` rejected
    /// any body whose `classify_loop_body` result was not exactly
    /// `IndexedAssignmentLoop`. After Option II's commit, the gate
    /// accepts `IndexedAssignmentLoop | KnownArrayRefs`. This test
    /// pins the new acceptance contract using an Ark-shaped synthetic
    /// body — `out[i] <== in[i] + C[i+r]` — that classifies as
    /// `KnownArrayRefs` (because of the `C[i+r]` reference into a
    /// compile-time array) and passes all downstream gates (no
    /// component / call / dot-access / state-carrying var mutation).
    /// A future regression that re-tightens the strategy gate or that
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

    /// R1″ Phase 6 / Follow-up D — soundness pin.
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
    ///
    /// If this test starts failing, a loosening regressed the soundness
    /// rule. The downstream catch is the `r1pp_followup_a_*_forgery_*`
    /// adversarial e2e (and `num2bits_forge_*`), but those run far
    /// downstream of this pin and report less specifically.
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

    /// R1″ Phase 6 / Follow-up D — soundness pin.
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

    /// R1″ Phase 6 / Follow-up D — soundness pin.
    ///
    /// MixS's first loop (`for(i) lc += S[(t*2-1)*r+i]*in[i]`) is
    /// structurally identical to inner-j: CompoundAssign without an
    /// in-body reset. The reset (`var lc = 0`) lives at template scope,
    /// outside this loop. MUST stay rejected.
    /// R1″ Phase 6 / Follow-up D — admit pin.
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
}
