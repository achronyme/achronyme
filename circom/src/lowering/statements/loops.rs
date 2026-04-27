//! Loop lowering: for loops, while loops, and compile-time loop evaluation.
//!
//! Circom for loops must have deterministic bounds for circuit compilation.
//! While loops are only allowed when they touch variables (not signals/components)
//! and are evaluated entirely at compile time.

use std::collections::HashMap;

use diagnostics::SpanRange;
use ir_forge::types::{CircuitNode, FieldConst, ForRange};

use crate::ast::{self, AssignOp, BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt};

use super::super::compile_time::CompileTimeEnv;
use super::super::context::LoweringContext;
use super::super::env::{Frontend, LoweringEnv};
use super::super::env_footprint::EnvFootprint;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::loop_var_subst::substitute_loop_var;
use super::super::utils::{const_eval_u64, BigVal};
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

    // Extract end bound from condition: `i < end` or `i <= end`
    let bound = extract_loop_bound(condition, &var_name, env).ok_or_else(|| {
        LoweringError::with_code(
            "for loop condition must be `i < <bound>` or `i <= <bound>` \
             where <bound> is a constant or template parameter",
            "E208",
            span,
        )
    })?;

    // Validate step is `i++` or `i += 1`
    validate_loop_step(step, &var_name, span)?;

    // Register loop variable
    env.locals.insert(var_name.clone());

    // Classify the body to decide whether to unroll at lowering time
    // and — if so — which strategy governs the unroll.
    let Some(strategy) = classify_loop_body(&body.stmts, env, &var_name) else {
        return emit_for_node(var_name, bound, start, body, span, env, nodes, ctx, pending);
    };

    let is_mixed = strategy == LoopLowering::MixedSignalVar;
    let end = resolve_bound_to_u64(&bound, env, ctx, span)?;

    // R1″ Phase 6 / Option D: opt-in memoized unroll. Capture iter
    // `start` with the loop variable held as a `LoopVar(token)`
    // placeholder; replay each remaining iter by cloning the captured
    // node slice and `substitute_loop_var`-rewriting the placeholder
    // to the iter value. Saves the dominant `lower_stmt` cost on heavy
    // bodies (SHA-256 round body in particular) without changing any
    // constraint downstream — the substituted slice is structurally
    // identical to what the legacy unroll would have emitted for that
    // iter. Gated on `R1PP_ENABLED=1` so the default behaviour stays
    // byte-for-byte legacy until the validation pass in D4 flips it.
    if r1pp_enabled() {
        if let Some(plan) = is_memoizable(strategy, &body.stmts, &var_name, start, end, env) {
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
    for i in start..end {
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

/// `true` iff `R1PP_ENABLED=1` is set in the process environment.
/// The memoized unroll path is opt-in until D4 validates against the
/// full benchmark + adversarial suite; once green, the default flips.
fn r1pp_enabled() -> bool {
    std::env::var("R1PP_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// A go-ahead from the memoization classifier.
///
/// Carries the LoopVar token to mint for the placeholder. The token is
/// a single 32-bit slot per active capture window; nested memoized
/// loops would need to allocate distinct tokens, but this MVP only
/// memoizes the outermost eligible loop and bails on nested cases via
/// the disqualifier set in [`is_memoizable`].
#[derive(Debug, Clone, Copy)]
struct MemoPlan {
    token: u32,
}

/// Decide whether this for-loop is safe to memoize.
///
/// Returns `Some(plan)` if every iteration's emission is either:
///   1. Independent of the loop var entirely (the substitute pass is a
///      no-op for those nodes), or
///   2. Differs only by names containing `loop_var_placeholder(token)`
///      and `CircuitExpr::LoopVar(token)` leaves that
///      `substitute_loop_var` will rewrite uniformly.
///
/// Disqualifiers — each rejects the loop and falls back to the legacy
/// unroll. Tightening this set is safer than loosening it; once the
/// classifier returns `Some`, the memoization branch trusts it
/// completely.
///
///   - **MixedSignalVar strategy**: the body interleaves compile-time
///     `var` mutations with signal expressions. Footprint replay can't
///     re-execute the var arithmetic.
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
    env: &LoweringEnv,
) -> Option<MemoPlan> {
    // MVP: only memoize the simplest strategy. `KnownArrayRefs` reads
    // compile-time arrays (Poseidon's `C[i+r]`, Mix's `M[j][i]`) whose
    // bindings flow through nested component inlining as substring
    // renames; the env-state mirroring for those bindings under
    // memoization isn't complete. `ComponentArrayOps` instantiates
    // sub-components per iter; pending state machinery isn't fully
    // captured by `EnvFootprint` either. Both are follow-ups.
    if !matches!(strategy, LoopLowering::IndexedAssignmentLoop) {
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
    //   `body_has_multi_dim_index` disqualifier (commit 8bfd2fd4) is
    //   no longer load-bearing FOR BODIES THAT PASS THE OTHER MVP
    //   GATES (component_or_call, dot_access, capture_array, iter <
    //   4). Widening any of those re-exposes the question whether the
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
    if body_reads_capture_array(body, env) {
        return None;
    }
    Some(MemoPlan { token: 0 })
}

/// `true` iff the body indexes into a captured array parameter
/// (e.g. `C[i + r]` where `C` is a `CaptureArrayDef` in the enclosing
/// template's captures). The capture-array binding flows through
/// component inlining via name substring rename (`C` →
/// `verifier.hash.pEx.ark_0.C`); when memoization clones iter-0 nodes
/// referencing the original capture name, the post-inline rename
/// either fails or leaves the array binding in a state instantiate
/// can't resolve as `InstEnvValue::Array`. EdDSAPoseidon → Poseidon
/// → PoseidonEx → Ark trips this, producing
/// `verifier.hash.pEx.ark_0.C is not an array` at instantiate.
/// Until the EnvFootprint mirroring covers `CaptureArrayDef` rebinding
/// across substitution, the safe call is to skip memoization for
/// these bodies.
fn body_reads_capture_array(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    stmts.iter().any(|s| stmt_reads_capture_array(s, env))
}

fn stmt_reads_capture_array(stmt: &Stmt, env: &LoweringEnv) -> bool {
    match stmt {
        Stmt::Substitution { value, .. } => expr_reads_capture_array(value, env),
        Stmt::CompoundAssign { value, .. } => expr_reads_capture_array(value, env),
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_reads_capture_array(lhs, env) || expr_reads_capture_array(rhs, env)
        }
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .is_some_and(|v| expr_reads_capture_array(v, env)),
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_reads_capture_array(condition, env)
                || then_body
                    .stmts
                    .iter()
                    .any(|s| stmt_reads_capture_array(s, env))
                || match else_body {
                    Some(ElseBranch::Block(b)) => {
                        b.stmts.iter().any(|s| stmt_reads_capture_array(s, env))
                    }
                    Some(ElseBranch::IfElse(s)) => stmt_reads_capture_array(s, env),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(|s| stmt_reads_capture_array(s, env)),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(|s| stmt_reads_capture_array(s, env))
        }
        _ => false,
    }
}

fn expr_reads_capture_array(expr: &Expr, env: &LoweringEnv) -> bool {
    match expr {
        Expr::Index { object, index, .. } => {
            // `cap[idx]` shape — the object resolves to a capture name.
            if let Expr::Ident { name, .. } = object.as_ref() {
                if env.captures.contains(name) {
                    return true;
                }
            }
            expr_reads_capture_array(object, env) || expr_reads_capture_array(index, env)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            expr_reads_capture_array(lhs, env) || expr_reads_capture_array(rhs, env)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_reads_capture_array(operand, env),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_reads_capture_array(condition, env)
                || expr_reads_capture_array(if_true, env)
                || expr_reads_capture_array(if_false, env)
        }
        Expr::Call { args, .. } => args.iter().any(|a| expr_reads_capture_array(a, env)),
        Expr::DotAccess { object, .. } => expr_reads_capture_array(object, env),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(|e| expr_reads_capture_array(e, env))
        }
        _ => false,
    }
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

/// `true` iff the body has any `arr[i][j]` (chained `Expr::Index`)
/// shape. R1″ Phase 6 / Follow-up A made `lower_multi_index`
/// placeholder-aware (it skips the const-fold fast path when the loop
/// var appears in any slot and falls through to symbolic linearisation
/// emitting `LoopVar(token)`). With that fix the disqualifier is no
/// longer needed in `is_memoizable`, but the helpers are retained
/// `#[allow(dead_code)]` so a future regression can re-add the gate
/// with a one-line change rather than reconstructing the walker.
#[allow(dead_code)]
fn body_has_multi_dim_index(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_multi_dim_index)
}

#[allow(dead_code)]
fn stmt_has_multi_dim_index(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_has_multi_dim_index(target) || expr_has_multi_dim_index(value)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_has_multi_dim_index(target) || expr_has_multi_dim_index(value)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_has_multi_dim_index(lhs) || expr_has_multi_dim_index(rhs)
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_has_multi_dim_index(condition)
                || then_body.stmts.iter().any(stmt_has_multi_dim_index)
                || match else_body {
                    Some(ElseBranch::Block(b)) => b.stmts.iter().any(stmt_has_multi_dim_index),
                    Some(ElseBranch::IfElse(s)) => stmt_has_multi_dim_index(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_multi_dim_index),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_multi_dim_index)
        }
        _ => false,
    }
}

#[allow(dead_code)]
fn expr_has_multi_dim_index(expr: &Expr) -> bool {
    match expr {
        Expr::Index { object, index, .. } => {
            // Chained Index: `arr[i][j]` shape.
            matches!(object.as_ref(), Expr::Index { .. })
                || expr_has_multi_dim_index(object)
                || expr_has_multi_dim_index(index)
        }
        Expr::BinOp { lhs, rhs, .. } => {
            expr_has_multi_dim_index(lhs) || expr_has_multi_dim_index(rhs)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_has_multi_dim_index(operand),
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_has_multi_dim_index(condition)
                || expr_has_multi_dim_index(if_true)
                || expr_has_multi_dim_index(if_false)
        }
        Expr::Call { args, .. } => args.iter().any(expr_has_multi_dim_index),
        Expr::DotAccess { object, .. } => expr_has_multi_dim_index(object),
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => {
            elements.iter().any(expr_has_multi_dim_index)
        }
        _ => false,
    }
}

/// `true` iff the body contains a compile-time `var` mutation —
/// either a `CompoundAssign` (always state-carrying — `lc1 += out[i]
/// * e2` accumulates across iters) or any plain `Substitution Assign`
/// whose target is a bare `Ident` (var-style assign). The Phase 5
/// footprint replay model captures the iter-`start` snapshot's value
/// of the var; iters that depend on that var via the captured
/// expression would all see iter-`start`'s frozen value. Num2Bits's
/// `e2` doubling sequence is the canonical case. Pedersen's
/// `nBits = (i == ...) ? n - (nSegments-1)*200 : 200;` is the broader
///   case where the value depends directly on the loop var.
///
/// Conservative on purpose: a body with `var x = 5;` (a literal-only
/// assign) is technically safe to memoize, but the rule rejects it
/// uniformly to keep the classifier dead simple. Loosening would need
/// per-stmt analysis of "does this var participate in any
/// loop-var-dependent expression downstream", which is exactly the
/// kind of analysis the brief warned about as expensive to make
/// correct.
///
/// Signal substitutions (`out[i] <== …` / `out[i] <-- …`) are
/// excluded because they target indexed signals (`Expr::Index`), not
/// bare identifiers, and they're handled via `LetIndexed` /
/// `WitnessHintIndexed` whose `index: LoopVar(token)` substitutes
/// uniformly.
fn body_has_state_carrying_var_mutation(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_state_carrying_var_mutation)
}

fn stmt_has_state_carrying_var_mutation(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::CompoundAssign { .. } => true,
        Stmt::Substitution {
            op: AssignOp::Assign,
            target: Expr::Ident { .. },
            ..
        } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body
                .stmts
                .iter()
                .any(stmt_has_state_carrying_var_mutation)
                || match else_body {
                    Some(ElseBranch::Block(b)) => {
                        b.stmts.iter().any(stmt_has_state_carrying_var_mutation)
                    }
                    Some(ElseBranch::IfElse(s)) => stmt_has_state_carrying_var_mutation(s),
                    None => false,
                }
        }
        Stmt::Block(b) => b.stmts.iter().any(stmt_has_state_carrying_var_mutation),
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            body.stmts.iter().any(stmt_has_state_carrying_var_mutation)
        }
        _ => false,
    }
}

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

/// Extract the upper bound from a loop condition like `i < N` or `i <= N`.
///
/// `N` can be a numeric literal or a template parameter (capture).
fn extract_loop_bound(condition: &Expr, var_name: &str, env: &LoweringEnv) -> Option<LoopBound> {
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

            // Try literal constant first
            if let Some(bound) = const_eval_u64(rhs) {
                return match op {
                    BinOp::Lt => Some(LoopBound::Literal(bound)),
                    BinOp::Le => Some(LoopBound::Literal(bound + 1)),
                    _ => None,
                };
            }

            // Try template parameter (capture)
            if let Expr::Ident { name, .. } = rhs.as_ref() {
                if env.captures.contains(name) {
                    return match op {
                        BinOp::Lt => Some(LoopBound::Capture(name.clone())),
                        // i <= capture: not directly representable as WithCapture
                        // (would need capture + 1). For now, only support <.
                        _ => None,
                    };
                }
            }

            // Expression bound (e.g., `i < n + 1`) — defer lowering to caller
            if matches!(op, BinOp::Lt) {
                return Some(LoopBound::Expr(rhs.as_ref().clone()));
            }

            None
        }
        _ => None,
    }
}

/// Validate that the loop step is `i++` or `i += 1`.
fn validate_loop_step(
    step: &Stmt,
    var_name: &str,
    span: &diagnostics::Span,
) -> Result<(), LoweringError> {
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
                    return Ok(());
                }
            }
            Err(LoweringError::new(
                format!("for loop step must increment `{var_name}`"),
                span,
            ))
        }
        // i += 1
        Stmt::CompoundAssign {
            target,
            op: CompoundOp::Add,
            value,
            ..
        } => {
            if let Expr::Ident { name, .. } = target {
                if name == var_name {
                    if let Some(1) = const_eval_u64(value) {
                        return Ok(());
                    }
                }
            }
            Err(LoweringError::new(
                format!("for loop step must be `{var_name}++` or `{var_name} += 1`"),
                span,
            ))
        }
        _ => Err(LoweringError::new(
            "for loop step must be `i++` or `i += 1` in circuit context",
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
    if body_has_loop_var_indexed_assignments(stmts, loop_var) {
        // Gap 1 Stage 5: when targeting Lysis, the
        // `SymbolicIndexedEffect` path (instantiate Stage 2 + walker
        // Stage 3) carries loop-var-indexed signal writes through to
        // bytecode without unrolling at lowering time. Keep the loop
        // rolled and let `lower_for` emit a `CircuitNode::For`. Legacy
        // R1CS compilation continues to unroll.
        if env.frontend == Frontend::Lysis {
            return None;
        }
        return Some(LoopLowering::IndexedAssignmentLoop);
    }
    // Catch-all: any loop whose body emits signal work (constraints,
    // witness hints, component wiring) is not safe for the Lysis
    // Symbolic `LoopUnroll` path today — the walker's per-iteration
    // register file is capped at 255 and heavy bodies overflow, and
    // not every signal op in a loop body has a const-index shape the
    // Symbolic emitter accepts. Phase 1 policy: if signal ops are
    // present, unroll at lowering so downstream only sees
    // `CircuitNode::Let` / assignments with concrete indices. Loops
    // with only compile-time `var` arithmetic (accumulators,
    // counters) remain as `CircuitNode::For` and still go through
    // the Symbolic fast path.
    if body_has_any_signal_ops(stmts) {
        // Gap 1 Stage 5: same gate as the indexed branch above. Lysis
        // wants the rolled `CircuitNode::For`; the walker handles
        // signal-op bodies via `SymbolicIndexedEffect` + per-iter
        // unrolling. Legacy keeps the catch-all unroll.
        if env.frontend == Frontend::Lysis {
            return None;
        }
        return Some(LoopLowering::IndexedAssignmentLoop);
    }
    None
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
    fn classify_num2bits_loop_is_indexed_assignment_loop() {
        // Num2Bits-style loop: `out[i] <-- ...` is an indexed
        // assignment whose target references the loop var `i`. The
        // downstream Lysis Symbolic path cannot resolve `i` at
        // instantiate time, so the loop must be unrolled here.
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
        let env = LoweringEnv::new();
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

    #[test]
    fn classify_sha256_padding_loop_is_indexed_assignment_loop() {
        // Reproduces SHA-256 padding: `paddedIn[k] <-- 0` in a
        // for-loop whose index depends on the loop var.
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
        let env = LoweringEnv::new();
        assert_eq!(
            classify_loop_body(&for_body, &env, "k"),
            Some(LoopLowering::IndexedAssignmentLoop),
        );
    }
}
