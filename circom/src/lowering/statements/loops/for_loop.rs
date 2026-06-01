use super::*;

/// Lower a C-style for loop to a ProveIR `For` node.
///
/// Circom for loops must have deterministic bounds for circuit compilation.
/// We try to extract `for (var i = start; i < end; i++)` patterns.
#[allow(clippy::too_many_arguments)]
pub(in crate::lowering::statements) fn lower_for_loop<'a>(
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
            let start = const_eval_u64(init_expr)
                .or_else(|| crate::lowering::utils::const_eval_ctx(init_expr, ctx, env)?.to_u64())
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
            let start = const_eval_u64(value)
                .or_else(|| crate::lowering::utils::const_eval_ctx(value, ctx, env)?.to_u64())
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
    //
    // Each lowering path has its own scope semantics for sub-component
    // flushing:
    //
    // - **direct unroll** (this fn, after `classify_loop_body` succeeds
    //   below): each iter's body lowers sequentially into the parent
    //   `nodes` Vec. Demand-driven flushes from `lower_stmt` land in
    //   the parent at iter 0 and remove the component from `pending`,
    //   so subsequent iters are no-ops. No replication, no special
    //   handling required.
    //
    // - **memoize** (`memoize_loop` below): iter `start` is captured
    //   as a body slice and replayed for the rest. `flush_tracker`
    //   records flush ranges so the replay can subtract them from the
    //   captured slice, preventing flushed component bodies from
    //   being cloned per replay iter.
    //
    // - **structural For** (`emit_for_node` below): the body is
    //   lowered once into a *local* Vec that becomes `For { body }`,
    //   then replicated by the instantiate-time unroll. Demand-driven
    //   flushes land in that local Vec, so outer-scope component
    //   bodies would be replicated N times. `emit_for_node` hoists
    //   outer-scope reads to the parent `nodes` BEFORE the For node
    //   to break the replication — see its body for the discriminator
    //   that excludes components also wired by the body.
    let Some(strategy) = classify_loop_body(&body.stmts, env, &var_name) else {
        return emit_for_node(var_name, bound, start, body, span, env, nodes, ctx, pending);
    };

    let is_mixed = strategy == LoopLowering::MixedSignalVar;
    let end = resolve_bound_to_u64(&bound, env, ctx, span)?;

    // Memoized unroll. Capture iter `start` with the loop variable
    // held as a `LoopVar(token)` placeholder; replay each remaining
    // iter by cloning the captured node slice and
    // `substitute_loop_var`-rewriting the placeholder to the iter
    // value. Saves the dominant `lower_stmt` cost on heavy bodies
    // (SHA-256 round body in particular) without changing any
    // constraint downstream — the substituted slice is structurally
    // identical to what the direct unroll would have emitted for
    // that iter. Set `R1PP_ENABLED=0` to opt out and exercise the
    // direct unroll path. Memoization assumes an ascending range;
    // descending loops fall through to the direct unroll below.
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
            super::super::lower_stmt(stmt, env, nodes, ctx, pending)?;
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
