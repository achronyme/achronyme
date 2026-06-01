use super::*;

/// Resolve a [`LoopBound`] to a concrete `u64` end value. Used by the
/// lowering-time unroll paths where iteration counts must be known
/// before emission. Literal bounds are returned as-is; captures and
/// expressions are looked up in `ctx.all_constants(env)`.
pub(super) fn resolve_bound_to_u64(
    bound: &LoopBound,
    env: &LoweringEnv,
    ctx: &LoweringContext,
    span: &diagnostics::Span,
) -> Result<u64, LoweringError> {
    match bound {
        LoopBound::Literal(n) => Ok(*n),
        LoopBound::Capture(name) => ctx
            .resolve_constant(name, env)
            .and_then(|fc| fc.to_u64())
            .ok_or_else(|| {
                LoweringError::new(
                    format!(
                        "component array loop bound `{name}` must be resolvable \
                         at compile time"
                    ),
                    span,
                )
            }),
        LoopBound::Expr(expr) => crate::lowering::utils::const_eval_ctx(expr, ctx, env)
            .and_then(|fc| fc.to_u64())
            .ok_or_else(|| {
                LoweringError::new(
                    "component array loop bound expression must be resolvable \
                     at compile time",
                    span,
                )
            }),
    }
}

/// Emit a `CircuitNode::For` node for the fall-through case (no
/// lowering-time unroll needed). Propagates `pending` so component
/// wirings inside the loop (like `mux.c[0][i] <== c[i]`) update the
/// parent's pending map — we deliberately do NOT flush remaining
/// wirings at the end because that is the parent scope's job.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_for_node<'a>(
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
    // Outer-scope flush hoist: a structural `For` carries its body Vec
    // through instantiate-time unroll, so any demand-driven flush that
    // lands inside the body would be replicated per iteration with
    // colliding `comp.out_*` Inputs. Walk the body for outer-scope
    // pending components that are read but NOT wired in the body, and
    // inline each into the parent `nodes` Vec before the structural
    // For is appended. Components that the body wires (with or without
    // also reading) stay in `pending` so the demand-driven flush can
    // fire mid-body once their inputs are bound — preserving order in
    // shapes that wire and read the same component within one body.
    let body_refs = collect_pending_refs_in_stmts(&body.stmts, pending, env, ctx);
    for comp_name in body_refs {
        flush_specific_component(&comp_name, nodes, ctx, pending, env)?;
    }

    let body_nodes = {
        let mut lowered = Vec::new();
        for stmt in &body.stmts {
            super::super::lower_stmt(stmt, env, &mut lowered, ctx, pending)?;
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
                crate::lowering::utils::const_eval_with_params(&ast_expr, &ctx.param_values)
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
