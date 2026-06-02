use std::collections::HashMap;

use diagnostics::SpanRange;
use ir_forge::types::CircuitNode;

use crate::ast::{self, ElseBranch, Expr};

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::wiring::PendingComponent;
use super::{lower_stmt, lower_stmts};

/// Lower an if/else statement.
#[allow(clippy::too_many_arguments)]
/// Scope semantics:
///
/// - **Compile-time-known condition**: the taken branch lowers into the
///   parent `nodes` Vec with the parent's `pending` HashMap, exactly as
///   if the branch's statements were inlined at the if-site. No scope
///   boundary — the branch becomes parent flow.
/// - **Runtime condition**: each branch lowers via `lower_stmts` (a
///   fresh `pending` HashMap, drained at exit), then both bodies are
///   wrapped as `CircuitNode::If`. The fresh pending is the scope
///   boundary — components declared inside a branch don't escape, and
///   demand-driven flushes from outer-scope components fire in the
///   parent before the If is emitted (the read site is the *condition
///   expression* in the parent statement, scanned by the demand-driven
///   walker before this function runs).
///
/// The runtime path doesn't replicate at instantiate (an `If` resolves
/// to a single Mux, not a body-N-times unroll), so no flush hoist is
/// needed — unlike `emit_for_node`, where the body Vec is replicated.
pub(super) fn lower_if_else<'a>(
    condition: &Expr,
    then_body: &'a ast::Block,
    else_body: Option<&'a ElseBranch>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Try compile-time branch selection: if the condition resolves
    // to a known constant, only lower the taken branch.
    if let Some(cond_val) = super::super::utils::const_eval_ctx(condition, ctx, env) {
        if !cond_val.is_zero() {
            for stmt in &then_body.stmts {
                lower_stmt(stmt, env, nodes, ctx, pending)?;
            }
        } else {
            match else_body {
                Some(ElseBranch::Block(block)) => {
                    for stmt in &block.stmts {
                        lower_stmt(stmt, env, nodes, ctx, pending)?;
                    }
                }
                Some(ElseBranch::IfElse(if_stmt)) => {
                    lower_stmt(if_stmt, env, nodes, ctx, pending)?;
                }
                None => {}
            }
        }
    } else {
        // Condition not resolvable — lower both branches as CircuitNode::If
        let cond = lower_expr(condition, env, ctx)?;
        let then_nodes = lower_stmts(&then_body.stmts, env, ctx)?;
        let else_nodes = match else_body {
            Some(ElseBranch::Block(block)) => lower_stmts(&block.stmts, env, ctx)?,
            Some(ElseBranch::IfElse(if_stmt)) => {
                let mut sub = Vec::new();
                lower_stmt(if_stmt, env, &mut sub, ctx, pending)?;
                sub
            }
            None => Vec::new(),
        };
        nodes.push(CircuitNode::If {
            cond,
            then_body: then_nodes,
            else_body: else_nodes,
            span: Some(SpanRange::from_span(span)),
        });
    }
    Ok(())
}
