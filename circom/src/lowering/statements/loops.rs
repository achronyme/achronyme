//! Loop lowering: for loops, while loops, and compile-time loop evaluation.
//!
//! Circom for loops must have deterministic bounds for circuit compilation.
//! While loops are only allowed when they touch variables (not signals/components)
//! and are evaluated entirely at compile time.

use std::collections::HashMap;

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitNode, ForRange};

use crate::ast::{self, AssignOp, BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt};

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::utils::const_eval_u64;
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
            let start = const_eval_u64(init_expr).ok_or_else(|| {
                LoweringError::with_code("for loop init must be a compile-time constant", "E208", span)
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
                LoweringError::with_code("for loop init must assign to a simple variable", "E208", span)
            })?;
            let start = const_eval_u64(value).ok_or_else(|| {
                LoweringError::with_code("for loop init must be a compile-time constant", "E208", span)
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

    // Check if body requires lowering-time unrolling:
    // 1. Component array operations (inlining needs concrete names)
    // 2. Known array references (C[i] needs i resolved at lowering time)
    let has_component_array_ops = body_has_component_array_ops(&body.stmts, env);
    let has_known_array_refs = body_references_known_arrays(&body.stmts, env);

    if has_component_array_ops || has_known_array_refs {
        // Resolve bound to a concrete number
        let end = match &bound {
            LoopBound::Literal(n) => *n,
            LoopBound::Capture(name) => ctx.param_values.get(name).copied().ok_or_else(|| {
                LoweringError::new(
                    format!(
                        "component array loop bound `{name}` must be resolvable \
                         at compile time"
                    ),
                    span,
                )
            })?,
            LoopBound::Expr(expr) => super::super::utils::const_eval_with_params(expr, &ctx.param_values)
                .ok_or_else(|| {
                    LoweringError::new(
                        "component array loop bound expression must be resolvable \
                         at compile time",
                        span,
                    )
                })?,
        };

        // Unroll: for each iteration, set loop var as known constant, lower body
        for i in start..end {
            env.known_constants.insert(var_name.clone(), i);
            for stmt in &body.stmts {
                super::lower_stmt(stmt, env, nodes, ctx, pending)?;
            }
        }
        env.known_constants.remove(&var_name);

        return Ok(());
    }

    // Lower body — propagate pending so component wirings in loops
    // (like `mux.c[0][i] <== c[i]`) update the parent's pending map.
    // Don't flush remaining at end — that's the parent's job.
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
            if let Some(end) = super::super::utils::const_eval_with_params(&ast_expr, &ctx.param_values) {
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
    let mut vars: HashMap<String, i64> = HashMap::new();
    for (k, v) in &env.known_constants {
        vars.insert(k.clone(), *v as i64);
    }
    for (k, v) in &ctx.param_values {
        vars.insert(k.clone(), *v as i64);
    }

    let functions: HashMap<&str, &ast::FunctionDef> =
        ctx.functions.iter().map(|(k, v)| (*k, *v)).collect();

    const MAX_WHILE_ITERS: usize = 10_000;

    if do_while {
        for _ in 0..MAX_WHILE_ITERS {
            for stmt in body_stmts {
                if super::super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions).is_none() {
                    return Err(LoweringError::with_code(
                        "do-while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        "E209",
                        span,
                    ));
                }
            }
            let cond =
                super::super::utils::try_eval_expr_i64(condition, &vars, &functions).ok_or_else(|| {
                    LoweringError::with_code(
                        "do-while loop condition could not be evaluated at compile time",
                        "E209",
                        span,
                    )
                })?;
            if cond == 0 {
                // Write back computed vars
                for (k, v) in &vars {
                    if *v >= 0 {
                        env.known_constants.insert(k.clone(), *v as u64);
                    }
                }
                return Ok(());
            }
        }
    } else {
        for _ in 0..MAX_WHILE_ITERS {
            let cond =
                super::super::utils::try_eval_expr_i64(condition, &vars, &functions).ok_or_else(|| {
                    LoweringError::with_code(
                        "while loop condition could not be evaluated at compile time",
                        "E209",
                        span,
                    )
                })?;
            if cond == 0 {
                // Write back computed vars
                for (k, v) in &vars {
                    if *v >= 0 {
                        env.known_constants.insert(k.clone(), *v as u64);
                    }
                }
                return Ok(());
            }
            for stmt in body_stmts {
                if super::super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions).is_none() {
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
