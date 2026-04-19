//! Function call lowering and inlining.
//!
//! Handles builtin calls (`log`, `assert`) and inlines user-defined Circom
//! functions by binding parameters to argument expressions and extracting
//! the return value.

use std::collections::HashMap;

use ir::prove_ir::types::{CircuitExpr, CircuitUnaryOp, FieldConst};

use crate::ast::{self, Expr};

use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::suggest::find_similar;
use super::super::utils::extract_ident_name;
use super::lower_expr;
use super::operators::lower_binop;
use super::DEFAULT_MAX_BITS;

/// Lower a function call expression.
///
/// Builtins (`log`, `assert`) are handled specially. User-defined functions
/// are inlined: the function body is lowered with parameters bound to
/// argument expressions. Only functions with a single `return expr;`
/// statement (after any `var` declarations) are supported for inlining.
pub(super) fn lower_call(
    callee: &Expr,
    args: &[Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let name = extract_ident_name(callee).ok_or_else(|| {
        LoweringError::new(
            "call target must be a simple identifier in circuit context",
            span,
        )
    })?;

    match name.as_str() {
        "log" => Ok(CircuitExpr::Const(FieldConst::zero())),
        "assert" => Err(LoweringError::new(
            "`assert` is a statement, not an expression in circuit context",
            span,
        )),
        _ => inline_function_call(&name, args, env, ctx, span),
    }
}

/// Inline a user-defined Circom function call.
fn inline_function_call(
    name: &str,
    args: &[Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let func = match ctx.functions.get(name) {
        Some(f) => *f,
        None => {
            let mut err = LoweringError::with_code(
                format!("undefined function `{name}` in circuit context"),
                "E201",
                span,
            );
            let fn_names: Vec<&str> = ctx.functions.keys().copied().collect();
            if let Some(similar) = find_similar(name, fn_names.into_iter()) {
                err.add_suggestion(
                    diagnostics::SpanRange::from_span(span),
                    similar,
                    "a similar function exists",
                );
            }
            return Err(err);
        }
    };

    if ctx.inline_depth >= super::super::context::MAX_INLINE_DEPTH {
        return Err(LoweringError::new(
            format!(
                "function inlining depth limit ({}) exceeded — \
                 possible recursion via `{name}`",
                super::super::context::MAX_INLINE_DEPTH,
            ),
            span,
        ));
    }

    if args.len() != func.params.len() {
        return Err(LoweringError::with_code(
            format!(
                "function `{name}` expects {} argument(s), got {}",
                func.params.len(),
                args.len(),
            ),
            "E206",
            span,
        ));
    }

    ctx.inline_depth += 1;

    // Try compile-time evaluation first (handles imperative functions like nbits).
    let eval_params = ctx.all_constants(env);
    if let Some(result) = super::super::utils::try_eval_function_call(
        func,
        args,
        &eval_params,
        &ctx.functions,
        ctx.inline_depth,
    ) {
        ctx.inline_depth -= 1;
        return Ok(CircuitExpr::Const(result));
    }

    // Find the return expression in the function body.
    let body = &func.body.stmts;
    let return_expr = find_return_expr(body).ok_or_else(|| {
        LoweringError::new(
            format!(
                "function `{name}` must end with a `return` statement \
                 for circuit inlining"
            ),
            span,
        )
    })?;

    // Compile-time evaluation failed — the function carries runtime signal
    // arguments. A function body that declares internal state (vars, loops,
    // multi-statement computations) cannot be safely inlined: substituting
    // just the return expression silently drops the internal computation, and
    // identifiers like `out` in `return out;` would fall back to the caller's
    // scope (which is how Gap E manifested in SHA256 — the function's local
    // `var out[256]` shadowed the template's `signal output out[256]`).
    //
    // Circom handles this pattern through witness calculators executed at
    // prove time. Achronyme does not yet implement that subsystem, so surface
    // the gap explicitly instead of producing garbage `Var(name)` references.
    if function_body_has_internal_state(body) {
        // Try the Artik witness-calculator lift first — succeeds on
        // simple var + return bodies over parameters, returns None on
        // anything else (control flow, arrays, nested calls). If it
        // succeeds, emit a WitnessCall node into the caller's
        // statement stream via `ctx.pending_nodes` and hand back a
        // `Var(output_binding)` expression.
        if let Some(lifted) =
            super::super::artik_lift::lift_function_to_artik(name, &func.params, body, ctx, span)
        {
            // Lower each argument expression in the caller's env so
            // the WitnessCall node carries resolved circuit
            // expressions (not the raw AST). This runs under the
            // original `inline_depth` bump, so recursive lifts are
            // guarded just like recursive inlines.
            let mut lowered_args: Vec<CircuitExpr> = Vec::with_capacity(args.len());
            for arg in args {
                let lowered = lower_expr(arg, env, ctx)?;
                lowered_args.push(lowered);
            }
            let output_binding = lifted.outputs[0].clone();
            ctx.pending_nodes
                .push(ir::prove_ir::types::CircuitNode::WitnessCall {
                    output_bindings: lifted.outputs,
                    input_signals: lowered_args,
                    program_bytes: lifted.program_bytes,
                    span: Some(diagnostics::SpanRange::from_span(span)),
                });
            ctx.inline_depth -= 1;
            return Ok(CircuitExpr::Var(output_binding));
        }

        ctx.inline_depth -= 1;
        return Err(LoweringError::with_code(
            format!(
                "function `{name}` cannot be circuit-inlined with runtime \
                 arguments: its body declares internal state (vars, loops, \
                 or multiple statements) that would require a witness \
                 calculator. This pattern is not yet supported — call the \
                 function with compile-time arguments, or move the \
                 computation into a template."
            ),
            "E212",
            span,
        ));
    }

    // Trivial-body path: `function f(x) { return <expr>; }`. Lower the return
    // expression with parameter substitution. No caller-scope leakage is
    // possible because the body has no internal identifiers beyond params.
    let mut param_env = LoweringEnv::new();
    let mut param_map: HashMap<String, CircuitExpr> = HashMap::new();
    for (param, arg) in func.params.iter().zip(args) {
        let lowered_arg = lower_expr(arg, env, ctx)?;
        param_map.insert(param.clone(), lowered_arg);
        param_env.locals.insert(param.clone());
    }

    let result = lower_expr_with_substitution(return_expr, &param_env, ctx, &param_map)?;

    ctx.inline_depth -= 1;
    Ok(result)
}

/// Is the function body "non-trivial" — does it declare internal state
/// (local vars, loops, if/else, multiple statements) beyond a single
/// `return <expr>;`?
///
/// This is the gating predicate for the witness-calculator gap: anything
/// more than a one-liner return cannot be safely inlined when the caller
/// passes runtime arguments, because we do not lower the body's
/// statements — only the return expression — and the body's internal
/// variables would silently collide with the caller's scope.
fn function_body_has_internal_state(stmts: &[crate::ast::Stmt]) -> bool {
    // Trivial form: body is a single `return <expr>;` statement.
    if stmts.len() == 1 && matches!(stmts[0], crate::ast::Stmt::Return { .. }) {
        return false;
    }
    true
}

/// Find the return expression in a function body.
fn find_return_expr(stmts: &[crate::ast::Stmt]) -> Option<&Expr> {
    for stmt in stmts.iter().rev() {
        if let crate::ast::Stmt::Return { value, .. } = stmt {
            return Some(value);
        }
    }
    None
}

/// Lower an expression, substituting parameter names with their values.
pub(super) fn lower_expr_with_substitution(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
    subs: &HashMap<String, CircuitExpr>,
) -> Result<CircuitExpr, LoweringError> {
    match expr {
        Expr::Ident { name, .. } => {
            if let Some(sub) = subs.get(name) {
                return Ok(sub.clone());
            }
            lower_expr(expr, env, ctx)
        }
        Expr::BinOp { op, lhs, rhs, span } => {
            let l = lower_expr_with_substitution(lhs, env, ctx, subs)?;
            let r = lower_expr_with_substitution(rhs, env, ctx, subs)?;
            lower_binop(*op, l, r, span)
        }
        Expr::UnaryOp { op, operand, .. } => {
            let inner = lower_expr_with_substitution(operand, env, ctx, subs)?;
            match op {
                ast::UnaryOp::Neg => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Neg,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::Not => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Not,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::BitNot => Ok(CircuitExpr::BitNot {
                    operand: Box::new(inner),
                    num_bits: DEFAULT_MAX_BITS,
                }),
            }
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let cond = lower_expr_with_substitution(condition, env, ctx, subs)?;
            let t = lower_expr_with_substitution(if_true, env, ctx, subs)?;
            let f = lower_expr_with_substitution(if_false, env, ctx, subs)?;
            Ok(CircuitExpr::Mux {
                cond: Box::new(cond),
                if_true: Box::new(t),
                if_false: Box::new(f),
            })
        }
        // For anything else, fall through to normal lowering
        _ => lower_expr(expr, env, ctx),
    }
}
