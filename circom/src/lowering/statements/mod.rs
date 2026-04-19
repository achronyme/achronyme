//! Statement lowering: Circom statements → ProveIR `CircuitNode` sequences.
//!
//! Key mappings:
//! - `signal <== expr`  → `Let { name, value }` (constraint is implicit — the R1CS backend
//!   constrains the wire via its definition, no separate `AssertEq` needed)
//! - `signal <-- expr`  → `Let { name, value }` (witness hint only, `===` handled separately)
//! - `lhs === rhs`      → `AssertEq { lhs, rhs }`
//! - `var x = expr`     → `Let { name, value }` (compile-time only, no constraint)
//! - `for (...) { ... }` → `For { var, range, body }`
//! - `if (...) { ... }`  → `If { cond, then_body, else_body }`
//! - `assert(expr)`      → `Assert { expr }`

mod arrays;
mod loops;
mod substitution;
mod targets;
mod wiring;

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitExpr, CircuitNode};

use crate::ast::{self, AssignOp, ElseBranch, Expr, Stmt};

use super::components::{inline_component_body_with_arrays, register_component_locals};
use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::expressions::lower_expr;
use super::signals::collect_signal_names;
use super::utils::extract_ident_name;

use arrays::{expand_eval_value_to_nodes, try_eval_array_init};
use loops::{eval_while_compile_time, lower_for_loop, stmts_are_var_only};
use substitution::{compound_to_binop, extract_component_call, lower_substitution};
use wiring::{collect_value_component_refs, flush_specific_component, PendingComponent};

/// Lower a sequence of Circom statements to ProveIR `CircuitNode`s.
pub fn lower_stmts<'a>(
    stmts: &'a [Stmt],
    env: &mut LoweringEnv,
    ctx: &mut LoweringContext<'a>,
) -> Result<Vec<CircuitNode>, LoweringError> {
    let mut pending: HashMap<String, PendingComponent> = HashMap::new();
    lower_stmts_with_pending(stmts, env, ctx, &mut pending)
}

/// Lower statements with an externally provided pending component map.
///
/// Used by `lower_for_loop` to propagate component wirings from loop body
/// to the parent scope (e.g., `for (...) { mux.c[0][i] <== c[i]; }`).
fn lower_stmts_with_pending<'a>(
    stmts: &'a [Stmt],
    env: &mut LoweringEnv,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<Vec<CircuitNode>, LoweringError> {
    let mut nodes = Vec::new();

    for stmt in stmts {
        // Remember where this statement's lowering will start so that
        // any Artik `WitnessCall` side effects it emits (via
        // `ctx.pending_nodes` during expression lowering) can be
        // spliced in *before* the statement's own node(s). Without
        // this splice, a `var x = witness_fn(sig);` would emit
        // `Let x = __artik_0_out` followed by the WitnessCall that
        // binds `__artik_0_out` — wrong order.
        let stmt_start = nodes.len();
        lower_stmt(stmt, env, &mut nodes, ctx, pending)?;
        if !ctx.pending_nodes.is_empty() {
            let pending_nodes: Vec<_> = ctx.pending_nodes.drain(..).collect();
            nodes.splice(stmt_start..stmt_start, pending_nodes);
        }
    }

    // Inline any components that weren't triggered by wiring completion
    // (e.g., components with no input signals, or partial wiring).
    let remaining: Vec<String> = pending.keys().cloned().collect();
    for comp_name in remaining {
        if let Some(comp) = pending.remove(&comp_name) {
            let span = comp.template_span().clone();
            comp.inline_into(&comp_name, &mut nodes, ctx, env, &span)?;
        }
    }

    Ok(nodes)
}

/// Lower a single Circom statement, appending results to `nodes`.
#[allow(clippy::too_many_arguments)]
fn lower_stmt<'a>(
    stmt: &'a Stmt,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Before processing a substitution that references a component output,
    // ensure the referenced component has been inlined so its output `Let`
    // bindings exist before the `Var` reference.
    //
    // Demand-driven flush: scan the VALUE expression (the side being read)
    // for references to pending components, and flush only those. This
    // avoids the bulk-flush approach we used to run, which could inline
    // components before their inputs were fully wired (e.g.,
    // `doublers[s-1] = Template()` would prematurely inline `segments_1`
    // before its `p` inputs were wired).
    //
    // We must NOT scan the assignment target — that would flush the
    // component we're trying to wire (e.g., scanning `zeropoint.in` in
    // `zeropoint.in <== p[0]` would prematurely flush `zeropoint`).
    if let Stmt::Substitution {
        target, op, value, ..
    } = stmt
    {
        // For reverse operators (==>, -->), the semantic value (read side)
        // is `target` and the semantic target (write side) is `value`.
        let actual_value = match op {
            AssignOp::RConstraintAssign | AssignOp::RSignalAssign => target,
            _ => value,
        };
        let refs = collect_value_component_refs(actual_value, pending, env, ctx);
        for comp_name in refs {
            flush_specific_component(&comp_name, nodes, ctx, pending, env)?;
        }
    }

    match stmt {
        // ── Signal declarations ─────────────────────────────────────
        Stmt::SignalDecl {
            declarations,
            init: Some((op, value)),
            span,
            ..
        } => {
            for decl in declarations {
                let lowered_value = lower_expr(value, env, ctx)?;
                let sr = Some(SpanRange::from_span(span));

                // Track constant signal values for intra-template propagation
                if let Some(fc) = super::const_fold::try_fold_const(&lowered_value) {
                    env.known_constants.insert(decl.name.clone(), fc);
                }

                match op {
                    AssignOp::ConstraintAssign => {
                        // `signal c <== expr` → Let only. The expression's Mul
                        // instructions produce R1CS constraints; no separate
                        // AssertEq needed (see substitution.rs for rationale).
                        nodes.push(CircuitNode::Let {
                            name: decl.name.clone(),
                            value: lowered_value,
                            span: sr,
                        });
                    }
                    AssignOp::SignalAssign => {
                        // `signal c <-- expr` → WitnessHint (zero constraints)
                        nodes.push(CircuitNode::WitnessHint {
                            name: decl.name.clone(),
                            hint: lowered_value,
                            span: sr,
                        });
                    }
                    _ => {
                        return Err(LoweringError::new(
                            "unsupported signal init operator in declaration",
                            span,
                        ));
                    }
                }
                // Register the signal name as a local binding for subsequent expressions
                env.locals.insert(decl.name.clone());
            }
        }

        // Signal declarations without initialization — just register names.
        Stmt::SignalDecl { declarations, .. } => {
            for decl in declarations {
                env.locals.insert(decl.name.clone());
            }
        }

        // ── Variable declarations ───────────────────────────────────
        Stmt::VarDecl {
            names, init, span, ..
        } => {
            lower_var_decl(names, init.as_ref(), span, env, nodes, ctx)?;
        }

        // ── Substitutions (signal assignments) ──────────────────────
        Stmt::Substitution {
            target,
            op,
            value,
            span,
        } => {
            lower_substitution(target, *op, value, span, env, nodes, ctx, pending)?;
        }

        // ── Constraint equality ─────────────────────────────────────
        Stmt::ConstraintEq { lhs, rhs, span } => {
            // Demand-driven flush: the constraint may reference component
            // outputs (e.g., `compConstant.out*enabled === 0`).
            let mut refs = collect_value_component_refs(lhs, pending, env, ctx);
            let rhs_refs = collect_value_component_refs(rhs, pending, env, ctx);
            for r in rhs_refs {
                if !refs.contains(&r) {
                    refs.push(r);
                }
            }
            for comp_name in refs {
                flush_specific_component(&comp_name, nodes, ctx, pending, env)?;
            }
            let l = lower_expr(lhs, env, ctx)?;
            let r = lower_expr(rhs, env, ctx)?;
            // Skip trivially-satisfied constraints where both sides are
            // compile-time constants (e.g., `Const(fc) * Const(k) === Const(m)`).
            // These arise from constant-propagated Montgomery/Edwards operations.
            let l_const = super::const_fold::try_fold_const(&l).is_some();
            let r_const = super::const_fold::try_fold_const(&r).is_some();
            if !(l_const && r_const) {
                nodes.push(CircuitNode::AssertEq {
                    lhs: l,
                    rhs: r,
                    message: None,
                    span: Some(SpanRange::from_span(span)),
                });
            }
        }

        // ── Compound assignment ─────────────────────────────────────
        Stmt::CompoundAssign {
            target,
            op,
            value,
            span,
        } => {
            let name = extract_ident_name(target).ok_or_else(|| {
                LoweringError::new(
                    "compound assignment target must be a simple identifier",
                    span,
                )
            })?;
            let current = CircuitExpr::Var(name.clone());
            let rhs = lower_expr(value, env, ctx)?;
            let bin_op = compound_to_binop(*op, &current, rhs, span)?;

            // In circuit context, variables are SSA-like. We create a new
            // binding with the same name (shadowing).
            nodes.push(CircuitNode::Let {
                name: name.clone(),
                value: bin_op,
                span: Some(SpanRange::from_span(span)),
            });
        }

        // ── If/else ─────────────────────────────────────────────────
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            span,
        } => {
            lower_if_else(
                condition,
                then_body,
                else_body.as_ref(),
                span,
                env,
                nodes,
                ctx,
                pending,
            )?;
        }

        // ── For loop ────────────────────────────────────────────────
        Stmt::For {
            init,
            condition,
            step,
            body,
            span,
        } => {
            lower_for_loop(init, condition, step, body, span, env, nodes, ctx, pending)?;
        }

        // ── While loop ──────────────────────────────────────────────
        Stmt::While {
            condition,
            body,
            span,
        } => {
            if !stmts_are_var_only(&body.stmts) {
                return Err(LoweringError::new(
                    "while loops that touch signals or components are not supported \
                     in circuit context; use for loops with known bounds",
                    span,
                ));
            }
            eval_while_compile_time(condition, &body.stmts, false, env, ctx, span)?;
        }

        Stmt::DoWhile {
            condition,
            body,
            span,
        } => {
            if !stmts_are_var_only(&body.stmts) {
                return Err(LoweringError::new(
                    "do-while loops that touch signals or components are not supported \
                     in circuit context; use for loops with known bounds",
                    span,
                ));
            }
            eval_while_compile_time(condition, &body.stmts, true, env, ctx, span)?;
        }

        // ── Assert ──────────────────────────────────────────────────
        Stmt::Assert { arg, span } => {
            let lowered = lower_expr(arg, env, ctx)?;
            nodes.push(CircuitNode::Assert {
                expr: lowered,
                message: Some("circom assert() failed during witness computation".to_string()),
                span: Some(SpanRange::from_span(span)),
            });
        }

        // ── Return ──────────────────────────────────────────────────
        Stmt::Return { span, .. } => {
            return Err(LoweringError::new(
                "return statements are only valid inside functions, \
                 not in template circuit context",
                span,
            ));
        }

        // ── Log ─────────────────────────────────────────────────────
        Stmt::Log { .. } => {
            // No-op in circuit context.
        }

        // ── Component declarations ──────────────────────────────────
        Stmt::ComponentDecl {
            names, init, span, ..
        } => {
            lower_component_decl(names, init.as_ref(), span, env, nodes, ctx, pending)?;
        }

        // ── Bare block ──────────────────────────────────────────────
        Stmt::Block(block) => {
            let inner = lower_stmts(&block.stmts, env, ctx)?;
            nodes.extend(inner);
        }

        // ── Bare expression statement ───────────────────────────────
        Stmt::Expr { expr, span } => {
            lower_expr_stmt(expr, span, nodes)?;
        }

        // ── Error recovery placeholder ──────────────────────────────
        Stmt::Error { span } => {
            return Err(LoweringError::new(
                "cannot lower error placeholder statement",
                span,
            ));
        }
    }

    Ok(())
}

/// Lower a variable declaration statement.
fn lower_var_decl(
    names: &[String],
    init: Option<&Expr>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'_>,
) -> Result<(), LoweringError> {
    if let Some(value) = init {
        if names.len() == 1 {
            // Skip nested (2D+) array literals already resolved by precompute_all
            // (e.g., `var BASE[10][2] = [[...], ...]` in Pedersen). These can't be
            // lowered via lower_expr (ArrayLit unsupported), but their values resolve
            // from known_array_values at compile time. Flat 1D array literals are
            // expanded to Let nodes below for use in circuit expressions.
            if env.known_array_values.contains_key(&names[0]) {
                if let Expr::ArrayLit { elements, .. } = value {
                    if elements.iter().any(|e| matches!(e, Expr::ArrayLit { .. })) {
                        return Ok(());
                    }
                }
            }

            // Check for array literal: `var arr = [1, 2, 3]`
            if let Expr::ArrayLit { elements, .. } = value {
                let base = &names[0];
                for (i, elem) in elements.iter().enumerate() {
                    let elem_name = format!("{base}_{i}");
                    let lowered = lower_expr(elem, env, ctx)?;
                    nodes.push(CircuitNode::Let {
                        name: elem_name.clone(),
                        value: lowered,
                        span: Some(SpanRange::from_span(span)),
                    });
                    env.locals.insert(elem_name);
                }
                env.register_array(names[0].clone(), elements.len());
            } else if let Some(eval_val) = try_eval_array_init(value, env, ctx) {
                // Function call or expression that evaluates to an array
                // at compile time (e.g. `var C[n] = POSEIDON_C(t)`).
                let base = &names[0];
                expand_eval_value_to_nodes(
                    base,
                    &eval_val,
                    nodes,
                    env,
                    &Some(SpanRange::from_span(span)),
                );
                env.known_array_values.insert(base.clone(), eval_val);
            } else {
                // Try compile-time evaluation for var inits that are pure
                // constant expressions. This is critical for patterns like
                // `var b = (1 << 128) - 1` in CompConstant — without this,
                // the expression becomes a circuit-level ShiftL that fails
                // range checks during R1CS compilation.
                let all = ctx.all_constants(env);
                let lowered =
                    if let Some(fc) = crate::lowering::utils::const_eval_with_params(value, &all) {
                        CircuitExpr::Const(fc)
                    } else {
                        lower_expr(value, env, ctx)?
                    };

                // Array-valued function-call init: when the lift (Artik)
                // returns `LiftedShape::Array`, the call site stages a
                // `LetArray { name: <synth>, elements }` in
                // `ctx.pending_nodes` and returns `Var(<synth>)`. A naive
                // scalar `Let { name: outCalc, value: Var(<synth>) }`
                // would make `outCalc` an alias of the synth *array*
                // binding — which trips a scalar/array type mismatch at
                // instantiate time when the caller reads `outCalc[i]`.
                // Rebind under the destination name as a LetArray so
                // subsequent indexed reads resolve element-wise.
                if let CircuitExpr::Var(source_name) = &lowered {
                    let matching = ctx.pending_nodes.iter().find_map(|node| match node {
                        CircuitNode::LetArray { name, elements, .. } if name == source_name => {
                            Some(elements.clone())
                        }
                        _ => None,
                    });
                    if let Some(elements) = matching {
                        let len = elements.len();
                        nodes.push(CircuitNode::LetArray {
                            name: names[0].clone(),
                            elements,
                            span: Some(SpanRange::from_span(span)),
                        });
                        env.register_array(names[0].clone(), len);
                        env.locals.insert(names[0].clone());
                        return Ok(());
                    }
                }

                nodes.push(CircuitNode::Let {
                    name: names[0].clone(),
                    value: lowered,
                    span: Some(SpanRange::from_span(span)),
                });
                env.locals.insert(names[0].clone());
            }
        } else {
            // Tuple var decl: `var (a, b) = (expr1, expr2)` — element-wise
            if let Expr::Tuple { elements, .. } = value {
                if elements.len() != names.len() {
                    return Err(LoweringError::new(
                        format!(
                            "tuple length mismatch: {} names but {} values",
                            names.len(),
                            elements.len()
                        ),
                        span,
                    ));
                }
                for (name, elem) in names.iter().zip(elements.iter()) {
                    let lowered = lower_expr(elem, env, ctx)?;
                    nodes.push(CircuitNode::Let {
                        name: name.clone(),
                        value: lowered,
                        span: Some(SpanRange::from_span(span)),
                    });
                    env.locals.insert(name.clone());
                }
            } else {
                return Err(LoweringError::new(
                    "tuple variable declaration requires a tuple on the right side",
                    span,
                ));
            }
        }
    } else {
        // Uninitialized var — just register name, will be assigned later.
        for name in names {
            env.locals.insert(name.clone());
        }
    }
    Ok(())
}

/// Lower an if/else statement.
#[allow(clippy::too_many_arguments)]
fn lower_if_else<'a>(
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
    let params = ctx.all_constants(env);
    if let Some(cond_val) = super::utils::const_eval_with_params(condition, &params) {
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

/// Lower a component declaration statement.
#[allow(clippy::too_many_arguments)]
fn lower_component_decl<'a>(
    names: &[ast::ComponentName],
    init: Option<&Expr>,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    for comp_name_decl in names {
        let comp_name = &comp_name_decl.name;

        // Component array: `component muls[n]` — register and skip init
        if !comp_name_decl.dimensions.is_empty() {
            env.component_arrays.insert(comp_name.clone());
            env.locals.insert(comp_name.clone());
            continue;
        }

        env.locals.insert(comp_name.clone());

        // If there's an initializer (`component c = Template(args)`),
        // resolve the template and prepare for signal wiring.
        if let Some(init_expr) = init {
            if let Some(call) = extract_component_call(init_expr, env, ctx)? {
                if let Some(template) = ctx.templates.get(call.template_name.as_str()) {
                    let template = *template;
                    // Register mangled output/intermediate locals
                    register_component_locals(comp_name, template, &call.scalar_args, env);

                    // Collect input signal names for wiring tracking
                    let signals = collect_signal_names(&template.body.stmts);
                    let input_signals: HashSet<String> = signals
                        .iter()
                        .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                        .map(|(n, _)| n.clone())
                        .collect();

                    if input_signals.is_empty() {
                        // No inputs to wire — inline immediately
                        let body = inline_component_body_with_arrays(
                            comp_name,
                            template,
                            &call.scalar_args,
                            &call.array_args,
                            ctx,
                            span,
                        )?;
                        nodes.extend(body);
                    } else {
                        pending.insert(
                            comp_name.clone(),
                            PendingComponent::new(
                                template,
                                call.scalar_args,
                                call.array_args,
                                input_signals,
                            ),
                        );
                    }
                } else {
                    let mut err = LoweringError::with_code(
                        format!("undefined template `{}`", call.template_name),
                        "E202",
                        span,
                    );
                    let tmpl_names: Vec<&str> = ctx.templates.keys().copied().collect();
                    if let Some(similar) = crate::lowering::suggest::find_similar(
                        &call.template_name,
                        tmpl_names.into_iter(),
                    ) {
                        err.add_suggestion(
                            diagnostics::SpanRange::from_span(span),
                            similar,
                            "a similar template exists",
                        );
                    }
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

/// Lower a bare expression statement (i++, i--, etc).
fn lower_expr_stmt(
    expr: &Expr,
    span: &diagnostics::Span,
    nodes: &mut Vec<CircuitNode>,
) -> Result<(), LoweringError> {
    match expr {
        Expr::PostfixOp {
            op: ast::PostfixOp::Increment,
            operand,
            ..
        }
        | Expr::PrefixOp {
            op: ast::PostfixOp::Increment,
            operand,
            ..
        } => {
            let name = extract_ident_name(operand).ok_or_else(|| {
                LoweringError::new("increment target must be an identifier", span)
            })?;
            let inc = CircuitExpr::BinOp {
                op: ir::prove_ir::types::CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var(name.clone())),
                rhs: Box::new(CircuitExpr::Const(ir::prove_ir::types::FieldConst::one())),
            };
            nodes.push(CircuitNode::Let {
                name,
                value: inc,
                span: Some(SpanRange::from_span(span)),
            });
        }
        Expr::PostfixOp {
            op: ast::PostfixOp::Decrement,
            operand,
            ..
        }
        | Expr::PrefixOp {
            op: ast::PostfixOp::Decrement,
            operand,
            ..
        } => {
            let name = extract_ident_name(operand).ok_or_else(|| {
                LoweringError::new("decrement target must be an identifier", span)
            })?;
            let dec = CircuitExpr::BinOp {
                op: ir::prove_ir::types::CircuitBinOp::Sub,
                lhs: Box::new(CircuitExpr::Var(name.clone())),
                rhs: Box::new(CircuitExpr::Const(ir::prove_ir::types::FieldConst::one())),
            };
            nodes.push(CircuitNode::Let {
                name,
                value: dec,
                span: Some(SpanRange::from_span(span)),
            });
        }
        _ => {
            // Other bare expressions are no-ops in circuit context.
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;
    use ir::prove_ir::types::{FieldConst, ForRange};

    /// Parse a template and lower its body statements.
    fn lower_template(src: &str) -> Result<Vec<CircuitNode>, LoweringError> {
        let full = format!("template T() {{ {src} }}");
        let (prog, errors) = parse_circom(&full).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        let template = match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };

        let mut env = LoweringEnv::new();
        // Pre-register common signal names for testing
        env.inputs.insert("in".to_string());
        env.inputs.insert("a".to_string());
        env.inputs.insert("b".to_string());
        let mut ctx = LoweringContext::from_program(&prog);
        // Pre-evaluate compile-time vars (like lower_template does in the real pipeline)
        let known_vars = crate::lowering::utils::precompute_vars(
            &template.body.stmts,
            &ctx.param_values,
            &ctx.functions,
        );
        for (name, val) in known_vars {
            ctx.param_values.insert(name, val);
        }
        lower_stmts(&template.body.stmts, &mut env, &mut ctx)
    }

    // ── Constraint assignment (<==) ─────────────────────────────────

    #[test]
    fn constraint_assign_produces_let() {
        let nodes = lower_template("signal output c; c <== a + b;").unwrap();
        // signal decl doesn't produce nodes, <== produces only a Let (no AssertEq)
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
    }

    #[test]
    fn inline_constraint_assign_signal_decl() {
        let nodes = lower_template("signal output c <== 42;").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
    }

    // ── Signal assignment (<--) ─────────────────────────────────────

    #[test]
    fn signal_assign_produces_witness_hint() {
        let nodes = lower_template("signal inv; inv <-- 1;").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
    }

    // ── Constraint equality (===) ───────────────────────────────────

    #[test]
    fn constraint_eq_produces_assert_eq() {
        let nodes = lower_template("signal x; x <-- 1; a === x;").unwrap();
        // x <-- 1 → WitnessHint, a === x → AssertEq
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::WitnessHint { .. }));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
    }

    // ── Variable declaration ────────────────────────────────────────

    #[test]
    fn var_decl_with_init() {
        let nodes = lower_template("var x = 42;").unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "x");
                assert_eq!(*value, CircuitExpr::Const(FieldConst::from_u64(42)));
            }
            other => panic!("expected Let, got {:?}", other),
        }
    }

    #[test]
    fn var_decl_without_init() {
        // No node produced, just registers the name
        let nodes = lower_template("var x;").unwrap();
        assert!(nodes.is_empty());
    }

    // ── Variable assignment (=) ─────────────────────────────────────

    #[test]
    fn var_reassignment() {
        let nodes = lower_template("var x = 0; x = 1;").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "x"));
        assert!(matches!(&nodes[1], CircuitNode::Let { name, .. } if name == "x"));
    }

    // ── Compound assignment ─────────────────────────────────────────

    #[test]
    fn compound_add_assignment() {
        let nodes = lower_template("var x = 0; x += 1;").unwrap();
        assert_eq!(nodes.len(), 2);
        match &nodes[1] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "x");
                assert!(matches!(
                    value,
                    CircuitExpr::BinOp {
                        op: ir::prove_ir::types::CircuitBinOp::Add,
                        ..
                    }
                ));
            }
            other => panic!("expected Let with BinOp, got {:?}", other),
        }
    }

    // ── If/else ─────────────────────────────────────────────────────

    #[test]
    fn if_else_produces_if_node() {
        let nodes = lower_template("signal x; if (a == 0) { x <-- 1; } else { x <-- 2; }").unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0] {
            CircuitNode::If {
                then_body,
                else_body,
                ..
            } => {
                assert_eq!(then_body.len(), 1);
                assert_eq!(else_body.len(), 1);
            }
            other => panic!("expected If, got {:?}", other),
        }
    }

    #[test]
    fn if_without_else() {
        let nodes = lower_template("signal x; if (a == 0) { x <-- 1; }").unwrap();
        match &nodes[0] {
            CircuitNode::If { else_body, .. } => {
                assert!(else_body.is_empty());
            }
            other => panic!("expected If, got {:?}", other),
        }
    }

    // ── For loop ────────────────────────────────────────────────────

    #[test]
    fn for_loop_with_literal_bounds() {
        let nodes = lower_template("signal x; for (var i = 0; i < 8; i++) { x <-- 1; }").unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0] {
            CircuitNode::For {
                var, range, body, ..
            } => {
                assert_eq!(var, "i");
                assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
                assert_eq!(body.len(), 1);
            }
            other => panic!("expected For, got {:?}", other),
        }
    }

    #[test]
    fn for_loop_le_condition() {
        let nodes = lower_template("signal x; for (var i = 0; i <= 7; i++) { x <-- 1; }").unwrap();
        match &nodes[0] {
            CircuitNode::For { range, .. } => {
                // i <= 7 → end = 8
                assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
            }
            other => panic!("expected For, got {:?}", other),
        }
    }

    // ── Assert ──────────────────────────────────────────────────────

    #[test]
    fn assert_emits_witness_check() {
        let nodes = lower_template("assert(a == 1);").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(nodes[0], CircuitNode::Assert { .. }));
    }

    // ── Log is no-op ────────────────────────────────────────────────

    #[test]
    fn log_is_noop() {
        let nodes = lower_template("log(a);").unwrap();
        assert!(nodes.is_empty());
    }

    // ── Tag value assignment ──────────────────────────────────────

    #[test]
    fn tag_value_assignment_is_noop() {
        let nodes = lower_template("signal input {maxbit} a; a.maxbit = 8;").unwrap();
        assert!(nodes.is_empty());
    }

    // ── While loops ────────────────────────────────────────────────

    #[test]
    fn while_var_only_succeeds() {
        let nodes = lower_template("var i = 0; while (i < 5) { i += 1; }").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "i"));
    }

    #[test]
    fn while_with_signals_is_error() {
        let result =
            lower_template("signal output x; var i = 0; while (i < 5) { x <== i; i += 1; }");
        assert!(result.is_err());
    }

    // ── Reverse operators ───────────────────────────────────────────

    #[test]
    fn reverse_constraint_assign() {
        let nodes = lower_template("signal output c; a ==> c;").unwrap();
        // ==> is reverse <==, produces only a Let (no AssertEq)
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
    }

    #[test]
    fn reverse_signal_assign() {
        let nodes = lower_template("signal inv; a --> inv;").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
    }

    // ── Postfix ops in expression statements ────────────────────────

    #[test]
    fn postfix_increment_stmt() {
        let nodes = lower_template("var i = 0; i++;").unwrap();
        assert_eq!(nodes.len(), 2);
        match &nodes[1] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "i");
                assert!(matches!(
                    value,
                    CircuitExpr::BinOp {
                        op: ir::prove_ir::types::CircuitBinOp::Add,
                        ..
                    }
                ));
            }
            other => panic!("expected Let, got {:?}", other),
        }
    }

    // ── IsZero pattern ──────────────────────────────────────────────

    #[test]
    fn iszero_pattern() {
        let nodes = lower_template(
            r#"
            signal inv;
            signal output out;
            inv <-- 1;
            out <== 0 - a * inv + 1;
            a * out === 0;
            "#,
        )
        .unwrap();
        // inv <-- 1 → WitnessHint, out <== ... → Let (no AssertEq), a * out === 0 → AssertEq
        assert_eq!(nodes.len(), 3);
        assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
        assert!(matches!(&nodes[1], CircuitNode::Let { name, .. } if name == "out"));
        assert!(matches!(&nodes[2], CircuitNode::AssertEq { .. }));
    }
}
