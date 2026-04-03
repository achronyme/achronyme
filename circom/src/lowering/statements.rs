//! Statement lowering: Circom statements → ProveIR `CircuitNode` sequences.
//!
//! Key mappings:
//! - `signal <== expr`  → `Let { name, value }` + `AssertEq { lhs: Var(name), rhs: value }`
//! - `signal <-- expr`  → `Let { name, value }` (witness hint only, `===` handled separately)
//! - `lhs === rhs`      → `AssertEq { lhs, rhs }`
//! - `var x = expr`     → `Let { name, value }` (compile-time only, no constraint)
//! - `for (...) { ... }` → `For { var, range, body }`
//! - `if (...) { ... }`  → `If { cond, then_body, else_body }`
//! - `assert(expr)`      → `Assert { expr }`

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir::prove_ir::types::{CircuitBinOp, CircuitExpr, CircuitNode, FieldConst, ForRange};

use crate::ast::{self, AssignOp, ElseBranch, Expr, Stmt};

use super::components::{inline_component_body, register_component_locals};
use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::expressions::lower_expr;
use super::signals::collect_signal_names;
use super::utils::{const_eval_u64, extract_ident_name};

/// A pending component whose input signals haven't all been wired yet.
struct PendingComponent<'a> {
    template: &'a ast::TemplateDef,
    template_args: Vec<CircuitExpr>,
    input_signals: HashSet<String>,
    wired_signals: HashSet<String>,
    /// True if any input was wired via indexed assignment (comp.signal[i]).
    /// Such components can't trigger inline from wiring completion alone —
    /// they need explicit flushing before their outputs are referenced.
    has_indexed_wirings: bool,
}

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
        lower_stmt(stmt, env, &mut nodes, ctx, pending)?;
    }

    // Inline any components that weren't triggered by wiring completion
    // (e.g., components with no input signals, or partial wiring).
    let remaining: Vec<String> = pending.keys().cloned().collect();
    for comp_name in remaining {
        if let Some(comp) = pending.remove(&comp_name) {
            let body = inline_component_body(
                &comp_name,
                comp.template,
                &comp.template_args,
                ctx,
                &comp.template.span,
            )?;
            nodes.extend(body);
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
    // flush pending components whose inputs were wired via indexed
    // assignments. Skip if this statement is itself a wiring of a pending
    // component (to avoid flushing before all array elements are wired).
    if let Stmt::Substitution {
        target, op, value, ..
    } = stmt
    {
        // For reverse operators (==>, -->), the actual assignment target
        // is `value` (RHS), not `target` (LHS). Use the correct one to
        // decide whether this statement is a component wiring.
        let actual_target = match op {
            AssignOp::RConstraintAssign | AssignOp::RSignalAssign => value,
            _ => target,
        };
        let is_pending_wiring = extract_component_wiring_with_env(actual_target, env)
            .map(|(comp, _)| pending.contains_key(&comp))
            .unwrap_or(false);
        if !is_pending_wiring {
            flush_indexed_pending(nodes, ctx, pending)?;
        }
    }

    match stmt {
        // ── Signal declarations ─────────────────────────────────────
        // Signal declarations themselves don't produce CircuitNodes directly;
        // they are handled by the signal layout extraction (signals.rs).
        // However, inline initialization (`signal output c <== expr`) does.
        Stmt::SignalDecl {
            declarations,
            init: Some((op, value)),
            span,
            ..
        } => {
            for decl in declarations {
                let lowered_value = lower_expr(value, env, ctx)?;
                let sr = Some(SpanRange::from_span(span));

                match op {
                    AssignOp::ConstraintAssign => {
                        // `signal c <== expr` → Let + AssertEq
                        nodes.push(CircuitNode::Let {
                            name: decl.name.clone(),
                            value: lowered_value.clone(),
                            span: sr.clone(),
                        });
                        nodes.push(CircuitNode::AssertEq {
                            lhs: CircuitExpr::Var(decl.name.clone()),
                            rhs: lowered_value,
                            message: None,
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
        Stmt::VarDecl { names, init, span } => {
            if let Some(value) = init {
                if names.len() == 1 {
                    // Check for array literal: `var arr = [1, 2, 3]`
                    // → expand into arr_0, arr_1, arr_2 individual let-bindings
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
                        // Register the base name too (for array indexing resolution)
                        env.register_array(names[0].clone(), elements.len());
                    } else {
                        let lowered = lower_expr(value, env, ctx)?;
                        nodes.push(CircuitNode::Let {
                            name: names[0].clone(),
                            value: lowered,
                            span: Some(SpanRange::from_span(span)),
                        });
                        env.locals.insert(names[0].clone());
                    }
                } else {
                    // Tuple var decl: `var (a, b) = expr` — not directly
                    // expressible in ProveIR. For now, error.
                    return Err(LoweringError::new(
                        "tuple variable declarations are not supported in circuit context",
                        span,
                    ));
                }
            } else {
                // Uninitialized var — just register name, will be assigned later.
                for name in names {
                    env.locals.insert(name.clone());
                }
            }
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
            let l = lower_expr(lhs, env, ctx)?;
            let r = lower_expr(rhs, env, ctx)?;
            nodes.push(CircuitNode::AssertEq {
                lhs: l,
                rhs: r,
                message: None,
                span: Some(SpanRange::from_span(span)),
            });
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
        // While loops are not directly supported in ProveIR because they
        // require dynamic termination. Circom while loops should be
        // compile-time deterministic.
        Stmt::While { span, .. } => {
            return Err(LoweringError::new(
                "while loops are not supported in circuit context; \
                 use for loops with known bounds",
                span,
            ));
        }

        // ── Assert ──────────────────────────────────────────────────
        Stmt::Assert { arg, span } => {
            let expr = lower_expr(arg, env, ctx)?;
            nodes.push(CircuitNode::Assert {
                expr,
                message: None,
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
        // log() is a debug-only construct — no circuit semantics.
        Stmt::Log { .. } => {
            // No-op in circuit context.
        }

        // ── Component declarations ──────────────────────────────────
        Stmt::ComponentDecl {
            names, init, span, ..
        } => {
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
                    if let Some((tmpl_name, tmpl_args)) =
                        extract_component_call(init_expr, env, ctx)?
                    {
                        if let Some(template) = ctx.templates.get(tmpl_name.as_str()) {
                            let template = *template;
                            // Register mangled output/intermediate locals
                            register_component_locals(comp_name, template, &tmpl_args, env);

                            // Collect input signal names for wiring tracking
                            let signals = collect_signal_names(&template.body.stmts);
                            let input_signals: HashSet<String> = signals
                                .iter()
                                .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                                .map(|(n, _)| n.clone())
                                .collect();

                            if input_signals.is_empty() {
                                // No inputs to wire — inline immediately
                                let body = inline_component_body(
                                    comp_name, template, &tmpl_args, ctx, span,
                                )?;
                                nodes.extend(body);
                            } else {
                                pending.insert(
                                    comp_name.clone(),
                                    PendingComponent {
                                        template,
                                        template_args: tmpl_args,
                                        input_signals,
                                        wired_signals: HashSet::new(),
                                        has_indexed_wirings: false,
                                    },
                                );
                            }
                        } else {
                            return Err(LoweringError::new(
                                format!("undefined template `{tmpl_name}`"),
                                span,
                            ));
                        }
                    }
                }
            }
        }

        // ── Bare block ──────────────────────────────────────────────
        Stmt::Block(block) => {
            let inner = lower_stmts(&block.stmts, env, ctx)?;
            nodes.extend(inner);
        }

        // ── Bare expression statement ───────────────────────────────
        Stmt::Expr { expr, span } => {
            // Postfix ops (i++) in for-loop steps are handled as compound
            // assignment. Other bare expressions are usually no-ops.
            match expr {
                Expr::PostfixOp {
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

/// Describes the target of a signal assignment.
enum AssignTarget {
    /// Simple identifier: `x`
    Scalar(String),
    /// Indexed array element: `out[i]`
    Indexed { array: String, index: Box<Expr> },
    /// Multi-indexed: `c[i][j]`, `c[i][j][k]`, etc.
    /// Indices are in order: [outer, ..., inner].
    MultiIndexed { array: String, indices: Vec<Expr> },
}

/// Extract a target from either a simple identifier, dot access, or array index.
///
/// - `Ident("x")` → `Scalar("x")`
/// - `DotAccess { object: "c", field: "a" }` → `Scalar("c.a")`
/// - `Index { object: "out", index: i }` → `Indexed { array: "out", index: i }`
fn extract_assign_target(expr: &Expr) -> Option<AssignTarget> {
    extract_assign_target_with_constants(expr, &HashMap::new())
}

/// Extract an assignment target, resolving known constants for component array indices.
fn extract_assign_target_with_constants(
    expr: &Expr,
    known_constants: &HashMap<String, u64>,
) -> Option<AssignTarget> {
    match expr {
        Expr::Ident { name, .. } => Some(AssignTarget::Scalar(name.clone())),
        Expr::DotAccess { object, field, .. } => {
            // Simple: comp.field
            if let Some(obj) = extract_ident_name(object) {
                return Some(AssignTarget::Scalar(format!("{obj}.{field}")));
            }
            // Component array: comp[i].field → comp_{i}.field
            if let Expr::Index {
                object: inner_obj,
                index: inner_idx,
                ..
            } = object.as_ref()
            {
                if let Some(arr_name) = extract_ident_name(inner_obj) {
                    let idx = const_eval_u64(inner_idx).or_else(|| {
                        if let Expr::Ident { name, .. } = inner_idx.as_ref() {
                            known_constants.get(name.as_str()).copied()
                        } else {
                            None
                        }
                    })?;
                    return Some(AssignTarget::Scalar(format!("{arr_name}_{idx}.{field}")));
                }
            }
            None
        }
        Expr::Index { object, index, .. } => {
            // Unwrap nested Index chains: arr[i][j][k] → base + [i, j, k]
            let mut indices: Vec<Expr> = vec![index.as_ref().clone()];
            let mut current = object.as_ref();
            loop {
                match current {
                    Expr::Ident { name, .. } => {
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array: name.clone(),
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed {
                                array: name.clone(),
                                indices,
                            })
                        };
                    }
                    Expr::DotAccess {
                        object: inner,
                        field,
                        ..
                    } => {
                        let obj = extract_ident_name(inner)?;
                        let array = format!("{obj}.{field}");
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array,
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed { array, indices })
                        };
                    }
                    Expr::Index {
                        object: inner_obj,
                        index: inner_idx,
                        ..
                    } => {
                        indices.push(inner_idx.as_ref().clone());
                        current = inner_obj.as_ref();
                    }
                    _ => return None,
                }
            }
        }
        _ => None,
    }
}

/// Extract a simple scalar target name (for backwards compatibility).
fn extract_target_name(expr: &Expr) -> Option<String> {
    match extract_assign_target(expr)? {
        AssignTarget::Scalar(name) => Some(name),
        AssignTarget::Indexed { .. } | AssignTarget::MultiIndexed { .. } => None,
    }
}

/// Check if a substitution target is a component signal wiring.
/// Handles `comp.signal`, `comp.signal[i]`, and `comp[i].signal`.
/// Returns `(component_name, signal_name)` if so.
fn extract_component_wiring_with_env(target: &Expr, env: &LoweringEnv) -> Option<(String, String)> {
    match target {
        // comp.signal <== expr  OR  comp[i].signal <== expr
        Expr::DotAccess { object, field, .. } => {
            // Simple: comp.signal
            if let Some(obj) = extract_ident_name(object) {
                return Some((obj, field.clone()));
            }
            // Component array: comp[i].signal → comp_{i}.signal
            if let Expr::Index {
                object: inner_obj,
                index: inner_idx,
                ..
            } = object.as_ref()
            {
                if let Some(arr_name) = extract_ident_name(inner_obj) {
                    let idx = const_eval_u64(inner_idx).or_else(|| {
                        if let Expr::Ident { name, .. } = inner_idx.as_ref() {
                            env.known_constants.get(name.as_str()).copied()
                        } else {
                            None
                        }
                    });
                    if let Some(idx) = idx {
                        return Some((format!("{arr_name}_{idx}"), field.clone()));
                    }
                }
            }
            None
        }
        // comp.signal[i] <== expr or comp.signal[i][j] <== expr
        // Return the base signal name for tracking purposes.
        Expr::Index { object, .. } => {
            // Single index: comp.signal[i]
            if let Expr::DotAccess {
                object: inner,
                field,
                ..
            } = object.as_ref()
            {
                return extract_ident_name(inner).map(|obj| (obj, field.clone()));
            }
            // Double index: comp.signal[i][j]
            if let Expr::Index {
                object: inner_obj, ..
            } = object.as_ref()
            {
                if let Expr::DotAccess {
                    object: da_obj,
                    field,
                    ..
                } = inner_obj.as_ref()
                {
                    return extract_ident_name(da_obj).map(|obj| (obj, field.clone()));
                }
            }
            None
        }
        _ => None,
    }
}

/// Lower a substitution statement (`target op value`).
///
/// Handles both simple identifiers and dot access targets (component
/// signal wirings like `c.a <== expr`).
#[allow(clippy::too_many_arguments)]
fn lower_substitution<'a>(
    target: &Expr,
    op: AssignOp,
    value: &Expr,
    span: &diagnostics::Span,
    env: &mut LoweringEnv,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    // Desugar reverse operators: `expr ==> target` → `target <== expr`
    //                            `expr --> target` → `target <-- expr`
    let (target, op, value) = match op {
        AssignOp::RConstraintAssign => (value, AssignOp::ConstraintAssign, target),
        AssignOp::RSignalAssign => (value, AssignOp::SignalAssign, target),
        other => (target, other, value),
    };

    let sr = Some(SpanRange::from_span(span));

    match op {
        // `target <== expr` → Let + AssertEq (or LetIndexed + AssertEq for arrays)
        AssignOp::ConstraintAssign => {
            let assign_target = extract_assign_target_with_constants(target, &env.known_constants)
                .ok_or_else(|| {
                    LoweringError::new(
                        "constraint assignment target must be an identifier, \
                     component signal, or array element",
                        span,
                    )
                })?;
            let lowered = lower_expr(value, env, ctx)?;
            match assign_target {
                AssignTarget::Scalar(name) => {
                    nodes.push(CircuitNode::Let {
                        name: name.clone(),
                        value: lowered.clone(),
                        span: sr.clone(),
                    });
                    nodes.push(CircuitNode::AssertEq {
                        lhs: CircuitExpr::Var(name),
                        rhs: lowered,
                        message: None,
                        span: sr,
                    });
                }
                AssignTarget::Indexed { array, index } => {
                    let idx_expr = lower_expr(&index, env, ctx)?;
                    nodes.push(CircuitNode::LetIndexed {
                        array: array.clone(),
                        index: idx_expr.clone(),
                        value: lowered.clone(),
                        span: sr.clone(),
                    });
                    nodes.push(CircuitNode::AssertEq {
                        lhs: CircuitExpr::ArrayIndex {
                            array,
                            index: Box::new(idx_expr),
                        },
                        rhs: lowered,
                        message: None,
                        span: sr,
                    });
                }
                AssignTarget::MultiIndexed { array, indices } => {
                    let idx_expr = linearize_multi_index(&array, &indices, env, ctx)?;
                    nodes.push(CircuitNode::LetIndexed {
                        array: array.clone(),
                        index: idx_expr.clone(),
                        value: lowered.clone(),
                        span: sr.clone(),
                    });
                    nodes.push(CircuitNode::AssertEq {
                        lhs: CircuitExpr::ArrayIndex {
                            array,
                            index: Box::new(idx_expr),
                        },
                        rhs: lowered,
                        message: None,
                        span: sr,
                    });
                }
            }
            maybe_trigger_inline(target, nodes, ctx, pending, span, env)?;
        }

        // `target <-- expr` → WitnessHint or WitnessHintIndexed
        AssignOp::SignalAssign => {
            let assign_target = extract_assign_target_with_constants(target, &env.known_constants)
                .ok_or_else(|| {
                    LoweringError::new(
                        "signal assignment target must be an identifier, \
                     component signal, or array element",
                        span,
                    )
                })?;
            let lowered = lower_expr(value, env, ctx)?;
            match assign_target {
                AssignTarget::Scalar(name) => {
                    nodes.push(CircuitNode::WitnessHint {
                        name,
                        hint: lowered,
                        span: sr,
                    });
                }
                AssignTarget::Indexed { array, index } => {
                    let idx_expr = lower_expr(&index, env, ctx)?;
                    nodes.push(CircuitNode::WitnessHintIndexed {
                        array,
                        index: idx_expr,
                        hint: lowered,
                        span: sr,
                    });
                }
                AssignTarget::MultiIndexed { array, indices } => {
                    let idx_expr = linearize_multi_index(&array, &indices, env, ctx)?;
                    nodes.push(CircuitNode::WitnessHintIndexed {
                        array,
                        index: idx_expr,
                        hint: lowered,
                        span: sr,
                    });
                }
            }
            maybe_trigger_inline(target, nodes, ctx, pending, span, env)?;
        }

        // RConstraintAssign (==>) and RSignalAssign (-->) are desugared
        // to ConstraintAssign (<==) and SignalAssign (<--) above.
        AssignOp::RConstraintAssign | AssignOp::RSignalAssign => {
            unreachable!("reverse operators desugared at function entry")
        }

        // `target = expr` → variable reassignment, component array instantiation, or SSA shadowing
        AssignOp::Assign => {
            // Component array element instantiation: muls[i] = Template()
            if let Expr::Index {
                object: idx_obj,
                index: idx_expr,
                ..
            } = target
            {
                if let Some(arr_name) = extract_ident_name(idx_obj) {
                    if env.component_arrays.contains(&arr_name) {
                        // Resolve index to constant
                        let idx = const_eval_u64(idx_expr)
                            .or_else(|| {
                                if let Expr::Ident { name, .. } = idx_expr.as_ref() {
                                    env.known_constants.get(name.as_str()).copied()
                                } else {
                                    None
                                }
                            })
                            .ok_or_else(|| {
                                LoweringError::new(
                                    "component array index must be a compile-time constant",
                                    span,
                                )
                            })?;

                        let comp_name = format!("{arr_name}_{idx}");
                        env.locals.insert(comp_name.clone());

                        if let Some((tmpl_name, tmpl_args)) =
                            extract_component_call(value, env, ctx)?
                        {
                            if let Some(template) = ctx.templates.get(tmpl_name.as_str()) {
                                let template = *template;
                                register_component_locals(&comp_name, template, &tmpl_args, env);

                                let signals = collect_signal_names(&template.body.stmts);
                                let input_signals: HashSet<String> = signals
                                    .iter()
                                    .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                                    .map(|(n, _)| n.clone())
                                    .collect();

                                if input_signals.is_empty() {
                                    let body = inline_component_body(
                                        &comp_name, template, &tmpl_args, ctx, span,
                                    )?;
                                    nodes.extend(body);
                                } else {
                                    pending.insert(
                                        comp_name,
                                        PendingComponent {
                                            template,
                                            template_args: tmpl_args,
                                            input_signals,
                                            wired_signals: HashSet::new(),
                                            has_indexed_wirings: false,
                                        },
                                    );
                                }
                            }
                        }
                        return Ok(());
                    }
                }
            }

            let name = extract_target_name(target).ok_or_else(|| {
                LoweringError::new(
                    "assignment target must be an identifier in circuit context",
                    span,
                )
            })?;
            let lowered = lower_expr(value, env, ctx)?;
            nodes.push(CircuitNode::Let {
                name,
                value: lowered,
                span: sr,
            });
        }
    }

    Ok(())
}

/// Linearize multi-dimensional array indices using strides.
///
/// For `arr[i][j]` with strides [s0]: linear = i * s0 + j
/// For `arr[i][j][k]` with strides [s0, s1]: linear = i * s0 + j * s1 + k
///
/// Falls back to stride=1 if no stride info is available.
fn linearize_multi_index(
    array_name: &str,
    indices: &[Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext<'_>,
) -> Result<CircuitExpr, LoweringError> {
    let strides = env.strides.get(array_name);
    let n = indices.len();

    // Try full constant evaluation first
    let const_indices: Option<Vec<u64>> = indices.iter().map(const_eval_u64).collect();
    if let Some(vals) = const_indices {
        let mut linear: usize = 0;
        for (dim, &val) in vals.iter().enumerate() {
            let stride = if dim < n - 1 {
                strides.and_then(|s| s.get(dim)).copied().unwrap_or(1)
            } else {
                1
            };
            linear += val as usize * stride;
        }
        if let Some(elem_name) = env.resolve_array_element(array_name, linear) {
            return Ok(CircuitExpr::Var(elem_name));
        }
        return Ok(CircuitExpr::Const(FieldConst::from_u64(linear as u64)));
    }

    // Build symbolic linearized expression
    let mut result: Option<CircuitExpr> = None;
    for (dim, idx_expr) in indices.iter().enumerate() {
        let lowered = lower_expr(idx_expr, env, ctx)?;
        let stride = if dim < n - 1 {
            strides.and_then(|s| s.get(dim)).copied().unwrap_or(1)
        } else {
            1
        };

        let term = if stride == 1 {
            lowered
        } else {
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(lowered),
                rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(stride as u64))),
            }
        };

        result = Some(match result {
            None => term,
            Some(acc) => CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(acc),
                rhs: Box::new(term),
            },
        });
    }

    Ok(result.unwrap())
}

/// Flush pending components whose inputs were wired via indexed
/// assignments (`comp.signal[i]`). These can't trigger eagerly because
/// we don't know when the array is fully wired, so we flush before
/// the next substitution statement (which might reference their outputs).
fn flush_indexed_pending<'a>(
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
) -> Result<(), LoweringError> {
    let to_flush: Vec<String> = pending
        .iter()
        .filter(|(_, c)| c.has_indexed_wirings)
        .map(|(name, _)| name.clone())
        .collect();
    for comp_name in &to_flush {
        if let Some(comp) = pending.remove(comp_name) {
            let body = inline_component_body(
                comp_name,
                comp.template,
                &comp.template_args,
                ctx,
                &comp.template.span,
            )?;
            nodes.extend(body);
        }
    }
    Ok(())
}

/// If this substitution wires a component input, mark it as wired.
/// When all inputs are wired, inline the component body.
///
/// For indexed wirings (`comp.signal[i] <== expr`), the wiring is
/// tracked but the base signal name counts as wired (since the array
/// will be fully wired across multiple indexed assignments).
fn maybe_trigger_inline<'a>(
    target: &Expr,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    span: &diagnostics::Span,
    env: &LoweringEnv,
) -> Result<(), LoweringError> {
    let is_indexed = matches!(target, Expr::Index { .. });
    if let Some((comp_name, signal_name)) = extract_component_wiring_with_env(target, env) {
        if let Some(comp) = pending.get_mut(&comp_name) {
            comp.wired_signals.insert(signal_name);
            if is_indexed {
                comp.has_indexed_wirings = true;
            }
            // Don't trigger inline from the first indexed wiring to an
            // array — wait until the next non-wiring statement forces a
            // flush, or until all non-array inputs are also wired.
            if comp.has_indexed_wirings {
                return Ok(());
            }
            if comp.wired_signals.is_superset(&comp.input_signals) {
                let comp = pending.remove(&comp_name).unwrap();
                let body = inline_component_body(
                    &comp_name,
                    comp.template,
                    &comp.template_args,
                    ctx,
                    span,
                )?;
                nodes.extend(body);
            }
        }
    }
    Ok(())
}

/// Extract a template call from a component initializer expression.
///
/// `Template(arg1, arg2)` → `Some(("Template", [lowered_arg1, lowered_arg2]))`
fn extract_component_call(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<Option<(String, Vec<CircuitExpr>)>, LoweringError> {
    if let Expr::Call { callee, args, span } = expr {
        if let Some(name) = extract_ident_name(callee) {
            let mut lowered_args = Vec::new();
            for arg in args {
                lowered_args.push(lower_expr(arg, env, ctx)?);
            }
            return Ok(Some((name, lowered_args)));
        }
        return Err(LoweringError::new(
            "component template call must use a simple name",
            span,
        ));
    }
    Ok(None)
}

/// Lower a C-style for loop to a ProveIR `For` node.
///
/// Circom for loops must have deterministic bounds for circuit compilation.
/// We try to extract `for (var i = start; i < end; i++)` patterns.
#[allow(clippy::too_many_arguments)]
fn lower_for_loop<'a>(
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
                LoweringError::new("for loop init must be a compile-time constant", span)
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
                LoweringError::new("for loop init must assign to a simple variable", span)
            })?;
            let start = const_eval_u64(value).ok_or_else(|| {
                LoweringError::new("for loop init must be a compile-time constant", span)
            })?;
            (name, start)
        }
        _ => {
            return Err(LoweringError::new(
                "for loop must use `var i = <const>` or `i = <const>` initialization",
                span,
            ));
        }
    };

    // Extract end bound from condition: `i < end` or `i <= end`
    let bound = extract_loop_bound(condition, &var_name, env).ok_or_else(|| {
        LoweringError::new(
            "for loop condition must be `i < <bound>` or `i <= <bound>` \
             where <bound> is a constant or template parameter",
            span,
        )
    })?;

    // Validate step is `i++` or `i += 1`
    validate_loop_step(step, &var_name, span)?;

    // Register loop variable
    env.locals.insert(var_name.clone());

    // Check if body contains component array operations.
    // If so, unroll the loop at lowering time (component inlining needs
    // concrete names like muls_0, muls_1, etc.).
    let has_component_array_ops = body_has_component_array_ops(&body.stmts, env);

    if has_component_array_ops {
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
            LoopBound::Expr(expr) => super::utils::const_eval_with_params(expr, &ctx.param_values)
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
                lower_stmt(stmt, env, nodes, ctx, pending)?;
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
            lower_stmt(stmt, env, &mut lowered, ctx, pending)?;
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
            if let Some(end) = super::utils::const_eval_with_params(&ast_expr, &ctx.param_values) {
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

/// Check if any statement in the body uses a component array operation.
///
/// Detects patterns like `muls[i] = Template()` or `muls[i].a <== expr`
/// where `muls` is a declared component array.
fn body_has_component_array_ops(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    for stmt in stmts {
        if let Stmt::Substitution { target, .. } = stmt {
            // muls[i] = Template() — component array element instantiation
            if let Expr::Index { object, .. } = target {
                if let Some(name) = extract_ident_name(object) {
                    if env.component_arrays.contains(&name) {
                        return true;
                    }
                }
            }
            // muls[i].a <== expr — component array element wiring
            if let Expr::DotAccess { object, .. } = target {
                if let Expr::Index { object: inner, .. } = object.as_ref() {
                    if let Some(name) = extract_ident_name(inner) {
                        if env.component_arrays.contains(&name) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// A loop bound: literal constant, template parameter, or AST expression.
enum LoopBound {
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
                    ast::BinOp::Lt => Some(LoopBound::Literal(bound)),
                    ast::BinOp::Le => Some(LoopBound::Literal(bound + 1)),
                    _ => None,
                };
            }

            // Try template parameter (capture)
            if let Expr::Ident { name, .. } = rhs.as_ref() {
                if env.captures.contains(name) {
                    return match op {
                        ast::BinOp::Lt => Some(LoopBound::Capture(name.clone())),
                        // i <= capture: not directly representable as WithCapture
                        // (would need capture + 1). For now, only support <.
                        _ => None,
                    };
                }
            }

            // Expression bound (e.g., `i < n + 1`) — defer lowering to caller
            if matches!(op, ast::BinOp::Lt) {
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
                    op: ast::PostfixOp::Increment,
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
            op: ast::CompoundOp::Add,
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

/// Convert a compound assignment operator to a CircuitExpr binary op.
fn compound_to_binop(
    op: ast::CompoundOp,
    lhs: &CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    use ir::prove_ir::types::CircuitBinOp;

    let l = Box::new(lhs.clone());
    let r = Box::new(rhs);

    match op {
        ast::CompoundOp::Add => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: l,
            rhs: r,
        }),
        ast::CompoundOp::Sub => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: l,
            rhs: r,
        }),
        ast::CompoundOp::Mul => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: l,
            rhs: r,
        }),
        ast::CompoundOp::Div => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: l,
            rhs: r,
        }),
        ast::CompoundOp::IntDiv => Ok(CircuitExpr::IntDiv {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        ast::CompoundOp::Mod => Ok(CircuitExpr::IntMod {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        ast::CompoundOp::Pow => {
            let exp = match r.as_ref() {
                CircuitExpr::Const(fc) => fc.to_u64().ok_or_else(|| {
                    LoweringError::new("power exponent must be a small constant", span)
                })?,
                _ => {
                    return Err(LoweringError::new(
                        "power exponent must be a compile-time constant",
                        span,
                    ));
                }
            };
            Ok(CircuitExpr::Pow { base: l, exp })
        }
        ast::CompoundOp::ShiftL
        | ast::CompoundOp::ShiftR
        | ast::CompoundOp::BitAnd
        | ast::CompoundOp::BitOr
        | ast::CompoundOp::BitXor => Err(LoweringError::new(
            "bitwise compound assignment is not supported in circuit context",
            span,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;
    use ir::prove_ir::types::FieldConst;

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
        lower_stmts(&template.body.stmts, &mut env, &mut ctx)
    }

    // ── Constraint assignment (<==) ─────────────────────────────────

    #[test]
    fn constraint_assign_produces_let_and_assert_eq() {
        let nodes = lower_template("signal output c; c <== a + b;").unwrap();
        // signal decl doesn't produce nodes, substitution produces Let + AssertEq
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
    }

    #[test]
    fn inline_constraint_assign_signal_decl() {
        let nodes = lower_template("signal output c <== 42;").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
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
    fn assert_produces_assert_node() {
        let nodes = lower_template("assert(a == 1);").unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Assert { .. }));
    }

    // ── Log is no-op ────────────────────────────────────────────────

    #[test]
    fn log_is_noop() {
        let nodes = lower_template("log(a);").unwrap();
        assert!(nodes.is_empty());
    }

    // ── While is error ──────────────────────────────────────────────

    #[test]
    fn while_is_error() {
        let result = lower_template("var i = 0; while (i < 5) { i += 1; }");
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("while loops"));
    }

    // ── Reverse operators ───────────────────────────────────────────

    #[test]
    fn reverse_constraint_assign() {
        let nodes = lower_template("signal output c; a ==> c;").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&nodes[1], CircuitNode::AssertEq { .. }));
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
        // The canonical IsZero: <-- for witness hint, <== for verification, === for final check
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
        // inv <-- 1 → WitnessHint (no constraints)
        // out <== expr → Let + AssertEq
        // a * out === 0 → AssertEq
        assert_eq!(nodes.len(), 4);
        assert!(matches!(&nodes[0], CircuitNode::WitnessHint { name, .. } if name == "inv"));
        assert!(matches!(&nodes[1], CircuitNode::Let { name, .. } if name == "out"));
        assert!(matches!(&nodes[2], CircuitNode::AssertEq { .. }));
        assert!(matches!(&nodes[3], CircuitNode::AssertEq { .. }));
    }
}
