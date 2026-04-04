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

use super::components::{
    inline_component_body, inline_component_body_with_arrays, register_component_locals,
};
use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::expressions::lower_expr;
use super::signals::collect_signal_names;
use super::utils::{const_eval_u64, extract_ident_name, EvalValue};

/// A pending component whose input signals haven't all been wired yet.
struct PendingComponent<'a> {
    template: &'a ast::TemplateDef,
    template_args: Vec<CircuitExpr>,
    /// Array template args (param_name → compile-time array value).
    array_args: HashMap<String, EvalValue>,
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
            let body = inline_component_body_with_arrays(
                &comp_name,
                comp.template,
                &comp.template_args,
                &comp.array_args,
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
        let is_pending_wiring = extract_component_wiring_with_env(actual_target, env, ctx)
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
                    } else if let Some(eval_val) = try_eval_array_init(value, env, ctx) {
                        // Function call or expression that evaluates to an array
                        // at compile time (e.g. `var C[n] = POSEIDON_C(t)`).
                        // Expand into individual Const let-bindings.
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
                        let lowered = lower_expr(value, env, ctx)?;
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
            // Try compile-time branch selection: if the condition resolves
            // to a known constant, only lower the taken branch.  This avoids
            // lowering invalid expressions in dead branches (e.g., mix[r-1]
            // when r==0 inside `if (r==0) { ... } else { ... mix[r-1] ... }`).
            let mut params = ctx.param_values.clone();
            for (k, &v) in &env.known_constants {
                params.insert(k.clone(), v);
            }
            if let Some(cond_val) = super::utils::const_eval_with_params(condition, &params) {
                if cond_val != 0 {
                    // Condition is true — only lower then_body
                    for stmt in &then_body.stmts {
                        lower_stmt(stmt, env, nodes, ctx, pending)?;
                    }
                } else {
                    // Condition is false — only lower else_body
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
        // While loops can't produce structural circuit nodes (no static
        // bounds). However, Circom allows them when they only touch vars
        // (not signals/components). In that case we evaluate them at
        // compile time, like function bodies.
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
        // In Circom, assert() is a prover-side runtime check during witness
        // computation — it does NOT generate R1CS constraints. Only `===`
        // produces constraints. We emit an Assert node so the witness
        // evaluator can check it, but the instantiator ignores it.
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
                                    PendingComponent {
                                        template,
                                        template_args: call.scalar_args,
                                        array_args: call.array_args,
                                        input_signals,
                                        wired_signals: HashSet::new(),
                                        has_indexed_wirings: false,
                                    },
                                );
                            }
                        } else {
                            return Err(LoweringError::new(
                                format!("undefined template `{}`", call.template_name),
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
            // Also handles 2D: comp[i][j].field → comp_{i}_{j}.field
            if let Some(comp_name) = resolve_component_array_name(object, known_constants) {
                return Some(AssignTarget::Scalar(format!("{comp_name}.{field}")));
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
                        // comp.signal[j] or comp[i].signal[j]
                        let base = if let Some(obj) = extract_ident_name(inner) {
                            format!("{obj}.{field}")
                        } else if let Some(comp) =
                            resolve_component_array_name(inner, known_constants)
                        {
                            format!("{comp}.{field}")
                        } else {
                            return None;
                        };
                        indices.reverse();
                        return if indices.len() == 1 {
                            Some(AssignTarget::Indexed {
                                array: base,
                                index: Box::new(indices.remove(0)),
                            })
                        } else {
                            Some(AssignTarget::MultiIndexed {
                                array: base,
                                indices,
                            })
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

/// Resolve a component array expression like `comp[i]` or `comp[i][j]` to
/// a mangled component name (`comp_0`, `comp_0_1`).
///
/// Returns `None` if indices cannot be resolved at compile time.
fn resolve_component_array_name(
    expr: &Expr,
    known_constants: &HashMap<String, u64>,
) -> Option<String> {
    match expr {
        Expr::Index { object, index, .. } => {
            let idx = resolve_const_index(index, known_constants)?;
            if let Some(arr_name) = extract_ident_name(object) {
                // 1D: comp[i] → comp_{i}
                Some(format!("{arr_name}_{idx}"))
            } else {
                // Multi-dim: recurse on inner
                let inner = resolve_component_array_name(object, known_constants)?;
                Some(format!("{inner}_{idx}"))
            }
        }
        _ => None,
    }
}

/// Resolve an index expression to a constant u64 using literals + known_constants.
fn resolve_const_index(expr: &Expr, known_constants: &HashMap<String, u64>) -> Option<u64> {
    const_eval_u64(expr).or_else(|| super::utils::const_eval_with_params(expr, known_constants))
}

/// Try to resolve a component array target (1D or multi-dim) to a component name.
///
/// `muls[i]` → `Some("muls_0")`, `sigmaF[r][j]` → `Some("sigmaF_0_1")`
/// Returns `None` if the target isn't a component array access.
fn try_resolve_component_array_target(
    target: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<String> {
    // Combine known_constants + param_values for full resolution
    let mut all_constants = ctx.param_values.clone();
    for (k, &v) in &env.known_constants {
        all_constants.insert(k.clone(), v);
    }
    // Unwrap Index chain to find base name and indices
    let mut indices: Vec<&Expr> = Vec::new();
    let mut current = target;
    loop {
        match current {
            Expr::Index { object, index, .. } => {
                indices.push(index.as_ref());
                current = object.as_ref();
            }
            Expr::Ident { name, .. } => {
                if !env.component_arrays.contains(name) {
                    return None;
                }
                indices.reverse();
                let mut comp_name = name.clone();
                for idx_expr in &indices {
                    let idx = resolve_const_index(idx_expr, &all_constants)?;
                    comp_name = format!("{comp_name}_{idx}");
                }
                return Some(comp_name);
            }
            _ => return None,
        }
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
/// Handles `comp.signal`, `comp.signal[i]`, `comp[i].signal`,
/// and `comp[i][j].signal` (2D component arrays).
/// Returns `(component_name, signal_name)` if so.
fn extract_component_wiring_with_env(
    target: &Expr,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Option<(String, String)> {
    // Build combined constants for index resolution
    let mut all_constants = ctx.param_values.clone();
    for (k, &v) in &env.known_constants {
        all_constants.insert(k.clone(), v);
    }

    match target {
        // comp.signal <== expr  OR  comp[i].signal <== expr  OR  comp[i][j].signal <== expr
        Expr::DotAccess { object, field, .. } => {
            // Simple: comp.signal
            if let Some(obj) = extract_ident_name(object) {
                return Some((obj, field.clone()));
            }
            // Component array (1D or multi-dim): comp[i].signal, comp[i][j].signal
            if let Some(comp_name) = resolve_component_array_name(object, &all_constants) {
                return Some((comp_name, field.clone()));
            }
            None
        }
        // Index patterns: comp.signal[i], comp.signal[i][j], comp[i].signal[j]
        Expr::Index { object, .. } => {
            // Unwrap Index chain to find the DotAccess inside
            let mut cur = object.as_ref();
            loop {
                match cur {
                    Expr::DotAccess {
                        object: da_obj,
                        field,
                        ..
                    } => {
                        if let Some(obj) = extract_ident_name(da_obj) {
                            return Some((obj, field.clone()));
                        }
                        if let Some(comp) = resolve_component_array_name(da_obj, &all_constants) {
                            return Some((comp, field.clone()));
                        }
                        return None;
                    }
                    Expr::Index { object: inner, .. } => {
                        cur = inner.as_ref();
                    }
                    _ => return None,
                }
            }
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
    // Build combined constants map (known_constants + param_values) for target resolution
    let mut all_constants = ctx.param_values.clone();
    for (k, &v) in &env.known_constants {
        all_constants.insert(k.clone(), v);
    }

    // Desugar reverse operators: `expr ==> target` → `target <== expr`
    //                            `expr --> target` → `target <-- expr`
    let (target, op, value) = match op {
        AssignOp::RConstraintAssign => (value, AssignOp::ConstraintAssign, target),
        AssignOp::RSignalAssign => (value, AssignOp::SignalAssign, target),
        other => (target, other, value),
    };

    let sr = Some(SpanRange::from_span(span));

    // ── Tuple destructuring ────────────────────────────────────────
    // (a, b, ...) <== (expr1, expr2, ...)   — element-wise
    // (a, b, ...) <== Template(n)(inputs)   — anonymous component multi-output
    // (a, b, ...) = (expr1, expr2, ...)     — variable-level element-wise
    if let Expr::Tuple {
        elements: targets, ..
    } = target
    {
        // RHS must be a tuple with same arity, or an anonymous component
        if let Expr::Tuple {
            elements: values, ..
        } = value
        {
            if values.len() != targets.len() {
                return Err(LoweringError::new(
                    format!(
                        "tuple length mismatch: {} targets but {} values",
                        targets.len(),
                        values.len()
                    ),
                    span,
                ));
            }
            for (t, v) in targets.iter().zip(values.iter()) {
                // Skip underscore targets
                if matches!(t, Expr::Underscore { .. }) {
                    continue;
                }
                lower_substitution(t, op, v, span, env, nodes, ctx, pending)?;
            }
            return Ok(());
        }

        // RHS is an anonymous component — inline it, then wire its outputs
        // to the tuple targets in declaration order.
        if let Expr::AnonComponent {
            callee,
            template_args,
            signal_args,
            ..
        } = value
        {
            let tmpl_name = match callee.as_ref() {
                Expr::Ident { name, .. } => name.clone(),
                _ => {
                    return Err(LoweringError::new(
                        "anonymous component callee must be an identifier",
                        span,
                    ))
                }
            };
            let template = *ctx.templates.get(tmpl_name.as_str()).ok_or_else(|| {
                LoweringError::new(format!("template `{tmpl_name}` not found"), span)
            })?;

            // Lower template arguments
            let lowered_args: Vec<CircuitExpr> = template_args
                .iter()
                .map(|a| lower_expr(a, env, ctx))
                .collect::<Result<_, _>>()?;

            // Generate a unique internal name for the anonymous component
            let anon_name = format!("_anon_{}", ctx.next_anon_id());

            // Register component locals (output/intermediate signals)
            register_component_locals(&anon_name, template, &lowered_args, env);

            // Collect output signal names in declaration order
            let signals = collect_signal_names(&template.body.stmts);
            let output_names: Vec<String> = signals
                .iter()
                .filter(|(_, st)| matches!(st, ast::SignalType::Output))
                .map(|(n, _)| n.clone())
                .collect();

            let input_names: Vec<String> = signals
                .iter()
                .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                .map(|(n, _)| n.clone())
                .collect();

            // Wire input signals from signal_args
            for (i, arg) in signal_args.iter().enumerate() {
                let sig_name = if let Some(name) = &arg.name {
                    name.clone()
                } else if i < input_names.len() {
                    input_names[i].clone()
                } else {
                    return Err(LoweringError::new(
                        "too many signal arguments for anonymous component",
                        span,
                    ));
                };
                let wired_name = format!("{anon_name}.{sig_name}");
                let lowered_val = lower_expr(&arg.value, env, ctx)?;
                nodes.push(CircuitNode::Let {
                    name: wired_name,
                    value: lowered_val,
                    span: sr.clone(),
                });
            }

            // Inline the component body
            let body = inline_component_body(&anon_name, template, &lowered_args, ctx, span)?;
            nodes.extend(body);

            // Wire output signals to tuple targets
            if targets.len() > output_names.len() {
                return Err(LoweringError::new(
                    format!(
                        "tuple has {} targets but template `{tmpl_name}` has {} outputs",
                        targets.len(),
                        output_names.len()
                    ),
                    span,
                ));
            }
            for (t, out_name) in targets.iter().zip(output_names.iter()) {
                if matches!(t, Expr::Underscore { .. }) {
                    continue;
                }
                let target_name = match t {
                    Expr::Ident { name, .. } => name.clone(),
                    _ => {
                        return Err(LoweringError::new(
                            "tuple target must be an identifier or underscore",
                            span,
                        ))
                    }
                };
                let comp_output = CircuitExpr::Var(format!("{anon_name}.{out_name}"));
                match op {
                    AssignOp::ConstraintAssign => {
                        nodes.push(CircuitNode::Let {
                            name: target_name.clone(),
                            value: comp_output.clone(),
                            span: sr.clone(),
                        });
                        nodes.push(CircuitNode::AssertEq {
                            lhs: CircuitExpr::Var(target_name),
                            rhs: comp_output,
                            message: None,
                            span: sr.clone(),
                        });
                    }
                    AssignOp::SignalAssign => {
                        nodes.push(CircuitNode::WitnessHint {
                            name: target_name,
                            hint: comp_output,
                            span: sr.clone(),
                        });
                    }
                    AssignOp::Assign => {
                        nodes.push(CircuitNode::Let {
                            name: target_name,
                            value: comp_output,
                            span: sr.clone(),
                        });
                    }
                    _ => unreachable!(),
                }
            }
            return Ok(());
        }

        return Err(LoweringError::new(
            "tuple destructuring requires a tuple or anonymous component on the right side",
            span,
        ));
    }

    match op {
        // `target <== expr` → Let + AssertEq (or LetIndexed + AssertEq for arrays)
        AssignOp::ConstraintAssign => {
            let assign_target = extract_assign_target_with_constants(target, &all_constants)
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
            let assign_target = extract_assign_target_with_constants(target, &all_constants)
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
            // Tag value assignment: signal.tag = expr
            // In Circom, tags are metadata that don't produce circuit nodes.
            // Detect: if target is `x.field` and `x` is an input/local signal
            // but `x.field` is NOT a known component output, this is a tag assignment.
            if let Expr::DotAccess { object, field, .. } = target {
                if let Some(obj_name) = extract_ident_name(object) {
                    let mangled = format!("{obj_name}.{field}");
                    let is_component_signal = env.locals.contains(&mangled)
                        || env.inputs.contains(&mangled)
                        || pending.contains_key(&obj_name);
                    if !is_component_signal
                        && (env.inputs.contains(&obj_name) || env.locals.contains(&obj_name))
                    {
                        // This is a signal tag assignment — no circuit semantics.
                        return Ok(());
                    }
                }
            }

            // Component array element instantiation: muls[i] = Template()
            // Also handles 2D: sigmaF[r][j] = Sigma()
            if let Some(comp_name) = try_resolve_component_array_target(target, env, ctx) {
                env.locals.insert(comp_name.clone());

                if let Some(call) = extract_component_call(value, env, ctx)? {
                    if let Some(template) = ctx.templates.get(call.template_name.as_str()) {
                        let template = *template;
                        register_component_locals(&comp_name, template, &call.scalar_args, env);

                        let signals = collect_signal_names(&template.body.stmts);
                        let input_signals: HashSet<String> = signals
                            .iter()
                            .filter(|(_, st)| matches!(st, ast::SignalType::Input))
                            .map(|(n, _)| n.clone())
                            .collect();

                        if input_signals.is_empty() {
                            let body = inline_component_body_with_arrays(
                                &comp_name,
                                template,
                                &call.scalar_args,
                                &call.array_args,
                                ctx,
                                span,
                            )?;
                            nodes.extend(body);
                        } else {
                            pending.insert(
                                comp_name,
                                PendingComponent {
                                    template,
                                    template_args: call.scalar_args,
                                    array_args: call.array_args,
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
            let body = inline_component_body_with_arrays(
                comp_name,
                comp.template,
                &comp.template_args,
                &comp.array_args,
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
    if let Some((comp_name, signal_name)) = extract_component_wiring_with_env(target, env, ctx) {
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
                let body = inline_component_body_with_arrays(
                    &comp_name,
                    comp.template,
                    &comp.template_args,
                    &comp.array_args,
                    ctx,
                    span,
                )?;
                nodes.extend(body);
            }
        }
    }
    Ok(())
}

/// Parsed component call with scalar and array template arguments.
struct ComponentCall {
    template_name: String,
    scalar_args: Vec<CircuitExpr>,
    array_args: HashMap<String, EvalValue>,
}

/// Extract a template call from a component initializer expression.
///
/// `Template(arg1, arg2)` → `Some(ComponentCall { ... })`
///
/// Arguments that refer to known compile-time arrays (from `env.known_array_values`)
/// are stored in `array_args` instead of being lowered to `CircuitExpr`.
fn extract_component_call(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<Option<ComponentCall>, LoweringError> {
    if let Expr::Call { callee, args, span } = expr {
        if let Some(name) = extract_ident_name(callee) {
            // Check if this is a bus type being used as a component
            if ctx.bus_names.contains(name.as_str()) {
                return Err(LoweringError::new(
                    format!(
                        "`{name}` is a bus type, not a template; bus types require \
                         Circom ≥2.2.0 bus compilation support which is not yet implemented"
                    ),
                    span,
                ));
            }

            // Collect array arg indices before lowering (avoids borrow conflicts)
            let mut array_arg_indices: Vec<(usize, String, EvalValue)> = Vec::new();
            for (i, arg) in args.iter().enumerate() {
                if let Some(arg_name) = extract_ident_name(arg) {
                    if let Some(arr_val) = env.known_array_values.get(&arg_name) {
                        array_arg_indices.push((i, arg_name, arr_val.clone()));
                    }
                }
            }

            let mut lowered_args = Vec::new();
            let array_indices: HashSet<usize> =
                array_arg_indices.iter().map(|(i, _, _)| *i).collect();
            for (i, arg) in args.iter().enumerate() {
                if array_indices.contains(&i) {
                    lowered_args.push(CircuitExpr::Const(FieldConst::zero()));
                } else {
                    lowered_args.push(lower_expr(arg, env, ctx)?);
                }
            }

            // Map template param names → array values
            let mut array_args = HashMap::new();
            if let Some(template) = ctx.templates.get(name.as_str()) {
                for (i, _arg_name, arr_val) in &array_arg_indices {
                    if let Some(param_name) = template.params.get(*i) {
                        array_args.insert(param_name.clone(), arr_val.clone());
                    }
                }
            }
            return Ok(Some(ComponentCall {
                template_name: name,
                scalar_args: lowered_args,
                array_args,
            }));
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

/// Check if a list of statements only touches variables (no signals, components,
/// or constraint operations). Used to determine if a while loop can be evaluated
/// at compile time.
fn stmts_are_var_only(stmts: &[Stmt]) -> bool {
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
fn eval_while_compile_time(
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
                if super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions).is_none() {
                    return Err(LoweringError::new(
                        "do-while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        span,
                    ));
                }
            }
            let cond =
                super::utils::try_eval_expr_i64(condition, &vars, &functions).ok_or_else(|| {
                    LoweringError::new(
                        "do-while loop condition could not be evaluated at compile time",
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
                super::utils::try_eval_expr_i64(condition, &vars, &functions).ok_or_else(|| {
                    LoweringError::new(
                        "while loop condition could not be evaluated at compile time",
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
                if super::utils::try_eval_stmt_in_place(stmt, &mut vars, &functions).is_none() {
                    return Err(LoweringError::new(
                        "while loop body could not be evaluated at compile time; \
                         all variables must be known constants",
                        span,
                    ));
                }
            }
        }
    }

    Err(LoweringError::new(
        format!(
            "while loop did not terminate within {MAX_WHILE_ITERS} iterations \
             during compile-time evaluation"
        ),
        span,
    ))
}

/// Check if any statement in the body references a component array.
///
/// Uses a conservative approach: scans ALL expressions (not just direct
/// patterns) for any identifier matching a declared component array name.
/// This catches indirect access via functions, complex indices like
/// `muls[i*n+j]`, and nested expressions.
fn body_has_component_array_ops(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    if env.component_arrays.is_empty() {
        return false;
    }
    stmts_reference_component_arrays(stmts, &env.component_arrays)
}

/// Check if any statement in the body references a known compile-time array.
///
/// If so, the enclosing for loop must be unrolled so that array indices
/// resolve to constants at lowering time.
fn body_references_known_arrays(stmts: &[Stmt], env: &LoweringEnv) -> bool {
    if env.known_array_values.is_empty() {
        return false;
    }
    let array_names: HashSet<String> = env.known_array_values.keys().cloned().collect();
    stmts_reference_component_arrays(stmts, &array_names)
}

fn stmts_reference_component_arrays(stmts: &[Stmt], arrays: &HashSet<String>) -> bool {
    stmts
        .iter()
        .any(|s| stmt_references_component_arrays(s, arrays))
}

fn stmt_references_component_arrays(stmt: &Stmt, arrays: &HashSet<String>) -> bool {
    match stmt {
        Stmt::Substitution { target, value, .. } => {
            expr_references_component_arrays(target, arrays)
                || expr_references_component_arrays(value, arrays)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            expr_references_component_arrays(target, arrays)
                || expr_references_component_arrays(value, arrays)
        }
        Stmt::ConstraintEq { lhs, rhs, .. } => {
            expr_references_component_arrays(lhs, arrays)
                || expr_references_component_arrays(rhs, arrays)
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_references_component_arrays(condition, arrays)
                || stmts_reference_component_arrays(&then_body.stmts, arrays)
                || match else_body {
                    Some(ElseBranch::Block(b)) => {
                        stmts_reference_component_arrays(&b.stmts, arrays)
                    }
                    Some(ElseBranch::IfElse(s)) => stmt_references_component_arrays(s, arrays),
                    None => false,
                }
        }
        Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
            stmts_reference_component_arrays(&body.stmts, arrays)
        }
        Stmt::Block(b) => stmts_reference_component_arrays(&b.stmts, arrays),
        Stmt::ComponentDecl { init, .. } => init
            .as_ref()
            .map(|e| expr_references_component_arrays(e, arrays))
            .unwrap_or(false),
        Stmt::Expr { expr, .. } => expr_references_component_arrays(expr, arrays),
        Stmt::VarDecl { init, .. } => init
            .as_ref()
            .map(|e| expr_references_component_arrays(e, arrays))
            .unwrap_or(false),
        _ => false,
    }
}

fn expr_references_component_arrays(expr: &Expr, arrays: &HashSet<String>) -> bool {
    match expr {
        Expr::Ident { name, .. } => arrays.contains(name),
        Expr::BinOp { lhs, rhs, .. } => {
            expr_references_component_arrays(lhs, arrays)
                || expr_references_component_arrays(rhs, arrays)
        }
        Expr::UnaryOp { operand, .. }
        | Expr::PostfixOp { operand, .. }
        | Expr::PrefixOp { operand, .. }
        | Expr::ParallelOp { operand, .. } => expr_references_component_arrays(operand, arrays),
        Expr::Index { object, index, .. } => {
            expr_references_component_arrays(object, arrays)
                || expr_references_component_arrays(index, arrays)
        }
        Expr::DotAccess { object, .. } => expr_references_component_arrays(object, arrays),
        Expr::Call { callee, args, .. } => {
            expr_references_component_arrays(callee, arrays)
                || args
                    .iter()
                    .any(|a| expr_references_component_arrays(a, arrays))
        }
        Expr::AnonComponent {
            callee,
            template_args,
            signal_args,
            ..
        } => {
            expr_references_component_arrays(callee, arrays)
                || template_args
                    .iter()
                    .any(|a| expr_references_component_arrays(a, arrays))
                || signal_args
                    .iter()
                    .any(|a| expr_references_component_arrays(&a.value, arrays))
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_references_component_arrays(condition, arrays)
                || expr_references_component_arrays(if_true, arrays)
                || expr_references_component_arrays(if_false, arrays)
        }
        Expr::ArrayLit { elements, .. } | Expr::Tuple { elements, .. } => elements
            .iter()
            .any(|e| expr_references_component_arrays(e, arrays)),
        _ => false,
    }
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

// ---------------------------------------------------------------------------
// Array evaluation helpers
// ---------------------------------------------------------------------------

/// Try to evaluate a var initializer to a compile-time array.
///
/// Attempts compile-time evaluation for function calls that return arrays
/// (e.g. `POSEIDON_C(t)`) and for array literals whose elements are all
/// compile-time constants.  Returns `None` if the expression cannot be
/// fully evaluated.
fn try_eval_array_init(expr: &Expr, env: &LoweringEnv, ctx: &LoweringContext) -> Option<EvalValue> {
    // Build a combined params map from ctx.param_values + env.known_constants
    let mut params: HashMap<String, u64> = ctx.param_values.clone();
    for (k, &v) in &env.known_constants {
        params.insert(k.clone(), v);
    }

    match expr {
        Expr::Call { callee, args, .. } => {
            let fn_name = extract_ident_name(callee)?;
            let func = *ctx.functions.get(fn_name.as_str())?;
            let val = super::utils::try_eval_function_call_to_value(
                func,
                args,
                &params,
                &ctx.functions,
                ctx.inline_depth,
            )?;
            // Only return array values — scalars are handled by the normal path
            if matches!(val, EvalValue::Array(_)) {
                Some(val)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Expand an [`EvalValue`] into `CircuitNode::Let` bindings.
///
/// For a 1-D array `EvalValue::Array([S(1), Expr(0xabc), …])` with base `C`:
///   → `Let { name: "C_0", value: Const(1) }`
///   → `Let { name: "C_1", value: Const(from_hex("0xabc")) }`
///   → registers `C` as an array of length N
///
/// For 2-D arrays, flattens with strides.
fn expand_eval_value_to_nodes(
    base: &str,
    val: &EvalValue,
    nodes: &mut Vec<CircuitNode>,
    env: &mut LoweringEnv,
    span: &Option<SpanRange>,
) {
    match val {
        EvalValue::Scalar(v) => {
            nodes.push(CircuitNode::Let {
                name: base.to_string(),
                value: CircuitExpr::Const(FieldConst::from_u64(*v as u64)),
                span: span.clone(),
            });
            env.locals.insert(base.to_string());
        }
        EvalValue::Expr(expr) => {
            if let Some(fc) = expr_to_field_const(expr) {
                nodes.push(CircuitNode::Let {
                    name: base.to_string(),
                    value: CircuitExpr::Const(fc),
                    span: span.clone(),
                });
                env.locals.insert(base.to_string());
            }
        }
        EvalValue::Array(elems) => {
            // Check if this is a 2-D array (elements are arrays)
            let is_2d = elems
                .first()
                .is_some_and(|e| matches!(e, EvalValue::Array(_)));
            if is_2d {
                // 2-D: flatten with linearized indexing
                let mut flat_idx = 0;
                let row_len = elems.first().and_then(|e| e.len()).unwrap_or(0);
                for row_val in elems.iter() {
                    if let EvalValue::Array(cols) = row_val {
                        for col_val in cols.iter() {
                            let elem_name = format!("{base}_{flat_idx}");
                            emit_eval_leaf(&elem_name, col_val, nodes, env, span);
                            flat_idx += 1;
                        }
                    }
                }
                let total = elems.len() * row_len;
                env.register_array(base.to_string(), total);
                // Strides for 2-D: arr[i][j] → arr[i*cols+j]
                env.strides.insert(base.to_string(), vec![row_len]);
            } else {
                // 1-D: simple element naming
                for (i, elem) in elems.iter().enumerate() {
                    let elem_name = format!("{base}_{i}");
                    emit_eval_leaf(&elem_name, elem, nodes, env, span);
                }
                env.register_array(base.to_string(), elems.len());
            }
        }
    }
}

/// Emit a single Let node for a leaf EvalValue (Scalar or Expr).
fn emit_eval_leaf(
    name: &str,
    val: &EvalValue,
    nodes: &mut Vec<CircuitNode>,
    env: &mut LoweringEnv,
    span: &Option<SpanRange>,
) {
    let fc = match val {
        EvalValue::Scalar(v) => Some(FieldConst::from_u64(*v as u64)),
        EvalValue::Expr(expr) => expr_to_field_const(expr),
        EvalValue::Array(_) => None, // shouldn't happen at leaf level
    };
    if let Some(fc) = fc {
        nodes.push(CircuitNode::Let {
            name: name.to_string(),
            value: CircuitExpr::Const(fc),
            span: span.clone(),
        });
        env.locals.insert(name.to_string());
    }
}

/// Convert an AST expression (number or hex literal) to a `FieldConst`.
fn expr_to_field_const(expr: &Expr) -> Option<FieldConst> {
    match expr {
        Expr::Number { value, .. } => FieldConst::from_decimal_str(value),
        Expr::HexNumber { value, .. } => FieldConst::from_hex_str(value),
        _ => None,
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
    fn assert_emits_witness_check() {
        // In Circom, assert() is a prover-side runtime check during witness
        // computation. We emit an Assert node so the witness evaluator can
        // verify it, but the instantiator treats it as a no-op (no R1CS constraints).
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
        // signal.tag = expr is metadata, produces no circuit nodes.
        let nodes = lower_template("signal input {maxbit} a; a.maxbit = 8;").unwrap();
        // Only the signal decl registers the name, no circuit nodes.
        assert!(nodes.is_empty());
    }

    // ── While loops ────────────────────────────────────────────────

    #[test]
    fn while_var_only_succeeds() {
        // While loops that only touch vars are evaluated at compile time.
        let nodes = lower_template("var i = 0; while (i < 5) { i += 1; }").unwrap();
        // Only the initial VarDecl produces a Let node; the while loop is
        // fully evaluated at compile time and produces no circuit nodes.
        assert_eq!(nodes.len(), 1);
        assert!(matches!(&nodes[0], CircuitNode::Let { name, .. } if name == "i"));
    }

    #[test]
    fn while_with_signals_is_error() {
        // While loops that touch signals must fail.
        let result =
            lower_template("signal output x; var i = 0; while (i < 5) { x <== i; i += 1; }");
        assert!(result.is_err());
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
