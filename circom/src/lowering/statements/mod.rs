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
mod component_decl;
mod control;
mod expr_stmt;
mod loops;
mod signal_decl;
mod substitution;
mod targets;
#[cfg(test)]
mod tests;
mod vars;
pub(crate) mod wiring;

use std::collections::HashMap;

use diagnostics::SpanRange;
use ir_forge::types::{ArraySize, CircuitExpr, CircuitNode};

use crate::ast::{AssignOp, Expr, Stmt};

use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::expressions::lower_expr;
use super::utils::extract_ident_name;

use component_decl::lower_component_decl;
use control::lower_if_else;
use expr_stmt::lower_expr_stmt;
use loops::{eval_while_compile_time, lower_for_loop, stmts_are_var_only};
use signal_decl::total_dim_size;
use substitution::lower_substitution;
use vars::lower_var_decl;
use wiring::{collect_value_component_refs, flush_specific_component, PendingComponent};
/// Lower a sequence of Circom statements to ProveIR `CircuitNode`s.
///
/// Allocates a fresh `pending` HashMap for the duration of the call and
/// drains any remaining pending components into the returned Vec at exit.
/// **This is the block-scope primitive**: each call is a self-contained
/// scope where new components register, get wired, and inline. Use this
/// for body-introducing constructs that must not propagate pending state
/// to the caller (template body, runtime if/else branches, sub-template
/// inlining).
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
/// Used by `lower_for_loop`'s direct-unroll and memoize paths to share
/// component wirings between loop body and the parent scope (e.g.,
/// `for (...) { mux.c[0][i] <== c[i]; }` registers wirings on the
/// caller's `mux` so the next iteration sees them). **Skip the
/// end-of-block drain here** — the caller's own `lower_stmts` (or its
/// equivalent) owns the drain.
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
    //
    // `pending` is a `HashMap`, so its key iteration order is
    // per-process random. Each inlined component appends a whole body
    // chunk to `nodes`; emitting them in hash order would make the
    // lowered node sequence — and therefore every downstream IR,
    // bytecode, and constraint emission — non-deterministic across
    // processes for the same input. Sort by component name to pin a
    // stable, reproducible inline order.
    let mut remaining: Vec<String> = pending.keys().cloned().collect();
    remaining.sort();
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
        Stmt::SignalDecl {
            declarations, span, ..
        } => {
            for decl in declarations {
                env.locals.insert(decl.name.clone());
                // Two concerns, two conditionals.
                //
                // (1) `env.register_array` is lowering-internal state:
                //     it lets `lower_expr` resolve `arr[k]` to
                //     `Var("arr_k")` via `env.resolve_array_element`
                //     in subsequent statements *within this same body*.
                //     Always register when the dim is resolvable —
                //     including in inlined sub-template bodies. Without
                //     this, an indexed read inside the body falls
                //     through to `CircuitExpr::ArrayIndex` emission,
                //     which at instantiate time can mint fresh
                //     unconstrained wires when the array binding hasn't
                //     been populated by an upstream `Let`/`WitnessHint`.
                //     `extract_signal_array_sizes` (called from
                //     `components.rs` at inline-time) covers most cases
                //     but fails for dims computed via user-defined
                //     functions (e.g. `signal output out[nout]` where
                //     `nout = nbits((2**n-1)*ops)`); by the time
                //     lowering reaches this site the preceding `var`
                //     statements have populated `env.known_constants`,
                //     so `total_dim_size` resolves cleanly.
                //
                // (2) The `WitnessArrayDecl` IR node is the binding
                //     point for upstream slot allocation (the
                //     `SymbolicIndexedEffect` walker path snapshots
                //     `array_slots` from this declaration). Emitting
                //     it inside an inlined sub-template attaches a
                //     pre-mangle name that the outer instantiator
                //     can't bind to a slot, so skip the emission in
                //     inlined bodies — the classifier already forces
                //     unroll for inlined envs and the `WitnessHintIndexed`
                //     emit handles slot population at instantiate time.
                if !decl.dimensions.is_empty() {
                    if let Some(total) = total_dim_size(&decl.dimensions, ctx) {
                        env.register_array(decl.name.clone(), total as usize);
                        if !env.is_inlined {
                            nodes.push(CircuitNode::WitnessArrayDecl {
                                name: decl.name.clone(),
                                size: ArraySize::Literal(total as usize),
                                span: Some(diagnostics::SpanRange::from_span(span)),
                            });
                        }
                    }
                }
            }
        }

        // ── Variable declarations ───────────────────────────────────
        Stmt::VarDecl {
            names,
            dimensions,
            init,
            span,
        } => {
            lower_var_decl(names, dimensions, init.as_ref(), span, env, nodes, ctx)?;
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
            // Indexed compound write to a local var array (e.g. circomlib's
            // `prod_val[i + j] += a[i] * b[j]`): resolve the flat element
            // name through the same path as the indexed `=` lowering and
            // emit `Let { name: "X_<flat>", value: Var("X_<flat>") op rhs }`.
            // The loop classifier preempts to `IndexedAssignmentLoop` for
            // any body with indexed assignments, so `i` / `j` const-fold
            // per iteration.
            if let Some(assign_target) = targets::extract_assign_target_ctx(target, ctx, env) {
                let (array, idx_refs_owned) = match &assign_target {
                    targets::AssignTarget::Indexed { array, index } => {
                        (array.clone(), vec![(**index).clone()])
                    }
                    targets::AssignTarget::MultiIndexed { array, indices } => {
                        (array.clone(), indices.clone())
                    }
                    targets::AssignTarget::Scalar(_) => (String::new(), Vec::new()),
                };
                if env.arrays.contains_key(&array) {
                    let idx_refs: Vec<&Expr> = idx_refs_owned.iter().collect();
                    let elem_name = substitution::resolve_local_array_element_name(
                        &array, &idx_refs, span, env, ctx,
                    )?;
                    let current = CircuitExpr::Var(elem_name.clone());
                    let rhs = lower_expr(value, env, ctx)?;
                    let bin_op = substitution::compound_to_binop(*op, &current, rhs, span)?;
                    nodes.push(CircuitNode::Let {
                        name: elem_name,
                        value: bin_op,
                        span: Some(SpanRange::from_span(span)),
                    });
                    return Ok(());
                }
            }

            let name = extract_ident_name(target).ok_or_else(|| {
                LoweringError::new(
                    "compound assignment target must be a simple identifier",
                    span,
                )
            })?;
            let current = CircuitExpr::Var(name.clone());
            let rhs = lower_expr(value, env, ctx)?;
            let bin_op = substitution::compound_to_binop(*op, &current, rhs, span)?;

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
