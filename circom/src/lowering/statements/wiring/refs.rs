use super::*;

/// Inline a specific pending component by name.
///
/// Used by the value-scan flush: when a substitution's value expression
/// references a pending component's output (e.g., `windows[0].out8[0]`),
/// that component must be inlined first so its output `Let` bindings
/// exist before the `Var` reference.
pub(in super::super) fn flush_specific_component<'a>(
    comp_name: &str,
    nodes: &mut Vec<CircuitNode>,
    ctx: &mut LoweringContext<'a>,
    pending: &mut HashMap<String, PendingComponent<'a>>,
    env: &mut LoweringEnv,
) -> Result<(), LoweringError> {
    if let Some(comp) = pending.remove(comp_name) {
        let span = comp.template_span().clone();
        comp.inline_into(comp_name, nodes, ctx, env, &span)?;
    }
    Ok(())
}

/// Scan a value expression for references to pending component outputs.
///
/// Walks the AST recursively looking for `DotAccess` patterns whose object
/// resolves to a pending component name. Returns the names of referenced
/// pending components (deduplicated).
///
/// This enables demand-driven flushing: a component is inlined only when
/// its output is actually needed, not based on heuristic "fully wired" checks.
pub(in super::super) fn collect_value_component_refs(
    expr: &Expr,
    pending: &HashMap<String, PendingComponent>,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Vec<String> {
    let mut refs = Vec::new();
    collect_refs_recursive(expr, pending, env, ctx, &mut refs);
    refs
}

fn collect_refs_recursive(
    expr: &Expr,
    pending: &HashMap<String, PendingComponent>,
    env: &LoweringEnv,
    ctx: &LoweringContext,
    refs: &mut Vec<String>,
) {
    match expr {
        Expr::DotAccess { object, .. } => {
            // comp.signal or comp[i].signal
            let comp_name = extract_ident_name(object)
                .or_else(|| resolve_component_array_name_ctx(object, ctx, env));
            if let Some(name) = comp_name {
                if pending.contains_key(&name) && !refs.contains(&name) {
                    refs.push(name);
                }
            }
            // Also recurse into the object (handles nested Index chains)
            collect_refs_recursive(object, pending, env, ctx, refs);
        }
        Expr::Index { object, index, .. } => {
            collect_refs_recursive(object, pending, env, ctx, refs);
            collect_refs_recursive(index, pending, env, ctx, refs);
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_refs_recursive(lhs, pending, env, ctx, refs);
            collect_refs_recursive(rhs, pending, env, ctx, refs);
        }
        Expr::UnaryOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            collect_refs_recursive(operand, pending, env, ctx, refs);
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            collect_refs_recursive(condition, pending, env, ctx, refs);
            collect_refs_recursive(if_true, pending, env, ctx, refs);
            collect_refs_recursive(if_false, pending, env, ctx, refs);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_refs_recursive(arg, pending, env, ctx, refs);
            }
        }
        Expr::Tuple { elements, .. } => {
            for elem in elements {
                collect_refs_recursive(elem, pending, env, ctx, refs);
            }
        }
        // Leaf nodes: Ident, Number, HexNumber, etc. — no component references
        _ => {}
    }
}

/// Collect every pending component that is *only* read (never wired)
/// across a sequence of statements. Used to hoist sub-component flushes
/// out of loop and conditional bodies before they get replicated by an
/// instantiate-time unroll.
///
/// The walker descends into nested for/if/while/do-while/block bodies
/// so a read at any depth surfaces the component name.
///
/// Components that are also wired in the same body stay in `pending`:
/// the demand-driven flush in `lower_stmt` triggers them mid-body once
/// their inputs are bound, which preserves order. Only the
/// read-without-wiring case is safe to hoist — for those the body's
/// own statements never touch the pending component's input signals,
/// so flushing at parent scope can't strand a wiring.
pub(in super::super) fn collect_pending_refs_in_stmts(
    stmts: &[ast::Stmt],
    pending: &HashMap<String, PendingComponent>,
    env: &LoweringEnv,
    ctx: &LoweringContext,
) -> Vec<String> {
    let mut reads = Vec::new();
    let mut wired = Vec::new();
    for stmt in stmts {
        collect_refs_in_stmt(stmt, pending, env, ctx, &mut reads, &mut wired);
    }
    reads.retain(|n| !wired.contains(n));
    reads
}

/// Push `comp_name` onto `targets` if `expr` is a write-position pattern
/// (`comp.signal`, `comp.signal[i]`, `comp[i].signal`, etc.) whose base
/// resolves to a pending component.
fn record_wired_target(
    expr: &Expr,
    pending: &HashMap<String, PendingComponent>,
    env: &LoweringEnv,
    ctx: &LoweringContext,
    targets: &mut Vec<String>,
) {
    if let Some((comp_name, _)) = extract_component_wiring_with_env(expr, env, ctx) {
        if pending.contains_key(&comp_name) && !targets.contains(&comp_name) {
            targets.push(comp_name);
        }
    }
}

fn collect_refs_in_stmt(
    stmt: &ast::Stmt,
    pending: &HashMap<String, PendingComponent>,
    env: &LoweringEnv,
    ctx: &LoweringContext,
    reads: &mut Vec<String>,
    wired: &mut Vec<String>,
) {
    match stmt {
        ast::Stmt::SignalDecl { init, .. } => {
            if let Some((_, expr)) = init {
                collect_refs_recursive(expr, pending, env, ctx, reads);
            }
        }
        ast::Stmt::VarDecl {
            dimensions, init, ..
        } => {
            for dim in dimensions {
                collect_refs_recursive(dim, pending, env, ctx, reads);
            }
            if let Some(expr) = init {
                collect_refs_recursive(expr, pending, env, ctx, reads);
            }
        }
        ast::Stmt::ComponentDecl { init, .. } => {
            if let Some(expr) = init {
                collect_refs_recursive(expr, pending, env, ctx, reads);
            }
        }
        ast::Stmt::Substitution {
            target, op, value, ..
        } => {
            // Right-flowing ops (`==>`, `-->`) put the read-side
            // expression in `target` (the syntactic LHS) and the
            // write-side wiring target in `value` (the syntactic RHS).
            // Mirror the dispatch in `lower_stmt`'s demand-driven flush
            // so we walk the actual read side, and record the wiring
            // target so the caller can suppress hoisted flushes for
            // components whose inputs are bound by this very body.
            let (read_side, write_side) = match op {
                ast::AssignOp::RConstraintAssign | ast::AssignOp::RSignalAssign => (target, value),
                _ => (value, target),
            };
            collect_refs_recursive(read_side, pending, env, ctx, reads);
            record_wired_target(write_side, pending, env, ctx, wired);
        }
        ast::Stmt::CompoundAssign { target, value, .. } => {
            collect_refs_recursive(value, pending, env, ctx, reads);
            record_wired_target(target, pending, env, ctx, wired);
        }
        ast::Stmt::ConstraintEq { lhs, rhs, .. } => {
            collect_refs_recursive(lhs, pending, env, ctx, reads);
            collect_refs_recursive(rhs, pending, env, ctx, reads);
        }
        ast::Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            collect_refs_recursive(condition, pending, env, ctx, reads);
            for s in &then_body.stmts {
                collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
            }
            match else_body {
                Some(ast::ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
                    }
                }
                Some(ast::ElseBranch::IfElse(s)) => {
                    collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
                }
                None => {}
            }
        }
        ast::Stmt::For {
            condition, body, ..
        } => {
            collect_refs_recursive(condition, pending, env, ctx, reads);
            for s in &body.stmts {
                collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
            }
        }
        ast::Stmt::While {
            condition, body, ..
        } => {
            collect_refs_recursive(condition, pending, env, ctx, reads);
            for s in &body.stmts {
                collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
            }
        }
        ast::Stmt::DoWhile {
            body, condition, ..
        } => {
            for s in &body.stmts {
                collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
            }
            collect_refs_recursive(condition, pending, env, ctx, reads);
        }
        ast::Stmt::Return { value, .. } => {
            collect_refs_recursive(value, pending, env, ctx, reads);
        }
        ast::Stmt::Assert { arg, .. } => {
            collect_refs_recursive(arg, pending, env, ctx, reads);
        }
        ast::Stmt::Log { args, .. } => {
            for a in args {
                if let ast::LogArg::Expr(e) = a {
                    collect_refs_recursive(e, pending, env, ctx, reads);
                }
            }
        }
        ast::Stmt::Block(b) => {
            for s in &b.stmts {
                collect_refs_in_stmt(s, pending, env, ctx, reads, wired);
            }
        }
        ast::Stmt::Expr { expr, .. } => {
            collect_refs_recursive(expr, pending, env, ctx, reads);
        }
        ast::Stmt::Error { .. } => {}
    }
}
