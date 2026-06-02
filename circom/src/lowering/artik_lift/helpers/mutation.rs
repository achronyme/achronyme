use crate::ast::{ElseBranch, Expr, Stmt};

/// Collect the names of identifiers reassigned in `stmts`. Used by the
/// `while` lift to decide which scalars need slot-promotion across
/// loop iterations. Indexed assignments and array stores are
/// reported via `array_writes`; the `while` lift bails when those are
/// non-empty (heap arrays already persist across iterations, but
/// declaring a *new* array inside the body would re-allocate every
/// iteration and is rejected upstream).
pub(in super::super) fn collect_mutated_scalars(stmts: &[Stmt]) -> MutationSummary {
    let mut summary = MutationSummary::default();
    for stmt in stmts {
        walk_stmt(stmt, &mut summary);
    }
    summary
}

#[derive(Default)]
pub(in super::super) struct MutationSummary {
    /// Identifiers that appear as the target of `=`, `+=`, `++`, etc.
    pub scalars: std::collections::HashSet<String>,
    /// Identifiers used as the array side of `arr[i] = expr` or
    /// `arr[i] += expr` — the lift permits these inside `while`
    /// because Artik arrays are heap-resident.
    pub array_writes: std::collections::HashSet<String>,
    /// Set when the body re-declares an array via `var arr[N];`. The
    /// `while` lift rejects this — re-declaring an array each
    /// iteration would leak heap memory.
    pub declares_array: bool,
    /// Names introduced via a sized `var arr[N];` declaration. Lets
    /// the if/else slot merge tell array-typed targets apart from
    /// genuine scalars — `arr = call(...)` reads as a substitution
    /// against an `Ident` target syntactically, but the underlying
    /// shape is a heap rebind that doesn't need a slot.
    pub fresh_array_decls: std::collections::HashSet<String>,
    /// Set when the body emits a `<--` style witness write (currently
    /// not exposed inside circom function bodies, but kept so the
    /// detection grows cleanly if the AST adds the form).
    pub writes_witness: bool,
    /// Identifiers introduced via scalar `var x = ...;` — distinct
    /// from the pre-loop scope. The lift uses this to decide whether a
    /// reference inside the body refers to a fresh local or to one
    /// that needs slot promotion.
    pub fresh_decls: std::collections::HashSet<String>,
}

fn walk_stmt(stmt: &Stmt, out: &mut MutationSummary) {
    match stmt {
        Stmt::VarDecl {
            names, dimensions, ..
        } => {
            if !dimensions.is_empty() {
                out.declares_array = true;
                for name in names {
                    out.fresh_array_decls.insert(name.clone());
                }
            } else {
                for name in names {
                    out.fresh_decls.insert(name.clone());
                }
            }
        }
        Stmt::Substitution { target, .. } => {
            collect_assignment_target(target, out);
        }
        Stmt::CompoundAssign { target, .. } => {
            collect_assignment_target(target, out);
        }
        Stmt::Expr { expr, .. } => collect_side_effect_target(expr, out),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            for s in &then_body.stmts {
                walk_stmt(s, out);
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        walk_stmt(s, out);
                    }
                }
                Some(ElseBranch::IfElse(boxed)) => walk_stmt(boxed, out),
                None => {}
            }
        }
        Stmt::For {
            init, step, body, ..
        } => {
            walk_stmt(init, out);
            walk_stmt(step, out);
            for s in &body.stmts {
                walk_stmt(s, out);
            }
        }
        Stmt::While { body, .. } => {
            for s in &body.stmts {
                walk_stmt(s, out);
            }
        }
        Stmt::Return { .. } | Stmt::Block(_) | Stmt::Assert { .. } | Stmt::Log { .. } => {}
        _ => {}
    }
}

fn collect_assignment_target(target: &Expr, out: &mut MutationSummary) {
    match target {
        Expr::Ident { name, .. } => {
            out.scalars.insert(name.clone());
        }
        Expr::Index { object, .. } => {
            if let Expr::Ident { name, .. } = object.as_ref() {
                out.array_writes.insert(name.clone());
            }
        }
        _ => {}
    }
}

fn collect_side_effect_target(expr: &Expr, out: &mut MutationSummary) {
    if let Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } = expr {
        if let Expr::Ident { name, .. } = operand.as_ref() {
            out.scalars.insert(name.clone());
        }
    }
}
