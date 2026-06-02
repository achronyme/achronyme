use crate::ast::{ElseBranch, Stmt};

/// Does any statement in `stmts` (recursively) execute a `return`?
/// The `if/else` lift needs this to decide whether the mux merge is
/// safe — a returning arm can't merge branchlessly, so the lift falls
/// back to a real conditional jump.
pub(in super::super) fn stmts_have_return(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_return)
}

pub(in super::super) fn stmt_has_return(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return { .. } => true,
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            stmts_have_return(&then_body.stmts)
                || match else_body {
                    Some(ElseBranch::Block(b)) => stmts_have_return(&b.stmts),
                    Some(ElseBranch::IfElse(boxed)) => stmt_has_return(boxed),
                    None => false,
                }
        }
        Stmt::For { body, .. } => stmts_have_return(&body.stmts),
        Stmt::While { body, .. } => stmts_have_return(&body.stmts),
        Stmt::Block(b) => stmts_have_return(&b.stmts),
        _ => false,
    }
}

/// Collect every `var arr[...]` declaration the body would otherwise
/// execute on each loop iteration. Walks recursively into if/else,
/// for, while, and block bodies. Used by the runtime-while lift to
/// hoist the allocations out of the loop body — without hoisting,
/// each iter emits a fresh `AllocArray` and the heap explodes
/// quadratically (256 iters × ~3 arrays × 200 cells crosses the
/// per-program memory cap).
pub(in super::super) fn collect_array_decls<'a>(stmts: &'a [Stmt], out: &mut Vec<&'a Stmt>) {
    for s in stmts {
        collect_array_decls_in_stmt(s, out);
    }
}

fn collect_array_decls_in_stmt<'a>(stmt: &'a Stmt, out: &mut Vec<&'a Stmt>) {
    match stmt {
        Stmt::VarDecl { dimensions, .. } if !dimensions.is_empty() => out.push(stmt),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            collect_array_decls(&then_body.stmts, out);
            match else_body {
                Some(ElseBranch::Block(b)) => collect_array_decls(&b.stmts, out),
                Some(ElseBranch::IfElse(boxed)) => collect_array_decls_in_stmt(boxed, out),
                None => {}
            }
        }
        Stmt::For { body, .. } => collect_array_decls(&body.stmts, out),
        Stmt::While { body, .. } => collect_array_decls(&body.stmts, out),
        Stmt::Block(b) => collect_array_decls(&b.stmts, out),
        _ => {}
    }
}
