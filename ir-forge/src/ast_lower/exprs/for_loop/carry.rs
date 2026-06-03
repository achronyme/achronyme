use std::collections::{BTreeSet, HashMap, HashSet};

use achronyme_parser::ast::{Block, ElseBranch, Expr, Stmt};

// ---------------------------------------------------------------------------
// Carry-set detection for `for` loops with mutable accumulators.
//
// Returns the deterministically-sorted list of mutable variable names
// declared *outside* the body that the body re-assigns. An empty result
// means the body is safe for the rolled-loop path; a non-empty result
// means `compile_for_expr` must eager-unroll at lower (literal range) or
// reject (dynamic range).
//
// Mirrors `circom/src/lowering/statements/loops.rs::body_writes_to_outer_scope_var`
// adapted to the achronyme prove-block AST (`achronyme_parser::ast::Stmt`,
// `Expr`, `Block`). The detection is the same two-phase shape:
//
//   1. Collect every name declared inside the body - recursively
//      descending into nested if/else, for, while, forever, block.
//   2. Walk every assignment in the body. A target whose name is (a) in
//      the outer `ssa_versions` map (declared with `mut` outside),
//      (b) not in the body's local declaration set, and (c) not the
//      loop variable, is a carry.
//
// The walk stays purely structural - no type-checking, no constant
// folding. An identifier-target lookup against `ssa_versions` is the
// authoritative "declared with mut in outer scope" predicate because
// `compile_mut_decl` is the only path that inserts into `ssa_versions`.
// ---------------------------------------------------------------------------

pub(super) fn body_writes_to_outer_mut_var(
    body: &Block,
    ssa_versions: &HashMap<String, u32>,
    loop_var: &str,
) -> Vec<String> {
    let mut body_decls: HashSet<String> = HashSet::new();
    collect_block_decls(body, &mut body_decls);

    let mut out: BTreeSet<String> = BTreeSet::new();
    walk_block_writes(body, ssa_versions, &body_decls, loop_var, &mut out);
    out.into_iter().collect()
}

pub(super) fn format_carry_list(carries: &[String]) -> String {
    let quoted: Vec<String> = carries.iter().map(|n| format!("`{n}`")).collect();
    quoted.join(", ")
}

/// Collect every binding name introduced inside this block - let, mut,
/// fn parameters, and any nested control-flow bodies. Used to mask
/// inner-shadowed names from the carry-set: if the loop body redeclares
/// `acc`, writes to that inner `acc` are not carries.
fn collect_block_decls(block: &Block, acc: &mut HashSet<String>) {
    for stmt in &block.stmts {
        collect_stmt_decls(stmt, acc);
    }
}

fn collect_stmt_decls(stmt: &Stmt, acc: &mut HashSet<String>) {
    match stmt {
        Stmt::LetDecl { name, value, .. } | Stmt::MutDecl { name, value, .. } => {
            acc.insert(name.clone());
            collect_expr_decls(value, acc);
        }
        Stmt::FnDecl {
            name, params, body, ..
        } => {
            acc.insert(name.clone());
            for p in params {
                acc.insert(p.name.clone());
            }
            collect_block_decls(body, acc);
        }
        Stmt::Assignment { value, .. } => collect_expr_decls(value, acc),
        Stmt::Print { value, .. } => collect_expr_decls(value, acc),
        Stmt::Return { value: Some(v), .. } => collect_expr_decls(v, acc),
        Stmt::Export { inner, .. } => collect_stmt_decls(inner, acc),
        Stmt::Expr(e) => collect_expr_decls(e, acc),
        // Top-level / module-level declarations and parse-error
        // placeholders carry no body-local binding semantics for our
        // purposes here.
        _ => {}
    }
}

fn collect_expr_decls(expr: &Expr, acc: &mut HashSet<String>) {
    match expr {
        Expr::If {
            then_block,
            else_branch,
            ..
        } => {
            collect_block_decls(then_block, acc);
            match else_branch {
                Some(ElseBranch::Block(b)) => collect_block_decls(b, acc),
                Some(ElseBranch::If(e)) => collect_expr_decls(e, acc),
                None => {}
            }
        }
        Expr::For { var, body, .. } => {
            // The inner loop's induction var is body-local relative to
            // *that* loop. For the outer-loop carry analysis, treat it
            // as introduced inside the body.
            acc.insert(var.clone());
            collect_block_decls(body, acc);
        }
        Expr::While { body, .. } | Expr::Forever { body, .. } => {
            collect_block_decls(body, acc);
        }
        Expr::Block { block, .. } => collect_block_decls(block, acc),
        Expr::FnExpr { params, body, .. } => {
            for p in params {
                acc.insert(p.name.clone());
            }
            collect_block_decls(body, acc);
        }
        // Other expression variants don't introduce bindings; their
        // sub-expressions are scanned only if they could host one of
        // the above (covered by the recursive variants).
        _ => {}
    }
}

fn walk_block_writes(
    block: &Block,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    for stmt in &block.stmts {
        walk_stmt_writes(stmt, ssa_versions, body_decls, loop_var, out);
    }
}

fn walk_stmt_writes(
    stmt: &Stmt,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    match stmt {
        // Indexed assignments (`arr[i] = ...`) are handled by a separate
        // lowering path (`compile_indexed_assignment`) that emits
        // `LetIndexed`, not SSA-versioned `Let`. They don't share the
        // per-iter SSA-rebind shape, so they are intentionally not
        // treated as carries here.
        Stmt::Assignment {
            target: Expr::Ident { name, .. },
            ..
        } if name != loop_var && ssa_versions.contains_key(name) && !body_decls.contains(name) => {
            out.insert(name.clone());
        }
        Stmt::Expr(e) => walk_expr_writes(e, ssa_versions, body_decls, loop_var, out),
        Stmt::Print { value, .. } => {
            walk_expr_writes(value, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::Return { value: Some(v), .. } => {
            walk_expr_writes(v, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => {
            walk_expr_writes(value, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::Export { inner, .. } => {
            walk_stmt_writes(inner, ssa_versions, body_decls, loop_var, out)
        }
        _ => {}
    }
}

fn walk_expr_writes(
    expr: &Expr,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    match expr {
        Expr::If {
            then_block,
            else_branch,
            ..
        } => {
            walk_block_writes(then_block, ssa_versions, body_decls, loop_var, out);
            match else_branch {
                Some(ElseBranch::Block(b)) => {
                    walk_block_writes(b, ssa_versions, body_decls, loop_var, out)
                }
                Some(ElseBranch::If(e)) => {
                    walk_expr_writes(e, ssa_versions, body_decls, loop_var, out)
                }
                None => {}
            }
        }
        Expr::For { body, .. } | Expr::While { body, .. } | Expr::Forever { body, .. } => {
            walk_block_writes(body, ssa_versions, body_decls, loop_var, out);
        }
        Expr::Block { block, .. } => {
            walk_block_writes(block, ssa_versions, body_decls, loop_var, out)
        }
        // Other expression variants don't host assignments directly.
        _ => {}
    }
}
