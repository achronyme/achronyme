use std::collections::HashSet;

use crate::ast::{AssignOp, ElseBranch, Stmt};

use super::super::utils::extract_ident_name;

/// Find variables that are reassigned after their initial declaration.
///
/// Scans statements recursively for `Substitution { target: Ident(name), op: Assign, ... }`
/// and `CompoundAssign { target: Ident(name), ... }`. Returns the set of var names that
/// are targets of such reassignment. These vars must NOT be injected into
/// `known_constants` because their value changes during lowering.
pub(in crate::lowering) fn find_reassigned_vars(stmts: &[Stmt]) -> HashSet<String> {
    let mut reassigned = HashSet::new();
    let mut declared = HashSet::new();
    // Vars declared via `var X;` (no initializer) are treated as a
    // deferred init — the first top-level `X = expr;` is the logical
    // initializer, not a reassignment. This matches circomlib's SHA256
    // idiom (`var nBlocks; ...; nBlocks = (nBits+64)\512 + 1;`) and
    // lines up with `precompute_all`, which captures exactly that
    // first assignment as the var's compile-time value.
    let mut uninitialized = HashSet::new();
    scan_reassignments(stmts, &mut declared, &mut uninitialized, &mut reassigned);
    reassigned
}

fn scan_reassignments(
    stmts: &[Stmt],
    declared: &mut HashSet<String>,
    uninitialized: &mut HashSet<String>,
    reassigned: &mut HashSet<String>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::VarDecl { names, init, .. } => {
                for name in names {
                    declared.insert(name.clone());
                    if init.is_none() {
                        uninitialized.insert(name.clone());
                    }
                }
            }
            Stmt::Substitution {
                target,
                op: AssignOp::Assign,
                ..
            } => {
                if let Some(name) = extract_ident_name(target) {
                    if uninitialized.remove(&name) {
                        // First assignment to a `var X;` — treat as init.
                        continue;
                    }
                    if declared.contains(&name) {
                        reassigned.insert(name);
                    }
                }
            }
            Stmt::CompoundAssign { target, .. } => {
                if let Some(name) = extract_ident_name(target) {
                    reassigned.insert(name);
                }
            }
            Stmt::For {
                init, body, step, ..
            } => {
                scan_reassignments(
                    std::slice::from_ref(init.as_ref()),
                    declared,
                    uninitialized,
                    reassigned,
                );
                scan_reassignments(&body.stmts, declared, uninitialized, reassigned);
                scan_reassignments(
                    std::slice::from_ref(step.as_ref()),
                    declared,
                    uninitialized,
                    reassigned,
                );
            }
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                scan_reassignments(&then_body.stmts, declared, uninitialized, reassigned);
                if let Some(ElseBranch::Block(block)) = else_body {
                    scan_reassignments(&block.stmts, declared, uninitialized, reassigned);
                } else if let Some(ElseBranch::IfElse(inner)) = else_body {
                    scan_reassignments(
                        std::slice::from_ref(inner.as_ref()),
                        declared,
                        uninitialized,
                        reassigned,
                    );
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                scan_reassignments(&body.stmts, declared, uninitialized, reassigned);
            }
            Stmt::Block(block) => {
                scan_reassignments(&block.stmts, declared, uninitialized, reassigned);
            }
            _ => {}
        }
    }
}
