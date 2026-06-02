use std::collections::HashMap;

use crate::ast::{ElseBranch, Stmt};

use super::super::ConstInt;
use super::consts::eval_const_expr;

/// The array-dimension signature of a function body: every `var X[..]`
/// declaration's folded dimensions, concatenated in pre-order
/// source-traversal order. `None` if any dimension does not fold
/// against the param consts — a runtime array dimension means no
/// fixed-shape subprogram can be reserved for the body.
///
/// This is the subprogram specialization key. Two instantiations of
/// the same circom function whose array dimensions fold to the same
/// values share one subprogram; instantiations that differ in any
/// dimension get distinct ones. The traversal order is fixed
/// (statements in source order, `then` before `else`, recursing into
/// compound bodies), so a given body always produces the same `Vec`
/// and equality on it is a sound dedup key regardless of which call
/// site triggered the lift.
pub(in super::super) fn compute_dim_signature(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
) -> Option<Vec<u32>> {
    let mut sig = Vec::new();
    let mut ok = true;
    collect_dim_signature(stmts, param_consts, &mut sig, &mut ok);
    ok.then_some(sig)
}

fn collect_dim_signature(
    stmts: &[Stmt],
    param_consts: &HashMap<String, ConstInt>,
    sig: &mut Vec<u32>,
    ok: &mut bool,
) {
    for stmt in stmts {
        collect_dim_signature_in_stmt(stmt, param_consts, sig, ok);
        if !*ok {
            return;
        }
    }
}

fn collect_dim_signature_in_stmt(
    stmt: &Stmt,
    param_consts: &HashMap<String, ConstInt>,
    sig: &mut Vec<u32>,
    ok: &mut bool,
) {
    match stmt {
        Stmt::VarDecl { dimensions, .. } if !dimensions.is_empty() => {
            for d in dimensions {
                match eval_const_expr(d, param_consts).and_then(|v| u32::try_from(v).ok()) {
                    Some(n) => sig.push(n),
                    None => {
                        *ok = false;
                        return;
                    }
                }
            }
        }
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            collect_dim_signature(&then_body.stmts, param_consts, sig, ok);
            if !*ok {
                return;
            }
            match else_body {
                Some(ElseBranch::Block(b)) => {
                    collect_dim_signature(&b.stmts, param_consts, sig, ok)
                }
                Some(ElseBranch::IfElse(boxed)) => {
                    collect_dim_signature_in_stmt(boxed, param_consts, sig, ok)
                }
                None => {}
            }
        }
        Stmt::For { body, .. } => collect_dim_signature(&body.stmts, param_consts, sig, ok),
        Stmt::While { body, .. } => collect_dim_signature(&body.stmts, param_consts, sig, ok),
        Stmt::DoWhile { body, .. } => collect_dim_signature(&body.stmts, param_consts, sig, ok),
        Stmt::Block(b) => collect_dim_signature(&b.stmts, param_consts, sig, ok),
        _ => {}
    }
}
