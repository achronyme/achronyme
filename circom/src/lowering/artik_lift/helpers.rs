//! Pure free-function helpers used across submodules.
//!
//! - [`eval_const_expr`] — fold an expression to a compile-time integer
//!   using the lift state's `const_locals` map. Returns `None` for
//!   anything signal- or runtime-dependent.
//! - [`extract_call_name`] — pull a bare identifier out of a call's
//!   `callee` expression.
//! - [`is_increment_on`] — shape check for `name++` / `++name`.
//! - [`stmts_are_mux_compatible`] / [`stmt_is_mux_compatible`] /
//!   [`expr_is_mux_compatible`] — pre-flight for the runtime mux pass:
//!   reject arms with `return`, array writes, witness writes, or
//!   non-scalar assignment targets.
//! - [`compound_to_binop`] — map a compound-assignment operator to the
//!   plain binary op the lift knows how to emit.

use std::collections::HashMap;

use crate::ast::{BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt, UnaryOp};

use super::ConstInt;

/// Evaluate an expression to a compile-time integer. Used for loop
/// bounds and step amounts. Looks up identifiers in the provided
/// `const_locals` map; signals / runtime-valued locals return `None`.
pub(super) fn eval_const_expr(
    expr: &Expr,
    const_locals: &HashMap<String, ConstInt>,
) -> Option<ConstInt> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            ConstInt::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
        }
        Expr::Ident { name, .. } => const_locals.get(name).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = eval_const_expr(lhs, const_locals)?;
            let b = eval_const_expr(rhs, const_locals)?;
            match op {
                BinOp::Add => a.checked_add(b),
                BinOp::Sub => a.checked_sub(b),
                BinOp::Mul => a.checked_mul(b),
                // Comparisons return 1 / 0 so `if (i == 0) { ... }`
                // inside an unrolled loop folds correctly.
                BinOp::Eq => Some((a == b) as ConstInt),
                BinOp::Neq => Some((a != b) as ConstInt),
                BinOp::Lt => Some((a < b) as ConstInt),
                BinOp::Le => Some((a <= b) as ConstInt),
                BinOp::Gt => Some((a > b) as ConstInt),
                BinOp::Ge => Some((a >= b) as ConstInt),
                _ => None,
            }
        }
        Expr::UnaryOp {
            op: UnaryOp::Neg,
            operand,
            ..
        } => eval_const_expr(operand, const_locals).and_then(ConstInt::checked_neg),
        _ => None,
    }
}

/// Extract the simple identifier from a call's `callee` expression.
/// Circom's function-call callees are always bare identifiers at the
/// lowering layer; anything more complex (method access, indexed
/// callable, etc.) bails out of the lift.
pub(super) fn extract_call_name(callee: &Expr) -> Option<String> {
    match callee {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Is `expr` an increment on the named variable (`name++` or `++name`)?
pub(super) fn is_increment_on(expr: &Expr, name: &str) -> bool {
    let (op, operand) = match expr {
        Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => (op, operand),
        _ => return false,
    };
    if !matches!(op, PostfixOp::Increment) {
        return false;
    }
    matches!(operand.as_ref(), Expr::Ident { name: n, .. } if n == name)
}

/// Are all of `stmts` safe to lift under the mux scheme (both arms
/// executing unconditionally at runtime)?
pub(super) fn stmts_are_mux_compatible(stmts: &[Stmt]) -> bool {
    stmts.iter().all(stmt_is_mux_compatible)
}

/// Shape check for a single branch statement. The mux scheme runs
/// both arms of an if/else at runtime and picks the output of the
/// "taken" arm via field arithmetic, so only side-effect-free
/// statements are admissible:
/// - scalar `var` decls / `=` / compound-assign (no array writes),
/// - nested if/else (recursively checked),
/// - bare postfix/prefix side effects on pure expressions.
///
/// `return`, array stores, and tuple destructuring bail out of the mux
/// pass; the caller falls back to E212.
pub(super) fn stmt_is_mux_compatible(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::VarDecl {
            names,
            dimensions,
            init,
            ..
        } => {
            names.len() == 1
                && dimensions.is_empty()
                && init.as_ref().is_none_or(expr_is_mux_compatible)
        }
        Stmt::Substitution { target, value, .. } => {
            matches!(target, Expr::Ident { .. }) && expr_is_mux_compatible(value)
        }
        Stmt::CompoundAssign { target, value, .. } => {
            matches!(target, Expr::Ident { .. }) && expr_is_mux_compatible(value)
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            expr_is_mux_compatible(condition)
                && stmts_are_mux_compatible(&then_body.stmts)
                && match else_body {
                    Some(ElseBranch::Block(b)) => stmts_are_mux_compatible(&b.stmts),
                    Some(ElseBranch::IfElse(boxed)) => stmt_is_mux_compatible(boxed),
                    None => true,
                }
        }
        Stmt::Expr { expr, .. } => expr_is_mux_compatible(expr),
        _ => false,
    }
}

/// Is `expr` side-effect-free enough to evaluate on both arms of a
/// runtime mux? Calls bail out: a nested lift could still read
/// signals or emit work that's fine in isolation, but we keep the
/// MVP conservative and only admit pure register arithmetic.
fn expr_is_mux_compatible(expr: &Expr) -> bool {
    match expr {
        Expr::Number { .. } | Expr::HexNumber { .. } | Expr::Ident { .. } => true,
        Expr::BinOp { lhs, rhs, .. } => expr_is_mux_compatible(lhs) && expr_is_mux_compatible(rhs),
        Expr::UnaryOp { operand, .. } => expr_is_mux_compatible(operand),
        Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            expr_is_mux_compatible(operand)
        }
        Expr::Index { object, index, .. } => {
            // `arr[i]` reads from a pre-allocated array; both arms do
            // the read but only one result is selected.
            expr_is_mux_compatible(object) && expr_is_mux_compatible(index)
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            expr_is_mux_compatible(condition)
                && expr_is_mux_compatible(if_true)
                && expr_is_mux_compatible(if_false)
        }
        // Nested function calls inline into the current Artik program
        // at `nested_depth > 0`, which captures `return` via
        // `nested_result` instead of emitting `WriteWitness`. Array
        // allocations inside the callee are scope-local to the nested
        // frame and cannot leak to the caller's arrays map. Both arms
        // emit the call's instructions — wasted work, but not a
        // witness corruption, because the mux picks the winning
        // register after the fact.
        Expr::Call { args, .. } => args.iter().all(expr_is_mux_compatible),
        _ => false,
    }
}

/// Collect the names of identifiers reassigned in `stmts`. Used by the
/// `while` lift to decide which scalars need slot-promotion across
/// loop iterations. Indexed assignments and array stores are
/// reported via `array_writes`; the `while` lift bails when those are
/// non-empty (heap arrays already persist across iterations, but
/// declaring a *new* array inside the body would re-allocate every
/// iteration and is rejected upstream).
pub(super) fn collect_mutated_scalars(stmts: &[Stmt]) -> MutationSummary {
    let mut summary = MutationSummary::default();
    for stmt in stmts {
        walk_stmt(stmt, &mut summary);
    }
    summary
}

#[derive(Default)]
pub(super) struct MutationSummary {
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

/// Does any statement in `stmts` (recursively) execute a `return`?
/// The `if/else` lift needs this to decide whether the mux merge is
/// safe — a returning arm can't merge branchlessly, so the lift falls
/// back to a real conditional jump.
pub(super) fn stmts_have_return(stmts: &[Stmt]) -> bool {
    stmts.iter().any(stmt_has_return)
}

pub(super) fn stmt_has_return(stmt: &Stmt) -> bool {
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

/// Map a circom compound-assignment operator to the plain binary op
/// the lift knows how to emit. Returns `None` for unsupported shapes.
pub(super) fn compound_to_binop(op: CompoundOp) -> Option<BinOp> {
    match op {
        CompoundOp::Add => Some(BinOp::Add),
        CompoundOp::Sub => Some(BinOp::Sub),
        CompoundOp::Mul => Some(BinOp::Mul),
        CompoundOp::Div => Some(BinOp::Div),
        CompoundOp::ShiftL => Some(BinOp::ShiftL),
        CompoundOp::ShiftR => Some(BinOp::ShiftR),
        CompoundOp::BitAnd => Some(BinOp::BitAnd),
        CompoundOp::BitOr => Some(BinOp::BitOr),
        CompoundOp::BitXor => Some(BinOp::BitXor),
        _ => None,
    }
}
