use crate::ast::{BinOp, ElseBranch, Expr, Stmt};

/// Are all of `stmts` safe to lift under the mux scheme (both arms
/// executing unconditionally at runtime)?
pub(in super::super) fn stmts_are_mux_compatible(stmts: &[Stmt]) -> bool {
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
pub(in super::super) fn stmt_is_mux_compatible(stmt: &Stmt) -> bool {
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

/// Is `expr` side-effect-free *and non-faulting* enough to evaluate on
/// both arms of a runtime mux? The mux runs both arms unconditionally,
/// so an operation whose validity depends on the surrounding guard must
/// not be admitted — when the predicate cannot prove the operation
/// cannot fault, it routes through the branching lift, which evaluates
/// only the taken arm and honours the guard. Calls, array reads, and
/// division/modulo all bail for this reason.
pub(in super::super) fn expr_is_mux_compatible(expr: &Expr) -> bool {
    match expr {
        Expr::Number { .. } | Expr::HexNumber { .. } | Expr::Ident { .. } => true,
        Expr::BinOp { op, lhs, rhs, .. } => {
            // Division and modulo fault on a zero divisor
            // (`FieldDivByZero`). A guarded `if (x != 0) y = a \ x`
            // would compute `a \ 0` in the dead arm under the mux, so
            // route any div/mod through the branching lift. Every other
            // binop is pure arithmetic.
            !matches!(op, BinOp::Div | BinOp::IntDiv | BinOp::Mod)
                && expr_is_mux_compatible(lhs)
                && expr_is_mux_compatible(rhs)
        }
        Expr::UnaryOp { operand, .. } => expr_is_mux_compatible(operand),
        Expr::PostfixOp { operand, .. } | Expr::PrefixOp { operand, .. } => {
            expr_is_mux_compatible(operand)
        }
        // An array read `arr[i]` faults (`ArrayIndexOutOfBounds`) when
        // `i` is out of range. The predicate has no array-length info,
        // so it cannot prove the index in-range; a guarded
        // `if (i != 0) y = arr[i - 1]` would read `arr[-1]` in the dead
        // arm under the mux. Route reads through the branching lift,
        // which evaluates only the taken arm.
        Expr::Index { .. } => false,
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
        // Function calls are opaque: an inlined callee may emit a
        // faulting opcode (e.g. `FIDiv` on a zero divisor inside a
        // `\` op) whose validity hinges on the runtime guard the
        // caller wrapped around the call. Mux execution runs both
        // arms, so the not-taken arm's call still executes its body
        // and can fault. Route calls through the branching lift,
        // which honours the guard.
        Expr::Call { .. } => false,
        _ => false,
    }
}
