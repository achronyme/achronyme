//! Statement lift.
//!
//! [`LiftState::lift_stmt`] is the entry point: a dispatcher over statement
//! forms, with the larger arm bodies split into topic modules.

use crate::ast::Stmt;

use super::helpers::eval_const_expr;
use super::LiftState;

mod assignments;
mod compound;
mod declarations;
mod returns;
mod side_effects;

impl<'f> LiftState<'f> {
    pub(super) fn lift_stmt(&mut self, stmt: &Stmt) -> Option<()> {
        if self.halted {
            return Some(());
        }
        match stmt {
            Stmt::VarDecl {
                names,
                dimensions,
                init,
                ..
            } => self.lift_var_decl(names, dimensions, init),
            Stmt::Substitution { target, value, .. } => self.lift_substitution(target, value),
            Stmt::CompoundAssign {
                target, op, value, ..
            } => self.lift_compound_assign(target, *op, value),
            Stmt::For {
                init,
                condition,
                step,
                body,
                ..
            } => self.lift_for_dispatch(init, condition, step, &body.stmts),
            Stmt::While {
                condition, body, ..
            } => self.lift_while(condition, &body.stmts),
            Stmt::IfElse {
                condition,
                then_body,
                else_body,
                ..
            } => self.lift_if_else(condition, then_body, else_body.as_ref()),
            Stmt::Return { value, .. } => self.lift_return(value),
            Stmt::Assert { arg, .. } => {
                // Asserts inside a witness function are advisory checks
                // — they abort witness computation on failure but emit
                // no constraints. The Artik VM has no assert opcode, so
                // the lift evaluates the predicate at compile time:
                // a const-true predicate is dropped, a const-false
                // predicate bails so the caller surfaces an explicit
                // gap, and a runtime-valued predicate also bails so a
                // semantic the function relied on is not silently
                // skipped. Circomlib's witness functions invariably
                // gate on shape parameters (`n == 64 && k == 4`) which
                // fold cleanly under `try_eval_arg_const` at the call
                // site.
                let v = eval_const_expr(arg, &self.const_locals)?;
                if v == 0 {
                    return None;
                }
                Some(())
            }
            Stmt::Expr { expr, .. } => {
                // Bare expression statement. Only supported when it's
                // a postfix/prefix increment/decrement on a loop var —
                // the actual value is discarded; the side effect
                // mutates the const_locals entry. This is what lets
                // `for (; ; i++)` round-trip cleanly when the loop is
                // unrolled via `lift_for`.
                self.apply_side_effect(expr)
            }
            _ => None,
        }
    }
}
