//! Control-flow lift: `for` and `if / else`.
//!
//! [`LiftState::lift_for`] unrolls a literal-bounded loop at lift time —
//! the loop variable is tracked as a compile-time `ConstInt` for the
//! duration of each body invocation.
//!
//! [`LiftState::lift_if_else`] dispatches to one of two lower-level
//! paths:
//!
//! - [`LiftState::lift_if_else_folded`] — compile-time-foldable
//!   condition: emits only the taken side's instructions.
//! - [`LiftState::lift_if_else_mux`] — runtime condition: lowers both
//!   arms, branchlessly merges scalar local updates via a field-arithmetic
//!   mux. Bails on shapes (array writes, witness writes, `return`) the
//!   mux can't safely handle.

use std::collections::{BTreeSet, HashMap};

use artik::{IntW, Reg};

use crate::ast::{self, BinOp, CompoundOp, Expr, Stmt};

use super::helpers::{
    eval_const_expr, is_increment_on, stmt_is_mux_compatible, stmts_are_mux_compatible,
};
use super::{ConstInt, LiftState};

impl<'f> LiftState<'f> {
    /// Unroll a for loop at lift time. Only loops with literal bounds
    /// and a `++` / `+= 1` step over a freshly declared integer loop
    /// variable are supported. The loop variable is tracked as a
    /// `ConstInt` in `const_locals` for the duration of each body
    /// invocation; compile-time references to it fold to `PushConst`.
    pub(super) fn lift_for(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        // Init: `var <name> = <literal>;`
        let Stmt::VarDecl {
            names,
            init: Some(init_expr),
            ..
        } = init
        else {
            return None;
        };
        if names.len() != 1 {
            return None;
        }
        let var_name = names[0].clone();
        let start = eval_const_expr(init_expr, &self.const_locals)?;

        // Condition: `<var> < <bound>` or `<var> <= <bound>`
        let (end_bound, inclusive) = match condition {
            Expr::BinOp { op, lhs, rhs, .. } => {
                let Expr::Ident { name, .. } = lhs.as_ref() else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                let bound = eval_const_expr(rhs, &self.const_locals)?;
                match op {
                    BinOp::Lt => (bound, false),
                    BinOp::Le => (bound, true),
                    _ => return None,
                }
            }
            _ => return None,
        };

        // Step: `<var>++` / `++<var>` / `<var> += 1`
        match step {
            Stmt::Expr { expr, .. } => {
                if !is_increment_on(expr, &var_name) {
                    return None;
                }
            }
            Stmt::CompoundAssign {
                target, op, value, ..
            } => {
                let Expr::Ident { name, .. } = target else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                if !matches!(op, CompoundOp::Add) {
                    return None;
                }
                if eval_const_expr(value, &self.const_locals)? != 1 {
                    return None;
                }
            }
            _ => return None,
        }

        // Cheap bound on unroll work: the executor's frame size is
        // capped at MAX_FRAME_SIZE (65536 regs); each body iteration
        // can touch several registers. Reject loops beyond a safe
        // ceiling so a hostile circom source can't force the lift to
        // allocate a huge Artik body up front.
        let raw_end = if inclusive { end_bound + 1 } else { end_bound };
        let iterations = raw_end.saturating_sub(start);
        if !(0..=4096).contains(&iterations) {
            return None;
        }

        // Unroll. Restore the previous const_locals entry on exit so
        // nested loops with shadowing (rare) remain sound.
        let prev = self.const_locals.insert(var_name.clone(), start);
        for i in start..raw_end {
            *self
                .const_locals
                .get_mut(&var_name)
                .expect("loop var was just inserted") = i;
            for stmt in body {
                self.lift_stmt(stmt)?;
                if self.halted {
                    break;
                }
            }
            if self.halted {
                break;
            }
        }
        match prev {
            Some(v) => {
                self.const_locals.insert(var_name, v);
            }
            None => {
                self.const_locals.remove(&var_name);
            }
        }
        Some(())
    }

    /// Lift an `if / else`. Compile-time-foldable conditions pick a
    /// single branch and emit only that body's instructions. Runtime
    /// conditions (dependent on a signal or runtime-valued local) fall
    /// through to [`lift_if_else_mux`], which branchlessly computes
    /// both arms and selects per-variable via a field-arithmetic mux.
    /// Anything the mux pass can't prove safe returns `None` and the
    /// caller falls back to E212.
    pub(super) fn lift_if_else(
        &mut self,
        condition: &Expr,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        if let Some(cond) = eval_const_expr(condition, &self.const_locals) {
            return self.lift_if_else_folded(cond, then_body, else_body);
        }
        self.lift_if_else_mux(condition, then_body, else_body)
    }

    /// Compile-time branch: `cond` already evaluated to an integer;
    /// emit only the taken side's instructions.
    fn lift_if_else_folded(
        &mut self,
        cond: ConstInt,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        if cond != 0 {
            for s in &then_body.stmts {
                self.lift_stmt(s)?;
                if self.halted {
                    return Some(());
                }
            }
        } else {
            match else_body {
                Some(ast::ElseBranch::Block(b)) => {
                    for s in &b.stmts {
                        self.lift_stmt(s)?;
                        if self.halted {
                            return Some(());
                        }
                    }
                }
                Some(ast::ElseBranch::IfElse(boxed)) => {
                    self.lift_stmt(boxed)?;
                }
                None => {}
            }
        }
        Some(())
    }

    /// Runtime if/else: lower both branches into the same Artik
    /// program and merge their scalar local updates via a
    /// field-arithmetic mux — `x = cond_bool * then_x + (1 - cond_bool) * else_x`.
    /// `cond_bool` is derived from the raw condition through `FEq(cond, 0)`
    /// so the result matches circom's semantics (0 → false, non-zero → true)
    /// regardless of whether the caller already constrained `cond` to `{0,1}`.
    ///
    /// Bails (returns `None`) when either arm contains a shape the mux
    /// can't handle safely: array writes, witness writes, `return`, or
    /// non-scalar assignment targets. Both arms execute at runtime, so
    /// any side effect that isn't "write to a register we later discard"
    /// would produce a wrong witness.
    fn lift_if_else_mux(
        &mut self,
        condition: &Expr,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        // Pre-flight: reject anything that might have side effects at
        // runtime. `return`, array writes, and witness writes would all
        // execute unconditionally under the mux scheme.
        if !stmts_are_mux_compatible(&then_body.stmts) {
            return None;
        }
        match else_body {
            Some(ast::ElseBranch::Block(b)) => {
                if !stmts_are_mux_compatible(&b.stmts) {
                    return None;
                }
            }
            Some(ast::ElseBranch::IfElse(boxed)) => {
                if !stmt_is_mux_compatible(boxed) {
                    return None;
                }
            }
            None => {}
        }

        // Normalize the condition to a {0, 1} field element. We
        // compute `is_zero = FEq(cond, 0)` (outputs Int(U8) 0/1),
        // lift back to Field via `FieldFromInt U8`, then take
        // `bool_cond = 1 - is_zero`. This preserves circom's
        // "0 is false, non-zero is true" semantics without assuming
        // the caller pre-constrained `cond` to bool.
        let raw_cond = self.lift_expr(condition)?;
        let zero_reg = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(raw_cond, zero_reg);
        let is_zero_field = self.builder.field_from_int(is_zero_int, IntW::U8);
        let one_reg = self.push_const_unsigned(1)?;
        let bool_cond = self.builder.fsub(one_reg, is_zero_field);
        let not_bool_cond = self.builder.fsub(one_reg, bool_cond);

        // Snapshot the caller's scope so each branch starts from the
        // same pre-branch view.
        let pre_locals = self.locals.clone();
        let pre_const_locals = self.const_locals.clone();

        // Then-branch.
        for stmt in &then_body.stmts {
            self.lift_stmt(stmt)?;
            // `return` inside a mux branch is not representable —
            // one arm halting while the other doesn't has no
            // meaningful merge.
            if self.halted {
                return None;
            }
        }
        // A branch that demoted a const_local to runtime would make
        // the post-merge state ambiguous (const in one arm, runtime
        // in the other). Bail conservatively.
        if self.const_locals != pre_const_locals {
            return None;
        }
        let then_locals = std::mem::replace(&mut self.locals, pre_locals.clone());

        // Else-branch.
        match else_body {
            Some(ast::ElseBranch::Block(b)) => {
                for stmt in &b.stmts {
                    self.lift_stmt(stmt)?;
                    if self.halted {
                        return None;
                    }
                }
            }
            Some(ast::ElseBranch::IfElse(boxed)) => {
                self.lift_stmt(boxed)?;
                if self.halted {
                    return None;
                }
            }
            None => {}
        }
        if self.const_locals != pre_const_locals {
            return None;
        }
        let else_locals = std::mem::take(&mut self.locals);

        // Merge. For each name in the union of pre / then / else
        // scopes, produce one register that holds the post-branch
        // value. Names unchanged by both arms pass through; names
        // updated in at least one arm get a mux instruction triple.
        let mut names: BTreeSet<String> = BTreeSet::new();
        for k in pre_locals.keys() {
            names.insert(k.clone());
        }
        for k in then_locals.keys() {
            names.insert(k.clone());
        }
        for k in else_locals.keys() {
            names.insert(k.clone());
        }

        let mut merged: HashMap<String, Reg> = HashMap::new();
        for name in &names {
            let then_r = then_locals
                .get(name)
                .copied()
                .or_else(|| pre_locals.get(name).copied());
            let else_r = else_locals
                .get(name)
                .copied()
                .or_else(|| pre_locals.get(name).copied());
            match (then_r, else_r) {
                (Some(t), Some(e)) if t == e => {
                    merged.insert(name.clone(), t);
                }
                (Some(t), Some(e)) => {
                    let t_part = self.builder.fmul(bool_cond, t);
                    let e_part = self.builder.fmul(not_bool_cond, e);
                    let out = self.builder.fadd(t_part, e_part);
                    merged.insert(name.clone(), out);
                }
                // Name exists in only one arm and wasn't declared
                // before the branch — the other path leaves it
                // undefined, which the mux can't fix.
                _ => return None,
            }
        }

        self.locals = merged;
        Some(())
    }
}
