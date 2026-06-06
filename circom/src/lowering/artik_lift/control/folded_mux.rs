use std::collections::{BTreeSet, HashMap};

use artik::{IntW, Reg};

use crate::ast::{self, Expr};

use super::super::helpers::{stmt_is_mux_compatible, stmts_are_mux_compatible};
use super::super::{ConstInt, LiftState};

impl<'f> LiftState<'f> {
    /// Compile-time branch: `cond` already evaluated to an integer;
    /// emit only the taken side's instructions.
    pub(super) fn lift_if_else_folded(
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
    pub(super) fn lift_if_else_mux(
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
        let else_compatible = match else_body {
            Some(ast::ElseBranch::Block(b)) => stmts_are_mux_compatible(&b.stmts),
            Some(ast::ElseBranch::IfElse(boxed)) => stmt_is_mux_compatible(boxed),
            None => true,
        };
        if !else_compatible {
            return None;
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
