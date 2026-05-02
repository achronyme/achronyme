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
    collect_mutated_scalars, eval_const_expr, is_increment_on, stmt_is_mux_compatible,
    stmts_are_mux_compatible, stmts_have_return,
};
use super::{ConstInt, LiftState};

impl<'f> LiftState<'f> {
    /// Top-level `for` dispatcher. Tries the unroll path first; if
    /// the bounds aren't compile-time-foldable, falls back to a real
    /// loop emitted as `init; while (cond) { body; step; }`.
    pub(super) fn lift_for_dispatch(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        if let Some(()) = self.lift_for_unrolled(init, condition, step, body) {
            return Some(());
        }
        self.lift_for_runtime(init, condition, step, body)
    }

    /// Unroll a for loop at lift time. Only loops with literal bounds
    /// and a `++` / `+= 1` step over a freshly declared integer loop
    /// variable are supported. The loop variable is tracked as a
    /// `ConstInt` in `const_locals` for the duration of each body
    /// invocation; compile-time references to it fold to `PushConst`.
    pub(super) fn lift_for_unrolled(
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
    /// conditions dispatch to either [`lift_if_else_mux`] (branchless
    /// merge for side-effect-free arms) or
    /// [`lift_if_else_branching`] (real conditional jump for arms with
    /// `return`).
    pub(super) fn lift_if_else(
        &mut self,
        condition: &Expr,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        if let Some(cond) = eval_const_expr(condition, &self.const_locals) {
            return self.lift_if_else_folded(cond, then_body, else_body);
        }
        // `field_value < 0` is unreachable in field semantics — every
        // residue lives in `[0, p)` and `< 0` against a runtime field
        // value is dead code. Fold it to constant-false so the
        // surrounding if doesn't drag in a comparison the lift can't
        // safely emit.
        if is_field_lt_zero_pattern(condition) {
            return self.lift_if_else_folded(0, then_body, else_body);
        }

        let then_returns = stmts_have_return(&then_body.stmts);
        let else_returns = match else_body {
            Some(ast::ElseBranch::Block(b)) => stmts_have_return(&b.stmts),
            Some(ast::ElseBranch::IfElse(boxed)) => super::helpers::stmt_has_return(boxed),
            None => false,
        };
        if then_returns || else_returns {
            return self.lift_if_else_branching(condition, then_body, else_body);
        }
        self.lift_if_else_mux(condition, then_body, else_body)
    }

    /// Real conditional-jump if/else. Used when at least one arm
    /// `return`s — the mux merge can't represent a halt. Locals
    /// merging is intentionally narrow: at most one arm may modify
    /// locals, and in the both-fall-through case neither arm may
    /// touch locals. The shape covers circomlib's sqrt early-exit
    /// pattern (`if (cond) return 0;`) without forcing a general
    /// SSA-merge implementation.
    pub(super) fn lift_if_else_branching(
        &mut self,
        condition: &Expr,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        let cond_reg = self.lift_expr(condition)?;
        let zero = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(cond_reg, zero);

        let skip_label = self.builder.new_label();
        let end_label = self.builder.new_label();

        // Branch to skip when cond is false (is_zero_int == 1).
        self.builder.jump_if_to(is_zero_int, skip_label);

        let pre_locals = self.locals.clone();
        let pre_const_locals = self.const_locals.clone();

        // Then arm.
        let saved_halted = self.halted;
        self.halted = false;
        for stmt in &then_body.stmts {
            self.lift_stmt(stmt)?;
            if self.halted {
                break;
            }
        }
        let then_halted = self.halted;
        let then_locals = std::mem::replace(&mut self.locals, pre_locals.clone());
        let then_const_locals = std::mem::replace(&mut self.const_locals, pre_const_locals.clone());

        if !then_halted {
            self.builder.jump_to(end_label);
        }

        self.builder.place(skip_label);

        // Else arm.
        self.halted = false;
        let mut else_halted = false;
        match else_body {
            Some(ast::ElseBranch::Block(b)) => {
                for stmt in &b.stmts {
                    self.lift_stmt(stmt)?;
                    if self.halted {
                        break;
                    }
                }
                else_halted = self.halted;
            }
            Some(ast::ElseBranch::IfElse(boxed)) => {
                self.lift_stmt(boxed)?;
                else_halted = self.halted;
            }
            None => {}
        }
        let else_locals = std::mem::replace(&mut self.locals, pre_locals.clone());
        let else_const_locals = std::mem::replace(&mut self.const_locals, pre_const_locals.clone());

        self.builder.place(end_label);

        // const_locals must agree on both arms — the lift's loop
        // unroll path keys off compile-time entries, and a divergent
        // const view post-merge is undefined.
        if then_const_locals != pre_const_locals && !then_halted {
            return None;
        }
        if else_const_locals != pre_const_locals && !else_halted {
            return None;
        }

        self.halted = saved_halted || (then_halted && else_halted);
        if self.halted {
            return Some(());
        }

        let then_modified = then_locals != pre_locals;
        let else_modified = else_locals != pre_locals;

        self.locals = match (then_halted, else_halted) {
            (true, false) => else_locals,
            (false, true) => then_locals,
            (false, false) => {
                if !then_modified && !else_modified {
                    pre_locals
                } else {
                    return None;
                }
            }
            (true, true) => unreachable!("handled by halted check above"),
        };
        self.const_locals = pre_const_locals;
        Some(())
    }

    /// Emit a `while` as `place(start); cond; jump_if_zero end; body;
    /// jump start; place(end);`. Mutable scalars whose values must
    /// flow across iterations are promoted to 1-element heap slots —
    /// reload at top, store at tail.
    pub(super) fn lift_while(&mut self, condition: &Expr, body: &[Stmt]) -> Option<()> {
        let summary = collect_mutated_scalars(body);

        if summary.declares_array || summary.writes_witness {
            return None;
        }
        if stmts_have_return(body) {
            return None;
        }

        let mut promoted: Vec<(String, Reg)> = Vec::new();
        for name in &summary.scalars {
            if summary.fresh_decls.contains(name) {
                continue;
            }
            if self.const_locals.contains_key(name) {
                return None;
            }
            if let Some(initial) = self.locals.get(name).copied() {
                let slot = self.alloc_field_slot();
                self.store_field_slot(slot, initial)?;
                promoted.push((name.clone(), slot));
            }
        }

        let loop_start = self.builder.new_label();
        let loop_end = self.builder.new_label();

        self.builder.place(loop_start);

        for (name, slot) in &promoted {
            let reg = self.load_field_slot(*slot)?;
            self.locals.insert(name.clone(), reg);
        }

        let cond_reg = self.lift_expr(condition)?;
        let zero = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(cond_reg, zero);
        self.builder.jump_if_to(is_zero_int, loop_end);

        for stmt in body {
            self.lift_stmt(stmt)?;
            if self.halted {
                return None;
            }
        }

        for (name, slot) in &promoted {
            let cur = self.locals.get(name).copied()?;
            self.store_field_slot(*slot, cur)?;
        }

        self.builder.jump_to(loop_start);
        self.builder.place(loop_end);

        for (name, slot) in &promoted {
            let reg = self.load_field_slot(*slot)?;
            self.locals.insert(name.clone(), reg);
        }

        Some(())
    }

    /// Runtime fallback for `for` when the bounds are not literal:
    /// emit `init`, then a `while (cond)` whose body is `body; step;`.
    pub(super) fn lift_for_runtime(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        self.lift_stmt(init)?;
        let mut combined: Vec<Stmt> = body.to_vec();
        combined.push(step.clone());
        self.lift_while(condition, &combined)
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

/// Detect `<expr> < 0` / `0 > <expr>` against a literal `0`. The
/// canonical residue of any field value is `>= 0`, so the comparison
/// is dead code in the witness program. Folding it here keeps the
/// surrounding `if` lift from having to emit a field-`<` op the VM
/// doesn't natively support.
fn is_field_lt_zero_pattern(expr: &Expr) -> bool {
    match expr {
        Expr::BinOp {
            op: BinOp::Lt, rhs, ..
        } => is_literal_zero(rhs),
        Expr::BinOp {
            op: BinOp::Gt, lhs, ..
        } => is_literal_zero(lhs),
        _ => false,
    }
}

fn is_literal_zero(expr: &Expr) -> bool {
    match expr {
        Expr::Number { value, .. } => value == "0",
        Expr::HexNumber { value, .. } => {
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            trimmed.bytes().all(|b| b == b'0')
        }
        _ => false,
    }
}
