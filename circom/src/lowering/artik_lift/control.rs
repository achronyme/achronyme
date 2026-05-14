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
    collect_array_decls, collect_mutated_scalars, eval_const_expr, is_decrement_on,
    is_increment_on, stmt_is_mux_compatible, stmts_are_mux_compatible, stmts_have_return,
};
use super::{ConstInt, LiftState};

impl<'f> LiftState<'f> {
    /// Top-level `for` dispatcher. Tries the unroll path first; if
    /// the unroll would emit more registers than the executor's
    /// frame-size cap can hold, rolls back the builder and falls
    /// through to the runtime-while path. Bounds that don't fold
    /// compile-time also fall through to runtime.
    ///
    /// The rollback is the tricky bit: a partial unroll attempt
    /// leaves instructions and register allocations in the builder,
    /// and the runtime path would emit its own loop on top of that
    /// junk. The dispatch snapshots the builder state before the
    /// unroll and restores on bail.
    pub(super) fn lift_for_dispatch(
        &mut self,
        init: &Stmt,
        condition: &Expr,
        step: &Stmt,
        body: &[Stmt],
    ) -> Option<()> {
        let snapshot = self.builder.snapshot();
        let saved_locals = self.locals.clone();
        let saved_const_locals = self.const_locals.clone();
        let saved_arrays = self.arrays.clone();
        if let Some(()) = self.lift_for_unrolled(init, condition, step, body) {
            return Some(());
        }
        // Unroll either bailed structurally or grew the frame past
        // the cap. Restore the snapshot so the runtime emit starts
        // from a clean slate.
        self.builder.restore(snapshot);
        self.locals = saved_locals;
        self.const_locals = saved_const_locals;
        self.arrays = saved_arrays;
        self.lift_for_runtime(init, condition, step, body)
    }

    /// Unroll a for loop at lift time. Loops with literal bounds and
    /// either a unit-increment (`++` / `+= 1`) ascending step or a
    /// unit-decrement (`--` / `-= 1`) descending step are supported.
    /// The loop variable is tracked as a `ConstInt` in `const_locals`
    /// for the duration of each body invocation; compile-time
    /// references to it fold to `PushConst`.
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

        // Step direction: ascending (`++` / `+= 1`) or descending
        // (`--` / `-= 1`). Determined first so the condition arm
        // below can pair correctly.
        enum Direction {
            Ascending,
            Descending,
        }
        let direction = match step {
            Stmt::Expr { expr, .. } => {
                if is_increment_on(expr, &var_name) {
                    Direction::Ascending
                } else if is_decrement_on(expr, &var_name) {
                    Direction::Descending
                } else {
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
                if eval_const_expr(value, &self.const_locals)? != 1 {
                    return None;
                }
                match op {
                    CompoundOp::Add => Direction::Ascending,
                    CompoundOp::Sub => Direction::Descending,
                    _ => return None,
                }
            }
            _ => return None,
        };

        // Condition shape pairs with direction:
        //   ascending  + `<var> < B`  → `start..B`
        //   ascending  + `<var> <= B` → `start..=B` (i.e. `B+1` exclusive)
        //   descending + `<var> > B`  → iterate `start..B` reversed (B exclusive lower bound)
        //   descending + `<var> >= B` → iterate `start..=B` reversed
        let (lo, hi_exclusive) = match condition {
            Expr::BinOp { op, lhs, rhs, .. } => {
                let Expr::Ident { name, .. } = lhs.as_ref() else {
                    return None;
                };
                if name != &var_name {
                    return None;
                }
                let bound = eval_const_expr(rhs, &self.const_locals)?;
                match (&direction, op) {
                    (Direction::Ascending, BinOp::Lt) => (start, bound),
                    (Direction::Ascending, BinOp::Le) => (start, bound + 1),
                    (Direction::Descending, BinOp::Gt) => (bound + 1, start + 1),
                    (Direction::Descending, BinOp::Ge) => (bound, start + 1),
                    _ => return None,
                }
            }
            _ => return None,
        };

        // Cheap bound on unroll work: the executor's frame size is
        // capped at MAX_FRAME_SIZE (65536 regs); each body iteration
        // can touch several registers. Reject loops beyond a safe
        // ceiling so a hostile circom source can't force the lift to
        // allocate a huge Artik body up front.
        let iterations = hi_exclusive.saturating_sub(lo);
        if !(0..=4096).contains(&iterations) {
            return None;
        }

        // Unroll. Iteration order follows the step direction so the
        // body sees the loop variable monotonically — required for
        // `var pieces[100][100]` patterns where prior iterations
        // populate cells the current iteration reads.
        let prev = self.const_locals.insert(var_name.clone(), start);
        let iter: Box<dyn Iterator<Item = ConstInt>> = match direction {
            Direction::Ascending => Box::new(lo..hi_exclusive),
            Direction::Descending => Box::new((lo..hi_exclusive).rev()),
        };
        // Frame-size budget: the executor caps each program at
        // `MAX_FRAME_SIZE = 65536` registers. A heavy unroll that
        // inlines large callees per iter (e.g. `mod_exp`'s outer
        // loop calling `prod` and `long_div`) blows past this in
        // tens of iterations. Bail early once the running register
        // count crosses 90 % of the cap so the dispatcher can roll
        // back and retry via the runtime-while path.
        const FRAME_BUDGET: u32 = 60_000;
        for i in iter {
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
            if self.builder.next_reg() > FRAME_BUDGET {
                return None;
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

        // Mux-style merge requires both arms to be free of side effects
        // beyond scalar local updates: no `return`, no array writes, no
        // witness writes. Anything else routes through the conditional
        // branching path, which evaluates exactly one arm at runtime via
        // `JumpIf`. The branching path's locals merge is narrow (only
        // both-fall-through-with-no-scalar-modification or one-halts
        // shapes are handled), so cases that need a richer merge bail
        // back to E212.
        let then_mux_ok = stmts_are_mux_compatible(&then_body.stmts);
        let else_mux_ok = match else_body {
            Some(ast::ElseBranch::Block(b)) => stmts_are_mux_compatible(&b.stmts),
            Some(ast::ElseBranch::IfElse(boxed)) => stmt_is_mux_compatible(boxed),
            None => true,
        };
        if then_mux_ok && else_mux_ok {
            return self.lift_if_else_mux(condition, then_body, else_body);
        }
        self.lift_if_else_branching(condition, then_body, else_body)
    }

    /// Top-level dispatcher for the conditional-jump path. Routes to
    /// the slot-promotion merge when both arms fall through (the
    /// general "scalars updated in either arm" shape) and to the
    /// narrow single-side merge when one arm halts via `return`
    /// (slot-merge can't represent a halt without observing both
    /// arms first).
    pub(super) fn lift_if_else_branching(
        &mut self,
        condition: &Expr,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        let then_returns = stmts_have_return(&then_body.stmts);
        let else_returns = match else_body {
            Some(ast::ElseBranch::Block(b)) => stmts_have_return(&b.stmts),
            Some(ast::ElseBranch::IfElse(boxed)) => {
                stmts_have_return(std::slice::from_ref(boxed.as_ref()))
            }
            None => false,
        };
        if then_returns || else_returns {
            return self.lift_if_else_branching_narrow(condition, then_body, else_body);
        }
        self.lift_if_else_branching_slot_merge(condition, then_body, else_body)
    }

    /// Real conditional-jump if/else. Used when at least one arm
    /// `return`s — the slot-promotion merge can't represent a halt.
    /// Locals merging is intentionally narrow: at most one arm may
    /// modify locals, and in the both-fall-through case neither arm
    /// may touch locals. The shape covers circomlib's sqrt early-exit
    /// pattern (`if (cond) return 0;`) without forcing a general
    /// SSA-merge implementation.
    fn lift_if_else_branching_narrow(
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

    /// General-shape conditional-jump if/else for the both-arms-fall-
    /// through case. Promotes every scalar that either arm assigns to
    /// a 1-element heap slot, pre-initialised from the pre-branch
    /// register (or 0 for variables introduced inside the arms);
    /// after each arm's body completes, the lift stores the arm's
    /// current register for that scalar back into the slot. Post-
    /// branch, every merged name is reloaded into `self.locals` from
    /// its slot. The branching emission guarantees only one arm runs
    /// at runtime, so guarded operations like `if (x != 0) y = a \ x`
    /// stay safe — the not-taken arm's bytecode is still emitted but
    /// never executed.
    fn lift_if_else_branching_slot_merge(
        &mut self,
        condition: &Expr,
        then_body: &ast::Block,
        else_body: Option<&ast::ElseBranch>,
    ) -> Option<()> {
        let then_summary = collect_mutated_scalars(&then_body.stmts);
        let else_summary = match else_body {
            Some(ast::ElseBranch::Block(b)) => collect_mutated_scalars(&b.stmts),
            Some(ast::ElseBranch::IfElse(boxed)) => {
                collect_mutated_scalars(std::slice::from_ref(boxed.as_ref()))
            }
            None => super::helpers::MutationSummary::default(),
        };

        if then_summary.writes_witness || else_summary.writes_witness {
            return None;
        }
        // Array writes against names that already live on the heap
        // (declared and tracked in `self.arrays` pre-branch) persist
        // through the slot merge naturally — `StoreArr` writes
        // straight to the heap and is gated by the JumpIf. Writes
        // against unknown names mean the arm is referencing an array
        // we don't track; reject conservatively. Fresh array decls
        // produced inside an arm don't need to be tracked here — the
        // arm's own `VarDecl` emits the `AllocArray` and registers
        // the name in `self.arrays` before the write is lifted.
        let arm_array_decls: std::collections::HashSet<&String> = then_summary
            .fresh_array_decls
            .iter()
            .chain(else_summary.fresh_array_decls.iter())
            .collect();
        for name in then_summary
            .array_writes
            .iter()
            .chain(else_summary.array_writes.iter())
        {
            if !self.arrays.contains_key(name) && !arm_array_decls.contains(name) {
                return None;
            }
        }

        // Only true scalars need slot merging. `collect_mutated_scalars`
        // reports every `Ident = ...` substitution under `scalars`,
        // including the whole-array-rebind case `arr = call(...)` where
        // `arr` was declared with dimensions. Those targets live in
        // `self.arrays`, not `self.locals`, so a slot would be wrong.
        // Filter against the pre-branch array map and the in-arm
        // fresh-array decls to keep the merge scalar-only.
        let is_array_name = |n: &str| -> bool {
            self.arrays.contains_key(n) || arm_array_decls.contains(&n.to_string())
        };
        // Demoting a const_local to runtime inside an arm would leave
        // the post-merge view ambiguous — the runtime-merged register
        // we install for `name` doesn't carry the compile-time value
        // forward. Bail in that case so the parent lift can choose a
        // different shape.
        if then_summary
            .scalars
            .iter()
            .chain(else_summary.scalars.iter())
            .filter(|n| !is_array_name(n))
            .any(|n| self.const_locals.contains_key(n))
        {
            return None;
        }

        let mut merge_names: BTreeSet<String> = BTreeSet::new();
        for n in &then_summary.scalars {
            if !is_array_name(n) {
                merge_names.insert(n.clone());
            }
        }
        for n in &else_summary.scalars {
            if !is_array_name(n) {
                merge_names.insert(n.clone());
            }
        }

        // Pre-allocate the slot for every merged scalar. The fall-back
        // value is the pre-branch register if the local was already
        // bound, or a freshly-pushed 0 otherwise (covers `var y;` +
        // assignments inside arms, where the AST decl is a no-op for
        // the lift's locals map).
        let zero_reg = self.push_const_unsigned(0)?;
        let mut slots: Vec<(String, Reg)> = Vec::with_capacity(merge_names.len());
        for name in &merge_names {
            let slot = self.alloc_field_slot();
            let initial = self.locals.get(name).copied().unwrap_or(zero_reg);
            self.store_field_slot(slot, initial)?;
            slots.push((name.clone(), slot));
        }

        let cond_reg = self.lift_expr(condition)?;
        let zero = self.push_const_unsigned(0)?;
        let is_zero_int = self.builder.feq(cond_reg, zero);

        let skip_label = self.builder.new_label();
        let end_label = self.builder.new_label();

        self.builder.jump_if_to(is_zero_int, skip_label);

        let pre_locals = self.locals.clone();
        let pre_const_locals = self.const_locals.clone();

        // Then-arm.
        let saved_halted = self.halted;
        self.halted = false;
        for stmt in &then_body.stmts {
            self.lift_stmt(stmt)?;
            if self.halted {
                break;
            }
        }
        if self.halted {
            // Inlined nested calls restore `halted` to the outer
            // value, so the only way to land here is an AST-level
            // Return in the arm — which the dispatcher already
            // routed away from slot-merge. Defensive bail.
            return None;
        }
        for (name, slot) in &slots {
            if let Some(reg) = self.locals.get(name).copied() {
                self.store_field_slot(*slot, reg)?;
            }
        }
        self.builder.jump_to(end_label);

        // Reset state for the else-arm.
        self.locals = pre_locals.clone();
        self.const_locals = pre_const_locals.clone();
        self.halted = false;

        self.builder.place(skip_label);

        match else_body {
            Some(ast::ElseBranch::Block(b)) => {
                for stmt in &b.stmts {
                    self.lift_stmt(stmt)?;
                    if self.halted {
                        break;
                    }
                }
            }
            Some(ast::ElseBranch::IfElse(boxed)) => {
                self.lift_stmt(boxed)?;
            }
            None => {}
        }
        if self.halted {
            return None;
        }
        for (name, slot) in &slots {
            if let Some(reg) = self.locals.get(name).copied() {
                self.store_field_slot(*slot, reg)?;
            }
        }

        self.builder.place(end_label);

        // Restore state and re-install the merged scalars from slots.
        self.locals = pre_locals;
        self.const_locals = pre_const_locals;
        self.halted = saved_halted;
        for (name, slot) in slots {
            let reg = self.load_field_slot(slot)?;
            self.locals.insert(name, reg);
        }

        Some(())
    }

    /// Emit a `while` as `place(start); cond; jump_if_zero end; body;
    /// jump start; place(end);`. Mutable scalars whose values must
    /// flow across iterations are promoted to 1-element heap slots —
    /// reload at top, store at tail.
    pub(super) fn lift_while(&mut self, condition: &Expr, body: &[Stmt]) -> Option<()> {
        let summary = collect_mutated_scalars(body);

        if summary.writes_witness {
            return None;
        }
        if stmts_have_return(body) {
            return None;
        }

        // Hoist `var arr[N]` declarations out of the loop body. The
        // body's `temp = call(...)` rebinds via call-return on every
        // iteration, so the alloc itself is wasted work — but emitted
        // per-iter under a runtime while it accumulates fresh
        // allocations and the heap explodes. Pre-allocate once before
        // the loop_start label, register names in `arrays`, and mark
        // each as hoisted; the body's VarDecl handler then skips the
        // re-allocation. Required by `mod_exp`'s pattern of declaring
        // `var temp[200]` and `var temp2[2][100]` inside if-blocks.
        let mut newly_hoisted: Vec<String> = Vec::new();
        if summary.declares_array {
            let mut decls: Vec<&Stmt> = Vec::new();
            collect_array_decls(body, &mut decls);
            // Dedupe by name: the same `var temp[200]` may be declared
            // in several branches (e.g. mod_exp's two if-blocks both
            // declare it). Allocate once for the first occurrence and
            // skip the rest.
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for decl in decls {
                let Stmt::VarDecl { names, .. } = decl else {
                    continue;
                };
                let Some(n) = names.first() else { continue };
                if !seen.insert(n.clone()) {
                    continue;
                }
                self.lift_stmt(decl)?;
                if let Some(shape) = self.arrays.get(n).copied() {
                    self.hoisted_arrays.insert(n.clone(), shape);
                    newly_hoisted.push(n.clone());
                }
            }
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

        let lift_result: Option<()> = (|| {
            for stmt in body {
                self.lift_stmt(stmt)?;
                if self.halted {
                    return None;
                }
            }
            Some(())
        })();

        // Drop hoisted entries before propagating an outer error so the
        // enclosing scope doesn't see leaked bindings. Restoring the
        // declared shape into `arrays` here would mask later live-shape
        // queries; leaving the rebound shape is fine because the next
        // iteration's hoisted-skip check consults `hoisted_arrays`,
        // not `arrays`, for its size match.
        for n in &newly_hoisted {
            self.hoisted_arrays.remove(n);
        }
        lift_result?;

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
