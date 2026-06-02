use std::collections::BTreeSet;

use artik::{ElemT, Reg};

use crate::ast::{self, Expr};

use super::super::helpers::{
    collect_mutated_scalars, eval_const_expr, stmt_is_mux_compatible, stmts_are_mux_compatible,
    stmts_have_return,
};
use super::super::{ArrayShape, LiftState};
use super::predicates::is_field_lt_zero_pattern;

/// One pre-branch-tracked 1D array that an if/else arm rebinds via a
/// whole-array assignment (`name = call(...)`). The arm-selected
/// handle is stashed in `hslot` (a 1-cell IntU32 heap slot) as its
/// handle id, then reconstructed post-branch — the array analogue of
/// the scalar slot merge, but O(1) in the array length: only the
/// handle id crosses the branch, never the cells. `then_rebinds` /
/// `else_rebinds` record which arms rebind it so only those arms
/// stash, and pre-init is skipped when every runtime path overwrites
/// it anyway.
struct ArrayMergeSlot {
    name: String,
    src_handle: Reg,
    len: u32,
    hslot: Reg,
    then_rebinds: bool,
    else_rebinds: bool,
}

impl<'f> LiftState<'f> {
    /// Stash the arm's current array handle id into its heap slot,
    /// for the arms that rebind it. Emitted inside the arm's gated
    /// region so only the taken arm's stash runs at runtime; an arm
    /// that does not rebind the array leaves the slot holding the
    /// pre-init / other-arm id.
    fn stash_arm_array_handles(&mut self, slots: &[ArrayMergeSlot], then_side: bool) -> Option<()> {
        for slot in slots {
            let rebinds = if then_side {
                slot.then_rebinds
            } else {
                slot.else_rebinds
            };
            if !rebinds {
                continue;
            }
            if let Some(ArrayShape::Flat1D { handle, .. }) = self.arrays.get(&slot.name).copied() {
                let id = self.builder.array_id(handle);
                let idx0 = self.push_int_const(0)?;
                self.builder.store_arr(slot.hslot, idx0, id);
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
    pub(in super::super) fn lift_if_else(
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
    pub(in super::super) fn lift_if_else_branching(
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
            None => super::super::helpers::MutationSummary::default(),
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

        // Whole-array rebind reconciliation. `name = call(...)` where
        // `name` is a tracked array lands in `*_summary.scalars` (the
        // mutation summarizer has no type info) and is excluded from
        // `merge_names` by `is_array_name`. Such a rebind repoints
        // `self.arrays[name]` at a fresh handle inside the arm; since
        // `self.arrays` is not part of the scalar slot merge, the
        // post-branch view would statically resolve to whichever arm
        // was lifted last regardless of which arm runs. Reconcile each
        // pre-branch-tracked 1D array an arm rebinds via a 1-cell heap
        // slot holding the runtime-selected handle id. 2D rebinds and
        // names that are only a fresh in-arm decl (no pre-branch
        // shape) stay on the legacy pass-through path unchanged.
        let else_present = else_body.is_some();
        let mut array_merge: Vec<ArrayMergeSlot> = Vec::new();
        {
            let mut seen: BTreeSet<String> = BTreeSet::new();
            for n in then_summary
                .scalars
                .iter()
                .chain(else_summary.scalars.iter())
            {
                if !is_array_name(n) || !seen.insert(n.clone()) {
                    continue;
                }
                if let Some(ArrayShape::Flat1D { handle, len }) = self.arrays.get(n).copied() {
                    array_merge.push(ArrayMergeSlot {
                        name: n.clone(),
                        src_handle: handle,
                        len,
                        hslot: handle, // placeholder; real slot allocated below
                        then_rebinds: then_summary.scalars.contains(n),
                        else_rebinds: else_present && else_summary.scalars.contains(n),
                    });
                }
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

        // One IntU32 heap slot per rebound array, holding the chosen
        // handle id. Pre-init from the pre-branch handle is emitted
        // only when some runtime path does NOT rebind the array (a
        // single-`if`, or a 2-arm if where one arm leaves it
        // untouched) — that path must observe the pre-branch handle.
        // When every path rebinds it, pre-init is dead and skipped.
        // The stash/reconstruct is O(1) in the array length, so this
        // stays off the frame budget even inside unrolled bigint
        // loops where these rebind-ifs recur.
        for slot in &mut array_merge {
            let hslot = self.builder.alloc_array(1, ElemT::IntU32);
            let every_path_rebinds = slot.then_rebinds && else_present && slot.else_rebinds;
            if !every_path_rebinds {
                let id = self.builder.array_id(slot.src_handle);
                let idx0 = self.push_int_const(0)?;
                self.builder.store_arr(hslot, idx0, id);
            }
            slot.hslot = hslot;
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
        self.stash_arm_array_handles(&array_merge, true)?;
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
        // `else_rebinds` is false for every slot when there is no
        // else, so the helper stashes nothing on a no-else
        // fall-through — the slot keeps its pre-init id, which the
        // not-taken path must preserve.
        self.stash_arm_array_handles(&array_merge, false)?;

        self.builder.place(end_label);

        // Restore state and re-install the merged scalars from slots.
        self.locals = pre_locals;
        self.const_locals = pre_const_locals;
        self.halted = saved_halted;
        for (name, slot) in slots {
            let reg = self.load_field_slot(slot)?;
            self.locals.insert(name, reg);
        }
        // Reconstruct each rebound array from the runtime-selected
        // handle id so post-branch reads resolve to the arm that
        // actually ran.
        for slot in array_merge {
            let idx0 = self.push_int_const(0)?;
            let id = self.builder.load_arr(slot.hslot, idx0);
            let handle = self.builder.array_from_id(id, ElemT::Field);
            self.arrays.insert(
                slot.name,
                ArrayShape::Flat1D {
                    handle,
                    len: slot.len,
                },
            );
        }

        Some(())
    }
}
