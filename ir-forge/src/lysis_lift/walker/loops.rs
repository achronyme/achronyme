use super::*;

impl<F: FieldBackend> Walker<F> {
    pub(super) fn emit_loop_unroll(
        &mut self,
        iter_var: SsaVar,
        start: i64,
        end: i64,
        body: &[ExtendedInstruction<F>],
    ) -> Result<(), WalkError> {
        if start < 0 || end < 0 {
            return Err(WalkError::NegativeLoopBound { start, end });
        }

        // When the body (recursively, through nested LoopUnrolls)
        // contains a `SymbolicIndexedEffect` or `SymbolicArrayRead`,
        // the runtime `LoopUnroll` opcode can't carry either — both
        // need a literal `iter_var = i` on every iteration so the
        // walker can const-fold the index. Per-iter unroll the body
        // at walker time. Loops without symbolic ops keep the rolled
        // `LoopUnroll` opcode and InterningSink dedup — the wrapper's
        // value isn't sacrificed for the rest of the program.
        //
        // Also fall back to per-iter unroll when the body is wide
        // enough that a single rolled emission would exhaust the
        // frame cap. Rolled emit allocs sequentially; a body needing
        // >250 slots can't fit even in a fresh-after-split frame.
        // Per-iter unroll engages mid-iter `split_in_per_iter` and
        // chains chunks under cap. SHA-256(64)'s outer round loop
        // (~1779 estimated regs in a single rolled emission) hits
        // this path.
        if body_has_symbolic_op(body) || body_too_wide_for_rolled(body) {
            return self.emit_loop_unroll_per_iter(iter_var, start, end, body);
        }

        let start_u32 = start as u32;
        let end_u32 = end as u32;

        // Eagerize `one` *before* the LoopUnroll opcode if any nested
        // body instruction would need it. This keeps `body_byte_size`
        // accurate (it doesn't model lazy LoadConst emission within
        // the body) — the alternative would be a body-walker that
        // predicts which iterations would trigger the lazy load.
        if self.one_reg.is_none() && body_needs_one_const(body) {
            let _ = self.one()?;
        }

        let iter_reg = self.allocator.alloc()?;
        self.bind(iter_var, iter_reg);

        // Pre-compute the body's encoded byte length so the
        // LoopUnroll opcode can carry it. The size depends only on
        // opcode shape — independent of register allocation — so a
        // free function over the ExtendedInstruction tree suffices.
        let body_len = body_byte_size(body)?;
        if body_len > u32::from(u16::MAX) {
            return Err(WalkError::LoopBodyTooLong { bytes: body_len });
        }

        self.push_op(Opcode::LoopUnroll {
            iter_var: iter_reg,
            start: start_u32,
            end: end_u32,
            body_len: body_len as u16,
        });

        for inst in body {
            self.emit(inst)?;
        }
        Ok(())
    }

    /// Per-iteration walker materialisation for a `LoopUnroll` whose
    /// body contains a `SymbolicIndexedEffect`. Emits N flat
    /// per-iteration body sequences instead of one rolled
    /// `LoopUnroll` opcode, threading `walker_const[iter_var] = i` so
    /// the SymbolicIndexedEffect arm resolves to a literal slot.
    ///
    /// Allocator + ssa_to_reg state is checkpointed before the
    /// iterations and restored before each one, so body-internal
    /// regs get reused across iterations rather than ballooning past
    /// the 255-slot frame cap.
    ///
    /// **Mid-iter split**: when a single iteration's body would
    /// itself overflow the available frame slots, we apply a
    /// `split_in_per_iter` mid-emission, mirroring the top-level
    /// split but with a live set computed against the **whole** body
    /// (because subsequent iterations re-emit `body[0..N]` from the
    /// post-split frame and need every outer SsaVar reference to
    /// remain bound). The split chains a fresh template, body
    /// emission resumes there, and `pre_body_*` snapshots refresh so
    /// the next iteration's restore-and-emit cycle works against the
    /// new frame's state.
    pub(super) fn emit_loop_unroll_per_iter(
        &mut self,
        iter_var: SsaVar,
        start: i64,
        end: i64,
        body: &[ExtendedInstruction<F>],
    ) -> Result<(), WalkError> {
        let start_u32 = start as u32;
        let end_u32 = end as u32;
        if start_u32 >= end_u32 {
            return Ok(());
        }

        // Push iter_var onto the enclosing-loops stack so any nested
        // per-iter unroll inside `body` will force-live this iter_var
        // across its mid-emit splits. Pop after the inner work
        // completes regardless of success/failure (no `?` between push
        // and pop other than via the `_inner` helper, whose result we
        // propagate after popping).
        self.enclosing_iter_vars.push(iter_var);
        let result = self.emit_loop_unroll_per_iter_inner(iter_var, start_u32, end_u32, body);
        self.enclosing_iter_vars.pop();
        result
    }

    pub(super) fn emit_loop_unroll_per_iter_inner(
        &mut self,
        iter_var: SsaVar,
        start_u32: u32,
        end_u32: u32,
        body: &[ExtendedInstruction<F>],
    ) -> Result<(), WalkError> {
        if self.one_reg.is_none() && body_needs_one_const(body) {
            let _ = self.one()?;
        }

        // Allocate iter_var's reg ONCE for the whole per-iter loop.
        // Becomes mutable because mid-iter splits may rebind iter_var
        // to a new capture reg in the post-split frame.
        let mut iter_reg = self.allocator.alloc()?;
        self.bind(iter_var, iter_reg);

        // Snapshot pre-body state. Mutable so a mid-iter split can
        // refresh the snapshot from the post-split frame, letting the
        // next iteration restore-and-re-emit body in the chained
        // template. iter_var is removed from the walker_const snapshot
        // because it's set per-iter anyway.
        let mut pre_body_alloc_ckpt = self.allocator.checkpoint();
        let mut pre_body_bindings = self.ssa_to_reg.clone();
        let mut pre_body_walker_const = self.walker_const.clone();
        pre_body_walker_const.remove(&iter_var);

        // Pre-compute the set of SSA vars *defined* by `body`. Each
        // iteration re-binds these to fresh values, so any heap entry
        // they hold from a prior iter's spill is stale by the time
        // this iter's mid-emit split runs. Without stripping, the
        // dedup branch in `spill_cold_var` would skip the re-spill
        // and `resolve()`'s heap fault-in would forward iter-0's
        // value to every later iter — surfacing as the SymbolicShift
        // / BitAnd / SymbolicIndexedEffect "all 64 LoadHeaps point at
        // one stored value" failure mode. The set is invariant across
        // iters because `body` is the same slice every time, so
        // compute it once outside the loop.
        let body_defined: HashSet<SsaVar> = collect_defined_ssa_vars(body);

        for i in start_u32..end_u32 {
            // Track current at iter start so we can detect any split
            // that fires during this iteration — including splits
            // triggered by NESTED per-iter unrolls inside `body`. A
            // nested split moves `self.current` without setting our
            // local `split_happened_this_iter` flag, so detect via
            // `current_at_iter_start != self.current` instead.
            let current_at_iter_start = self.current;

            self.allocator.restore_to(pre_body_alloc_ckpt);
            self.ssa_to_reg = pre_body_bindings.clone();
            // Strip body-defined SsaVars from `ssa_to_heap` so the
            // next mid-iter split allocates a fresh slot for each
            // (per-iter SSA-after-unroll: each iter's body-defined
            // values are conceptually distinct). Iter-0 sees no such
            // entries yet so this is a no-op there; iter-1+ rolls
            // off iter-0's spilled body-defined slots, leaving
            // outer/external cold spills intact for cheap dedup.
            for v in &body_defined {
                self.ssa_to_heap.remove(v);
            }
            self.bind(iter_var, iter_reg);
            self.walker_const = pre_body_walker_const.clone();
            self.walker_const.insert(iter_var, i64::from(i));

            // Set iter_reg to Const(i) at runtime via LoadConst.
            let const_idx = self
                .builder
                .intern_field(FieldElement::<F>::from_u64(u64::from(i)));
            self.push_op(Opcode::LoadConst {
                dst: iter_reg,
                idx: const_idx,
            });

            for (j, inst) in body.iter().enumerate() {
                if j > 0 {
                    let cost = reg_cost_of_extinst(inst);
                    let cold_loads = cold_load_cost(inst, &self.ssa_to_heap, &self.ssa_to_reg);
                    let projected = self
                        .allocator
                        .next_slot()
                        .saturating_add(cost)
                        .saturating_add(cold_loads);
                    if projected.saturating_add(FRAME_MARGIN) >= FRAME_CAP {
                        self.split_in_per_iter(body, &body_defined)?;
                    }
                }
                self.emit(inst)?;
            }

            if self.current != current_at_iter_start {
                // Either an outer mid-emit split fired (above) or a
                // nested per-iter unroll inside `body` triggered its
                // own split. Either way, `self.current` now points at
                // a fresh chained template. Refresh the per-iter
                // snapshots so the NEXT iteration restores from this
                // frame's state instead of the now-invalid parent
                // state. iter_var was force-live across the split, so
                // its rebound reg (a capture slot) is in `ssa_to_reg`;
                // track it as the new `iter_reg` for upcoming
                // LoadConst writes.
                iter_reg = self
                    .ssa_to_reg
                    .get(&iter_var)
                    .copied()
                    .ok_or(WalkError::UndefinedSsaVar(iter_var))?;
                pre_body_alloc_ckpt = self.allocator.checkpoint();
                pre_body_bindings = self.ssa_to_reg.clone();
                pre_body_walker_const = self.walker_const.clone();
                pre_body_walker_const.remove(&iter_var);
            }
        }

        // Don't leak per-iter walker_const[iter_var] past the loop.
        self.walker_const.remove(&iter_var);
        Ok(())
    }
}
