use super::*;

impl<F: FieldBackend> Walker<F> {
    // ---------- witness call ----------
    // Intern the Artik bytecode blob, resolve input regs,
    // allocate fresh output destinations, and emit.
    //
    // Two emit paths, chosen by a dual guard:
    //
    //  - **Classic** (`EmitWitnessCall`): each output gets a
    //    fresh contiguous register; reg-allocator is
    //    bump-forward. Taken only when the call is both
    //    structurally small (outputs <=
    //    `MAX_WITNESS_OUTPUTS_INLINE`) AND its outputs
    //    provably fit the *current* frame.
    //
    //  - **Heap** (`EmitWitnessCallHeap`): outputs go to
    //    fresh heap slots (zero frame registers); downstream
    //    reads materialise via `LoadHeap` through
    //    `Walker::resolve`'s lazy-reload path. Taken when
    //    either guard trips:
    //      * a structurally wide call (outputs >
    //        `MAX_WITNESS_OUTPUTS_INLINE`) - e.g. SHA-256's
    //        256-output hash; or
    //      * an otherwise-inline-eligible call whose
    //        `outputs.len()` would not fit the slots left in
    //        the current frame. A single `WitnessCall` is
    //        atomic - the split machinery chains templates
    //        *between* instructions, never *within* one - so
    //        an inline call that does not fit cannot be
    //        rescued by a split. The heap path always fits
    //        (zero frame regs) and is the correct fallback;
    //        the static threshold alone is unsound because a
    //        nested/multi-instruction template can enter this
    //        call with the frame already near `FRAME_CAP`
    //        (the bigint helper return shape `[2][100]` =
    //        200 outputs lands exactly at the static bound).
    pub(super) fn emit_witness_call(
        &mut self,
        call: &ir_core::WitnessCallBody,
    ) -> Result<(), WalkError> {
        let outputs = &call.outputs;
        let inputs = &call.inputs;
        let program_bytes = &call.program_bytes;
        let blob_idx = self.builder.intern_artik_bytecode(program_bytes.clone());

        // Mirrors the pre-emit split predicate, but for the
        // *classic* register-output path's full frame cost.
        // That path allocates one fresh reg per output AND,
        // via `resolve()`, one fresh reg per cold input - an
        // input in `ssa_to_heap` but not `ssa_to_reg`, faulted
        // back into the frame with a `LoadHeap` (a preceding
        // split that spills this call's own inputs is exactly
        // what makes them cold). The call is only safe inline
        // when `next_slot + outputs + cold_inputs + margin`
        // stays under the cap; otherwise route to the
        // always-fitting heap path, where inputs become
        // `InputSrc::Slot`/`Reg` and outputs go to heap slots
        // (zero frame regs). A single WitnessCall is atomic
        // and cannot be split across frames, so a split cannot
        // rescue an inline call that does not fit.
        //
        // `cold_inputs` counts occurrences, so a repeated cold
        // input is counted more than once even though the
        // classic loop allocates it only once (the first
        // `resolve` binds it into `ssa_to_reg`; later dups hit
        // the fast path). That only over-estimates the classic
        // cost and can over-route to the always-correct heap
        // path - never unsafe. Do not de-dup it.
        let cold_inputs = inputs
            .iter()
            .filter(|v| !self.ssa_to_reg.contains_key(v) && self.ssa_to_heap.contains_key(v))
            .count() as u32;
        let classic_cost = (outputs.len() as u32).saturating_add(cold_inputs);
        let inline_would_overflow = self
            .allocator
            .next_slot()
            .saturating_add(classic_cost)
            .saturating_add(FRAME_MARGIN)
            >= FRAME_CAP;
        if outputs.len() > MAX_WITNESS_OUTPUTS_INLINE || inline_would_overflow {
            // Heap-output path: classify each input into
            // `InputSrc::Reg(reg)` (already in `ssa_to_reg`,
            // hot) or `InputSrc::Slot(slot)` (already in
            // `ssa_to_heap`, cold). NO `LoadHeap` is emitted
            // for cold inputs - the executor reads them
            // directly from `heap[slot]`. This is what makes
            // SHA-256-class circuits compilable: an Artik
            // call with 700+ inputs and 256 outputs would
            // otherwise need 700 LoadHeap + 256 fresh regs,
            // overflowing the 255 frame cap on a single
            // instruction.
            let mut classified_inputs: Vec<lysis::InputSrc> = Vec::with_capacity(inputs.len());
            for v in inputs {
                if let Some(&reg) = self.ssa_to_reg.get(v) {
                    classified_inputs.push(lysis::InputSrc::Reg(reg));
                } else if let Some(&slot) = self.ssa_to_heap.get(v) {
                    classified_inputs.push(lysis::InputSrc::Slot(slot));
                } else {
                    return Err(WalkError::UndefinedSsaVar(*v));
                }
            }
            // Each output binds to a fresh heap slot,
            // recorded in `ssa_to_heap`. Downstream consumers
            // pull via `Walker::resolve` lazy-reload (LoadHeap
            // emit) or, if they're another WitnessCallHeap,
            // directly through this same Slot classification.
            let mut out_slots: Vec<u32> = Vec::with_capacity(outputs.len());
            for o in outputs {
                let slot = self.heap_alloc;
                self.heap_alloc = self.heap_alloc.saturating_add(1);
                self.ssa_to_heap.insert(*o, slot);
                out_slots.push(slot);
            }
            self.push_op(Opcode::EmitWitnessCallHeap {
                bytecode_const_idx: blob_idx,
                inputs: Box::new(classified_inputs),
                out_slots: Box::new(out_slots),
            });
        } else {
            // Classic register-output path: resolve every
            // input into a frame reg (LoadHeap emitted for
            // cold inputs via `resolve`).
            let in_regs: Vec<RegId> = inputs
                .iter()
                .map(|v| self.resolve(*v))
                .collect::<Result<_, _>>()?;
            let mut out_regs: Vec<RegId> = Vec::with_capacity(outputs.len());
            for o in outputs {
                let reg = self.allocator.alloc()?;
                out_regs.push(reg);
                self.bind(*o, reg);
            }
            self.push_op(Opcode::EmitWitnessCall {
                bytecode_const_idx: blob_idx,
                in_regs: Box::new(in_regs),
                out_regs: Box::new(out_regs),
            });
        }

        Ok(())
    }
}
