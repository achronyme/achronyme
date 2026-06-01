use super::*;

impl<F: FieldBackend> Walker<F> {
    // NOTE: >500 LOC justified because emit_plain is one cohesive instruction-dispatch match; splitting arms would obscure parity in this mechanical move.
    pub(super) fn emit_plain(&mut self, inst: &Instruction<F>) -> Result<(), WalkError> {
        match inst {
            Instruction::Const { result, value } => {
                let idx = self.builder.intern_field(*value);
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::LoadConst { dst, idx });
                self.bind(*result, dst);
                if let Some(v) = field_to_i64(value) {
                    self.walker_const.insert(*result, v);
                }
            }
            Instruction::Input {
                result,
                name,
                visibility,
            } => {
                let name_idx = self.builder.intern_string(name.clone());
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::LoadInput {
                    dst,
                    name_idx,
                    vis: map_vis(*visibility),
                });
                self.bind(*result, dst);
            }

            // ---------- pure binary ----------
            Instruction::Add { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitAdd {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
                if let (Some(a), Some(b)) = (
                    self.walker_const.get(lhs).copied(),
                    self.walker_const.get(rhs).copied(),
                ) {
                    if let Some(s) = a.checked_add(b) {
                        self.walker_const.insert(*result, s);
                    }
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
                if let (Some(a), Some(b)) = (
                    self.walker_const.get(lhs).copied(),
                    self.walker_const.get(rhs).copied(),
                ) {
                    if let Some(s) = a.checked_sub(b) {
                        self.walker_const.insert(*result, s);
                    }
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
                if let (Some(a), Some(b)) = (
                    self.walker_const.get(lhs).copied(),
                    self.walker_const.get(rhs).copied(),
                ) {
                    if let Some(s) = a.checked_mul(b) {
                        self.walker_const.insert(*result, s);
                    }
                }
            }
            // Field division `Div(lhs, rhs)` — emit `Opcode::EmitDiv`.
            // The executor materialises that as `Instruction::Div` for
            // the sink, and the R1CS backend (`zkc::r1cs_backend`)
            // lowers it via `divide_lcs`, which handles the witness-
            // side inverse hint and the `rhs * inv = 1` constraint.
            //
            // The walker_const const-fold branch is intentionally
            // skipped: field division has no compile-time meaningful
            // result for the usize-shaped walker-side constants
            // (which model loop indices, not field elements).
            Instruction::Div { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitDiv {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }

            // ---------- unary ----------
            Instruction::Neg { result, operand } => {
                let op = self.resolve(*operand)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitNeg { dst, operand: op });
                self.bind(*result, dst);
                if let Some(v) = self.walker_const.get(operand).copied() {
                    if let Some(n) = v.checked_neg() {
                        self.walker_const.insert(*result, n);
                    }
                }
            }

            // ---------- boolean / logic — desugared to arithmetic.
            //            The operands are assumed boolean (0 or 1) by
            //            the upstream circuit; Lysis doesn't re-check.
            Instruction::Not { result, operand } => {
                let one = self.one()?;
                let x = self.resolve(*operand)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: x,
                });
                self.bind(*result, dst);
            }
            Instruction::And { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            Instruction::Or { result, lhs, rhs } => {
                // x OR y = x + y - x*y (for booleans).
                let (l, r) = self.bin(*lhs, *rhs)?;
                let sum = self.allocator.alloc()?;
                self.push_op(Opcode::EmitAdd {
                    dst: sum,
                    lhs: l,
                    rhs: r,
                });
                let prod = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst: prod,
                    lhs: l,
                    rhs: r,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: sum,
                    rhs: prod,
                });
                self.bind(*result, dst);
            }

            // ---------- mux ----------
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let c = self.resolve(*cond)?;
                let t = self.resolve(*if_true)?;
                let e = self.resolve(*if_false)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMux {
                    dst,
                    cond: c,
                    then_v: t,
                    else_v: e,
                });
                self.bind(*result, dst);
            }

            // ---------- comparisons ----------
            Instruction::IsEq { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsEq {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            Instruction::IsLt { result, lhs, rhs } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLt {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsNeq(x,y) = 1 - IsEq(x,y).
            Instruction::IsNeq { result, lhs, rhs } => {
                let one = self.one()?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let eq = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsEq {
                    dst: eq,
                    lhs: l,
                    rhs: r,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: eq,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsLe(x,y) = 1 - IsLt(y,x).
            Instruction::IsLe { result, lhs, rhs } => {
                let one = self.one()?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let lt = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLt {
                    dst: lt,
                    lhs: r,
                    rhs: l,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: lt,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsLtBounded(x,y,bits) ignores `bits`; the bound
            // is a soundness-preserving optimization hint (upstream
            // already range-checked operands to fit in `bits`). Emit
            // plain IsLt; a bounded opcode is not yet wired through.
            Instruction::IsLtBounded {
                result, lhs, rhs, ..
            } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLt {
                    dst,
                    lhs: l,
                    rhs: r,
                });
                self.bind(*result, dst);
            }
            // Desugar: IsLeBounded(x,y,bits) = 1 - IsLt(y,x); same
            // rationale as IsLtBounded.
            Instruction::IsLeBounded {
                result, lhs, rhs, ..
            } => {
                let one = self.one()?;
                let (l, r) = self.bin(*lhs, *rhs)?;
                let lt = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIsLt {
                    dst: lt,
                    lhs: r,
                    rhs: l,
                });
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitSub {
                    dst,
                    lhs: one,
                    rhs: lt,
                });
                self.bind(*result, dst);
            }

            // ---------- hash ----------
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let l = self.resolve(*left)?;
                let r = self.resolve(*right)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitPoseidonHash {
                    dst,
                    in_regs: Box::new(vec![l, r]),
                });
                self.bind(*result, dst);
            }

            // ---------- constraint side-effects ----------
            Instruction::AssertEq {
                result: _,
                lhs,
                rhs,
                message,
            } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                match message {
                    Some(msg) => {
                        let msg_idx = self.builder.intern_string(msg.clone());
                        self.push_op(Opcode::EmitAssertEqMsg {
                            lhs: l,
                            rhs: r,
                            msg_idx,
                        });
                    }
                    None => {
                        self.push_op(Opcode::EmitAssertEq { lhs: l, rhs: r });
                    }
                }
            }
            Instruction::Assert {
                result: _,
                operand,
                message,
            } => {
                // Desugar: assert operand == 1.
                let one = self.one()?;
                let op = self.resolve(*operand)?;
                match message {
                    Some(msg) => {
                        let msg_idx = self.builder.intern_string(msg.clone());
                        self.push_op(Opcode::EmitAssertEqMsg {
                            lhs: op,
                            rhs: one,
                            msg_idx,
                        });
                    }
                    None => {
                        self.push_op(Opcode::EmitAssertEq { lhs: op, rhs: one });
                    }
                }
            }
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                if *bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "RangeCheck.bits",
                        limit: u32::from(u8::MAX),
                        got: *bits,
                    });
                }
                let op = self.resolve(*operand)?;
                self.push_op(Opcode::EmitRangeCheck {
                    var: op,
                    max_bits: *bits as u8,
                });
                // Result aliases operand once the bit-width constraint is
                // enforced; downstream consumers (Mux, Bool propagation,
                // IsLtBounded) read result, so bind it to operand's reg.
                self.bind(*result, op);
            }
            Instruction::Decompose {
                result: _,
                bit_results,
                operand,
                num_bits,
            } => {
                if *num_bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "Decompose.num_bits",
                        limit: u32::from(u8::MAX),
                        got: *num_bits,
                    });
                }
                let op = self.resolve(*operand)?;
                let base = self.allocator.alloc()?;
                // Extra bits (bit 1..num_bits-1) consume consecutive slots.
                for _ in 1..*num_bits {
                    let _ = self.allocator.alloc()?;
                }
                self.push_op(Opcode::EmitDecompose {
                    dst_arr: base,
                    src: op,
                    n_bits: *num_bits as u8,
                });
                // Bind each bit_result to its corresponding register.
                for (i, br) in bit_results.iter().enumerate() {
                    self.bind(*br, base + i as RegId);
                }
            }

            // ---------- integer div/mod ----------
            // SHA-256(64) emits IntDiv from `int_div(...)` calls in
            // `padBlocks`, so the walker emits IntDiv/IntMod as
            // first-class output. The Lysis bytecode carries
            // `EmitIntDiv` / `EmitIntMod` (codes 0x4D / 0x4E) with
            // `max_bits: u8`; programs whose semantic max_bits
            // exceeds 255 surface as `OperandOutOfRange` so callers
            // learn the limit at walker time rather than as a silent
            // constraint bug.
            Instruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                if *max_bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "IntDiv.max_bits",
                        limit: u32::from(u8::MAX),
                        got: *max_bits,
                    });
                }
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIntDiv {
                    dst,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits as u8,
                });
                self.bind(*result, dst);
            }
            Instruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                if *max_bits > u32::from(u8::MAX) {
                    return Err(WalkError::OperandOutOfRange {
                        kind: "IntMod.max_bits",
                        limit: u32::from(u8::MAX),
                        got: *max_bits,
                    });
                }
                let (l, r) = self.bin(*lhs, *rhs)?;
                let dst = self.allocator.alloc()?;
                self.push_op(Opcode::EmitIntMod {
                    dst,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits as u8,
                });
                self.bind(*result, dst);
            }

            // ---------- witness call ----------
            // Intern the Artik bytecode blob, resolve input regs,
            // allocate fresh output destinations, and emit.
            //
            // Two emit paths, chosen by a dual guard:
            //
            //  - **Classic** (`EmitWitnessCall`): each output gets a
            //    fresh contiguous register; reg-allocator is
            //    bump-forward. Taken only when the call is both
            //    structurally small (outputs ≤
            //    `MAX_WITNESS_OUTPUTS_INLINE`) AND its outputs
            //    provably fit the *current* frame.
            //
            //  - **Heap** (`EmitWitnessCallHeap`): outputs go to
            //    fresh heap slots (zero frame registers); downstream
            //    reads materialise via `LoadHeap` through
            //    `Walker::resolve`'s lazy-reload path. Taken when
            //    either guard trips:
            //      * a structurally wide call (outputs >
            //        `MAX_WITNESS_OUTPUTS_INLINE`) — e.g. SHA-256's
            //        256-output hash; or
            //      * an otherwise-inline-eligible call whose
            //        `outputs.len()` would not fit the slots left in
            //        the current frame. A single `WitnessCall` is
            //        atomic — the split machinery chains templates
            //        *between* instructions, never *within* one — so
            //        an inline call that does not fit cannot be
            //        rescued by a split. The heap path always fits
            //        (zero frame regs) and is the correct fallback;
            //        the static threshold alone is unsound because a
            //        nested/multi-instruction template can enter this
            //        call with the frame already near `FRAME_CAP`
            //        (the bigint helper return shape `[2][100]` =
            //        200 outputs lands exactly at the static bound).
            Instruction::WitnessCall(call) => {
                let outputs = &call.outputs;
                let inputs = &call.inputs;
                let program_bytes = &call.program_bytes;
                let blob_idx = self.builder.intern_artik_bytecode(program_bytes.clone());

                // Mirrors the pre-emit split predicate, but for the
                // *classic* register-output path's full frame cost.
                // That path allocates one fresh reg per output AND,
                // via `resolve()`, one fresh reg per cold input — an
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
                // path — never unsafe. Do not de-dup it.
                let cold_inputs = inputs
                    .iter()
                    .filter(|v| {
                        !self.ssa_to_reg.contains_key(v) && self.ssa_to_heap.contains_key(v)
                    })
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
                    // for cold inputs — the executor reads them
                    // directly from `heap[slot]`. This is what makes
                    // SHA-256-class circuits compilable: an Artik
                    // call with 700+ inputs and 256 outputs would
                    // otherwise need 700 LoadHeap + 256 fresh regs,
                    // overflowing the 255 frame cap on a single
                    // instruction.
                    let mut classified_inputs: Vec<lysis::InputSrc> =
                        Vec::with_capacity(inputs.len());
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
            }
        }
        Ok(())
    }
}
