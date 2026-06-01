use super::*;

impl<F: FieldBackend> Walker<F> {
    /// Resolve a `SymbolicArrayRead` at walker time. Mirrors
    /// [`Self::emit_symbolic_indexed_effect`]: const-fold the index,
    /// pick the slot, rebind `result_var` to the slot's register.
    /// Requires `walker_const[index_var]` populated; the per-iteration
    /// walker is the only producer.
    ///
    /// If the slot has no register binding yet, synthesise a witness
    /// wire on demand — same pattern the write-side uses. This handles
    /// internal-signal arrays whose `WitnessArrayDecl` couldn't fire at
    /// lowering time (parametrized dims like `paddedIn[nBlocks*512]`
    /// in SHA-256 where `nBlocks` depends on the template parameter
    /// `nBits` and `total_dim_size` returns `None` at lowering). The
    /// subsequent write — emitted via `emit_symbolic_indexed_effect` or
    /// any const-indexed `Plain(AssertEq)` to the same `slot_var` —
    /// hits the cache, reuses the synthesised reg, and emits the
    /// constraint that closes the witness. Read-before-write is sound
    /// in this regime because every internal signal is eventually
    /// constrained by some write (otherwise the program would have
    /// no defining equation for the slot, which the constraint check
    /// would catch downstream).
    pub(super) fn emit_symbolic_array_read(
        &mut self,
        result_var: SsaVar,
        array_slots: &[SsaVar],
        index_var: SsaVar,
    ) -> Result<(), WalkError> {
        let idx_signed = self
            .walker_const
            .get(&index_var)
            .copied()
            .ok_or(WalkError::SymbolicArrayReadNotEmittable)?;
        if idx_signed < 0 || (idx_signed as usize) >= array_slots.len() {
            return Err(WalkError::SymbolicArrayReadIndexOutOfRange {
                idx: idx_signed,
                len: array_slots.len(),
            });
        }
        let idx = idx_signed as usize;
        let slot_var = array_slots[idx];

        let slot_reg = match self.resolve(slot_var) {
            Ok(reg) => reg,
            Err(WalkError::UndefinedSsaVar(_)) => {
                // Mirror `emit_symbolic_indexed_effect`'s on-demand
                // synthesis. Reachable only for slots never backed
                // by a `Plain(Input)` in any ancestor scope —
                // input-backed slots resolve via heap fault-in
                // (see live-set updates in `collect_in_extinst` /
                // `record_last_use_in_extinst`).
                let name = format!("__lysis_sym_slot_{}", slot_var.0);
                let name_idx = self.builder.intern_string(name);
                let reg = self.allocator.alloc()?;
                self.push_op(Opcode::LoadInput {
                    dst: reg,
                    name_idx,
                    vis: lysis::Visibility::Witness,
                });
                self.bind(slot_var, reg);
                reg
            }
            Err(e) => return Err(e),
        };
        self.bind(result_var, slot_reg);
        Ok(())
    }

    /// Resolve a `SymbolicShift` at walker time. Requires
    /// `walker_const[shift_var]` populated — the per-iteration loop
    /// unroll is the only producer.
    ///
    /// Mirrors [`crate::instantiate::Instantiator::emit_shift_right`] /
    /// `emit_shift_left` once `shift_var` is known to be a literal
    /// `u32`. The expansion is a single `EmitDecompose` followed by a
    /// linear recompose chain over the *kept* bits — only non-zero
    /// terms are emitted (zero terms in a left shift would const-fold
    /// to zero in the legacy IR path; the walker's `InterningSink`
    /// dedupes Const but doesn't peephole `bit * 0`, so we omit those
    /// terms directly).
    ///
    /// For `shift >= num_bits` the result is the constant zero — same
    /// early return as the legacy path.
    pub(super) fn emit_symbolic_shift(
        &mut self,
        result_var: SsaVar,
        operand_var: SsaVar,
        shift_var: SsaVar,
        num_bits: u32,
        direction: ShiftDirection,
    ) -> Result<(), WalkError> {
        let shift_signed = self
            .walker_const
            .get(&shift_var)
            .copied()
            .ok_or(WalkError::SymbolicShiftNotEmittable)?;
        if shift_signed < 0 {
            return Err(WalkError::SymbolicShiftNegativeAmount {
                shift: shift_signed,
            });
        }
        let shift = shift_signed as u32;

        // shift >= num_bits — the entire operand shifts out and the
        // result is zero. Mirrors `emit_shift_right` / `emit_shift_left`'s
        // early return in `instantiate/bits.rs`.
        if shift >= num_bits {
            let zero_idx = self.builder.intern_field(FieldElement::<F>::zero());
            let dst = self.allocator.alloc()?;
            self.push_op(Opcode::LoadConst { dst, idx: zero_idx });
            self.bind(result_var, dst);
            return Ok(());
        }

        // `EmitDecompose.n_bits` is a `u8`; reject wider operands at
        // walker time rather than miscompiling. The legacy path's
        // `Instruction::Decompose` walker arm (line 1207) applies the
        // same gate.
        if num_bits > u32::from(u8::MAX) {
            return Err(WalkError::OperandOutOfRange {
                kind: "SymbolicShift.num_bits",
                limit: u32::from(u8::MAX),
                got: num_bits,
            });
        }

        let operand_reg = self.resolve(operand_var)?;

        // Allocate `num_bits` consecutive registers for the bit array,
        // then emit `EmitDecompose`. Mirrors the
        // `Instruction::Decompose` walker arm exactly.
        let base = self.allocator.alloc()?;
        for _ in 1..num_bits {
            let _ = self.allocator.alloc()?;
        }
        self.push_op(Opcode::EmitDecompose {
            dst_arr: base,
            src: operand_reg,
            n_bits: num_bits as u8,
        });

        // Recompose the kept bits.
        //
        //   ShiftR(op, shift): result = sum_{j in 0..n_kept} bits[shift + j] * 2^j
        //   ShiftL(op, shift): result = sum_{j in 0..n_kept} bits[j] * 2^(j + shift)
        //
        // Both unify by iterating j over the kept range, picking the
        // appropriate bit index, and tracking `current_power` (the
        // coefficient for the j-th term). We start with the smallest
        // power for the direction and double per iteration.
        let n_kept = num_bits - shift;
        let mut current_power = FieldElement::<F>::one();
        if matches!(direction, ShiftDirection::Left) {
            for _ in 0..shift {
                current_power = current_power.add(&current_power);
            }
        }

        let mut acc: Option<RegId> = None;
        for j in 0..n_kept {
            let bit_idx = match direction {
                ShiftDirection::Right => shift + j,
                ShiftDirection::Left => j,
            };
            let bit_reg = base + bit_idx as RegId;

            // Skip the multiplication when the coefficient is 1
            // (matches `emit_recompose`'s peephole: the LSB is taken
            // directly).
            let term_reg = if current_power == FieldElement::<F>::one() {
                bit_reg
            } else {
                let power_idx = self.builder.intern_field(current_power);
                let power_reg = self.allocator.alloc()?;
                self.push_op(Opcode::LoadConst {
                    dst: power_reg,
                    idx: power_idx,
                });
                let term_reg = self.allocator.alloc()?;
                self.push_op(Opcode::EmitMul {
                    dst: term_reg,
                    lhs: bit_reg,
                    rhs: power_reg,
                });
                term_reg
            };

            acc = Some(match acc {
                None => term_reg,
                Some(prev) => {
                    let next = self.allocator.alloc()?;
                    self.push_op(Opcode::EmitAdd {
                        dst: next,
                        lhs: prev,
                        rhs: term_reg,
                    });
                    next
                }
            });

            current_power = current_power.add(&current_power);
        }

        // `n_kept >= 1` because `shift < num_bits` was checked above,
        // so the loop always runs at least once and `acc` is `Some`.
        let result_reg = acc.expect("n_kept >= 1 implies acc is bound");
        self.bind(result_var, result_reg);
        Ok(())
    }

    /// Emit `Opcode::InstantiateTemplate` for an
    /// [`ExtendedInstruction::TemplateCall`]. Captures resolve to
    /// register ids in the caller's frame; the executor copies them
    /// into the callee's `regs[0..n_params]` before the body runs
    /// (see `lysis::execute::dispatch`'s InstantiateTemplate handler).
    /// Outputs are not supported by the lift (Option B uses
    /// side-effects only — see `WalkError::TemplateOutputsNotSupported`).
    pub(super) fn emit_template_call(
        &mut self,
        template_id: TemplateId,
        captures: &[SsaVar],
        outputs: &[SsaVar],
    ) -> Result<(), WalkError> {
        if !outputs.is_empty() {
            return Err(WalkError::TemplateOutputsNotSupported);
        }
        if captures.len() > u8::MAX as usize {
            return Err(WalkError::OperandOutOfRange {
                kind: "TemplateCall.captures",
                limit: u32::from(u8::MAX),
                got: captures.len() as u32,
            });
        }
        let walker_idx = self
            .template_id_map
            .get(&template_id)
            .copied()
            .ok_or(WalkError::UndefinedTemplateId(template_id))?;
        let mut capture_regs: Vec<u8> = Vec::with_capacity(captures.len());
        for v in captures {
            capture_regs.push(self.resolve(*v)?);
        }
        self.push_op(Opcode::InstantiateTemplate {
            template_id: walker_idx,
            capture_regs: Box::new(capture_regs),
            output_regs: Box::new(Vec::new()),
        });
        Ok(())
    }

    /// Emit a separate template buffer for an
    /// [`ExtendedInstruction::TemplateBody`]. The body's frame is
    /// independent of the caller's: a fresh `RegAllocator` starts
    /// after `n_params` (the executor pre-fills regs `0..n_params`
    /// from the call's `capture_regs`), `ssa_to_reg` is rebuilt with
    /// `captures[i] → i`, and `one_reg` + `walker_const` reset. After
    /// the body emits, `close_current_template` stamps the high-water
    /// frame_size and appends `Return`; caller state is restored so
    /// emission resumes in the previous template.
    ///
    /// The declared `frame_size` and `n_params` from the lift are
    /// recorded for diagnostic purposes only; the actual frame_size
    /// stamped on the bytecode is `allocator.frame_size()` after the
    /// body runs (true high-water, not the lift's
    /// over-approximation).
    pub(super) fn emit_template_body(
        &mut self,
        id: TemplateId,
        _declared_frame_size: u8,
        n_params: u8,
        captures: &[SsaVar],
        body: &[ExtendedInstruction<F>],
    ) -> Result<(), WalkError> {
        if usize::from(n_params) != captures.len() {
            return Err(WalkError::TemplateCapturesMismatch {
                n_params,
                captures_len: captures.len(),
            });
        }

        // Save caller state. Each TemplateBody emission opens a new
        // template buffer and emits independently; on return the
        // walker resumes emitting where the parent left off.
        let saved_current = self.current;
        let saved_allocator = std::mem::replace(&mut self.allocator, RegAllocator::new());
        let saved_ssa_to_reg = std::mem::take(&mut self.ssa_to_reg);
        let saved_one_reg = self.one_reg.take();
        let saved_walker_const = std::mem::take(&mut self.walker_const);

        // Open a fresh template buffer at the tail of `templates`.
        // Record the lift-id → buffer-index mapping BEFORE emitting
        // the body so a recursive TemplateCall referencing this id
        // (e.g. self-recursive templates, though the lift never
        // emits them) resolves correctly.
        let walker_idx =
            u16::try_from(self.templates.len()).map_err(|_| WalkError::OperandOutOfRange {
                kind: "templates",
                limit: u32::from(u16::MAX),
                got: self.templates.len() as u32,
            })?;
        self.template_id_map.insert(id, walker_idx);
        self.templates.push(TemplateBuf::new(n_params));
        self.current = self.templates.len() - 1;
        self.allocator = RegAllocator::new_after_captures(n_params);

        // Bind capture SSA vars to regs `0..n_params`. The executor
        // mirrors this by writing `capture_regs[i]` into the
        // callee's `regs[i]` before the body runs.
        for (i, v) in captures.iter().enumerate() {
            self.bind(*v, i as RegId);
        }

        // Emit the body, propagating any walker error.
        let emit_result: Result<(), WalkError> = (|| {
            for inst in body {
                self.emit(inst)?;
            }
            Ok(())
        })();

        // Close the template regardless of body emission outcome so
        // the templates vector stays consistent. `close_current_template`
        // stamps frame_size and appends `Return`. The terminator is
        // benign on the error path because the program won't be
        // finalised.
        self.close_current_template();

        // Restore caller state.
        self.current = saved_current;
        self.allocator = saved_allocator;
        self.ssa_to_reg = saved_ssa_to_reg;
        self.one_reg = saved_one_reg;
        self.walker_const = saved_walker_const;

        emit_result
    }

    /// Resolve a `SymbolicIndexedEffect` at walker time. Requires
    /// `walker_const[index_var]` populated — the per-iteration loop
    /// unroll is the only producer.
    pub(super) fn emit_symbolic_indexed_effect(
        &mut self,
        kind: IndexedEffectKind,
        array_slots: &[SsaVar],
        index_var: SsaVar,
        value_var: Option<SsaVar>,
    ) -> Result<(), WalkError> {
        let idx_signed = self
            .walker_const
            .get(&index_var)
            .copied()
            .ok_or(WalkError::SymbolicIndexedEffectNotEmittable)?;
        if idx_signed < 0 || (idx_signed as usize) >= array_slots.len() {
            return Err(WalkError::SymbolicIndexedEffectIndexOutOfRange {
                idx: idx_signed,
                len: array_slots.len(),
            });
        }
        let idx = idx_signed as usize;
        let target_var = array_slots[idx];

        // Resolve the slot's reg, faulting in from heap if a prior
        // `perform_split` spilled the parent template's binding.
        // `resolve()` returns `UndefinedSsaVar` for slots that were
        // never bound by a `Plain(Input)` in any ancestor scope —
        // canonically, internal signal arrays whose elements
        // `instantiate/stmts.rs::emit_let_indexed_const` leaves as
        // lazy placeholders. For those we fall back to synthesizing
        // a fresh witness wire (the slot IS a witness signal by
        // design). For input-backed slots (public outputs, witness
        // inputs), `resolve()` succeeds because `collect_in_extinst`
        // and `record_last_use_in_extinst` include `array_slots`
        // in the live-set, ensuring perform_split spills them to
        // heap. Without that inclusion the synthesis path would fire
        // for input-backed slots too, silently downgrading e.g.
        // `paddedIn_X (Public)` to a fresh `__lysis_sym_slot_X
        // (Witness)` wire — covered by the `var_postdecl_padding_e2e`
        // regression test.
        let target_reg = match self.resolve(target_var) {
            Ok(reg) => reg,
            Err(WalkError::UndefinedSsaVar(_)) => {
                let name = format!("__lysis_sym_slot_{}", target_var.0);
                let name_idx = self.builder.intern_string(name);
                let reg = self.allocator.alloc()?;
                self.push_op(Opcode::LoadInput {
                    dst: reg,
                    name_idx,
                    vis: lysis::Visibility::Witness,
                });
                self.bind(target_var, reg);
                reg
            }
            Err(e) => return Err(e),
        };

        match kind {
            IndexedEffectKind::Let => {
                let value = value_var.ok_or(WalkError::SymbolicIndexedEffectMissingValue)?;
                let value_reg = self.resolve(value)?;
                self.push_op(Opcode::EmitAssertEq {
                    lhs: target_reg,
                    rhs: value_reg,
                });
            }
            IndexedEffectKind::WitnessHint => {
                // `target_reg` was either already bound (output array,
                // pre-emitted via Plain(Input)) or just synthesised
                // above as a witness wire. Either way the slot is now
                // live in the frame; no extra constraint to add — the
                // const-index `WitnessHintIndexed` path likewise just
                // declares the wire and stops.
            }
        }
        Ok(())
    }
}
