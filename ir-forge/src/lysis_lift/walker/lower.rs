use super::*;

impl<F: FieldBackend> Walker<F> {
    /// caller's body before any per-instruction work begins.
    pub fn lower(mut self, body: Vec<ExtendedInstruction<F>>) -> Result<Program<F>, WalkError> {
        let lower_trace =
            std::env::var("ACH_LYSIS_TRACE").is_ok() || std::env::var("LYSIS_WALKER_TRACE").is_ok();
        let lower_start = lower_trace.then(Instant::now);
        let input_len = body.len();

        let lift_start = lower_trace.then(Instant::now);
        let body_is_plain = body.iter().all(ExtendedInstruction::is_plain);
        let lifted = if body_is_plain {
            body
        } else {
            let mut registry = TemplateRegistry::<F>::new();
            lift_uniform_loops(body, &mut registry, &FixedBitSet::new()).map_err(|e| {
                // The lift's frame/template-space errors are walker-relevant
                // — surface them through the existing error channel rather
                // than silently dropping the lift.
                match e {
                    ExtractError::FrameOverflow { requested } => WalkError::OperandOutOfRange {
                        kind: "lift_uniform_loops.frame_size",
                        limit: MAX_FRAME_SIZE,
                        got: requested,
                    },
                    ExtractError::TemplateSpaceExhausted => WalkError::OperandOutOfRange {
                        kind: "lift_uniform_loops.template_id",
                        limit: u32::from(u16::MAX),
                        got: u32::from(u16::MAX) + 1,
                    },
                }
            })?
        };
        if let Some(start) = lift_start {
            eprintln!(
                "[walker.lower] lift_uniform_loops_ms={:.3} input_len={} lifted_len={} skipped={}",
                start.elapsed().as_secs_f64() * 1000.0,
                input_len,
                lifted.len(),
                body_is_plain,
            );
        }

        // Lazy `one` loading: deferred to first desugaring that needs
        // it, so wide single-instruction templates (Decompose, Or)
        // don't pay the slot tax up-front.
        let body = lifted;
        // Precompute last-use index map once. `do_split`'s live-set
        // predicate consults this O(1) instead of rebuilding a
        // referenced-SsaVar HashSet from `body[next_idx..]` on every
        // split (148 M visits across 1,288 SHA-256(64) splits in the
        // pre-fix profile, 99 % of `walker.lower`'s wall time).
        let last_use_start = lower_trace.then(Instant::now);
        let last_use_idx = compute_last_use_idx(&body);
        if let Some(start) = last_use_start {
            eprintln!(
                "[walker.lower] compute_last_use_idx_ms={:.3} entries={}",
                start.elapsed().as_secs_f64() * 1000.0,
                last_use_idx.len(),
            );
        }

        let emit_start = lower_trace.then(Instant::now);
        let mut split_count = 0usize;
        let mut split_nanos = 0u128;
        for (i, inst) in body.iter().enumerate() {
            // Pre-emit split decision. Skip the check at i == 0 —
            // the allocator is at most at 1 (just the `one` const)
            // so no instruction can overflow on its first emission.
            if i > 0 {
                let cost = reg_cost_of_extinst(inst);
                let cold_loads = cold_load_cost(inst, &self.ssa_to_heap, &self.ssa_to_reg);
                let projected = self
                    .allocator
                    .next_slot()
                    .saturating_add(cost)
                    .saturating_add(cold_loads);
                if projected.saturating_add(FRAME_MARGIN) >= FRAME_CAP {
                    let split_start = lower_trace.then(Instant::now);
                    self.do_split(&body, i, &last_use_idx)?;
                    split_count += 1;
                    if let Some(start) = split_start {
                        split_nanos += start.elapsed().as_nanos();
                    }
                }
            }
            self.emit(inst).map_err(|e| match e {
                WalkError::Alloc(_) => {
                    if std::env::var("LYSIS_WALKER_TRACE").is_ok() {
                        eprintln!(
                            "[walker] frame overflow at body idx {i}: {} (slot={}, cost_est={}, cold_loads={}, heap_size={}, reg_size={}, current_template={})",
                            extinst_summary(inst),
                            self.allocator.next_slot(),
                            reg_cost_of_extinst(inst),
                            cold_load_cost(inst, &self.ssa_to_heap, &self.ssa_to_reg),
                            self.ssa_to_heap.len(),
                            self.ssa_to_reg.len(),
                            self.current,
                        );
                    }
                    e
                }
                other => other,
            })?;
        }
        if let Some(start) = emit_start {
            eprintln!(
                "[walker.lower] emit_loop_ms={:.3} split_count={} split_ms={:.3}",
                start.elapsed().as_secs_f64() * 1000.0,
                split_count,
                split_nanos as f64 / 1_000_000.0,
            );
        }

        let finalize_start = lower_trace.then(Instant::now);
        let program = self.finalize()?;
        if let Some(start) = finalize_start {
            eprintln!(
                "[walker.lower] finalize_ms={:.3}",
                start.elapsed().as_secs_f64() * 1000.0,
            );
        }
        if let Some(start) = lower_start {
            eprintln!(
                "[walker.lower] total_ms={:.3}",
                start.elapsed().as_secs_f64() * 1000.0,
            );
        }
        Ok(program)
    }
    /// Assemble the final Program. The body order is
    /// `[DefineTemplate(i)]*  +  InstantiateTemplate(0, [], [])  +  Halt
    /// +  [Template 0 body]  +  [Template 1 body]  +...`. Offsets
    /// are stamped on each `DefineTemplate` so the executor can
    /// resolve `body_offset` → instruction index.
    pub(super) fn finalize(mut self) -> Result<Program<F>, WalkError> {
        self.close_current_template();
        if self.templates.len() > usize::from(u16::MAX) + 1 {
            return Err(WalkError::OperandOutOfRange {
                kind: "templates",
                limit: u32::from(u16::MAX),
                got: self.templates.len() as u32,
            });
        }

        // Compute encoded byte sizes for each template body so we can
        // stamp body_offset/body_len on the matching DefineTemplate.
        let mut body_sizes: Vec<u32> = Vec::with_capacity(self.templates.len());
        for buf in &self.templates {
            let mut total: u32 = 0;
            for op in &buf.opcodes {
                let mut bytes = Vec::new();
                encode_opcode(op, &mut bytes);
                total = total.saturating_add(bytes.len() as u32);
            }
            body_sizes.push(total);
        }

        // Bytes for the root prefix:
        //   N * sizeof(DefineTemplate) + sizeof(InstantiateTemplate(0, [], [])) + sizeof(Halt)
        let define_template_bytes: u32 = {
            let mut buf = Vec::new();
            encode_opcode(
                &Opcode::DefineTemplate {
                    template_id: 0,
                    frame_size: 0,
                    n_params: 0,
                    body_offset: 0,
                    body_len: 0,
                },
                &mut buf,
            );
            buf.len() as u32
        };
        let instantiate_t0_bytes: u32 = {
            let mut buf = Vec::new();
            encode_opcode(
                &Opcode::InstantiateTemplate {
                    template_id: 0,
                    capture_regs: Box::new(Vec::new()),
                    output_regs: Box::new(Vec::new()),
                },
                &mut buf,
            );
            buf.len() as u32
        };
        let root_bytes: u32 = define_template_bytes
            .saturating_mul(self.templates.len() as u32)
            .saturating_add(instantiate_t0_bytes)
            .saturating_add(1); // Halt = 1 byte

        // Stamp DefineTemplate opcodes with computed offsets, then
        // the root entry, then each template body.
        let mut offset_cursor = root_bytes;
        for (tid, (buf, &body_len)) in self.templates.iter().zip(body_sizes.iter()).enumerate() {
            self.builder.define_template(
                tid as u16,
                buf.frame_size,
                buf.n_params,
                offset_cursor,
                body_len,
            );
            offset_cursor = offset_cursor.saturating_add(body_len);
        }
        self.builder.instantiate_template(0, Vec::new(), Vec::new());
        self.builder.halt();
        for buf in self.templates.into_iter() {
            for op in buf.opcodes {
                self.builder.push_opcode(op);
            }
        }
        // Stamp the heap size hint so the executor pre-sizes its heap
        // to fit every slot allocated by `spill_cold_var`.
        self.builder.set_heap_size_hint(self.heap_alloc);
        Ok(self.builder.finish())
    }
}
