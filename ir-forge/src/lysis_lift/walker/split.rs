use super::*;

impl<F: FieldBackend> Walker<F> {
    pub(super) fn do_split(
        &mut self,
        body: &[ExtendedInstruction<F>],
        next_idx: usize,
        last_use_idx: &HashMap<SsaVar, usize>,
    ) -> Result<(), WalkError> {
        // Live set: SSA vars defined in the current frame AND
        // referenced by some instruction in `body[next_idx..]`. The
        // `one` const is intentionally excluded — re-load is cheaper
        // than capture-bind, and the InterningSink dedupes anyway.
        //
        // Predicate equivalence: `v ∈ referenced(body[next_idx..])` ⟺
        // `last_use_idx[v] ≥ next_idx`, by construction of
        // `compute_last_use_idx`. The HashMap lookup replaces a
        // tail-slice scan that previously rebuilt a HashSet from
        // scratch on every split.
        let live =
            self.compute_live_set(|v| last_use_idx.get(v).is_some_and(|&j| j >= next_idx))?;
        dump_live_set_trace("top_level", live.len(), body.len() - next_idx, self.current);
        // Partition by first-use ordering in the upcoming body. The
        // first MAX_CAPTURES_HOT (<= 48) referenced earliest stay as
        // captures; the rest spill to the heap and reload lazily on
        // first use.
        let upcoming = &body[next_idx..];
        let (hot, cold) = partition_live_set(&live, upcoming, &HashSet::default());
        self.perform_split(&hot, &cold)
    }

    /// Mid-emit split inside `emit_loop_unroll_per_iter`. The live set
    /// is computed against the **whole body** (not just `body[j..]`)
    /// because subsequent iterations re-emit `body[0..N]` from the
    /// post-split frame and would lose any outer SsaVar that
    /// `body[0..j]` references but `body[j..N]` doesn't. Every entry
    /// in `enclosing_iter_vars` is force-live so the current loop's
    /// `iter_var` plus every outer enclosing loop's iter_var survive
    /// the boundary — required so the next iteration's restore can
    /// rebind iter_var literals, and required so an inner-triggered
    /// split doesn't strand an outer loop's iter_var binding.
    ///
    /// `body_defined` is the set of SsaVars defined anywhere inside
    /// `body` (computed once per loop in `emit_loop_unroll_per_iter_inner`
    /// and threaded through). Anything in `ssa_to_reg` that is NOT in
    /// `body_defined` was produced by code outside the loop, so its
    /// only post-split fate is to be referenced by the OUTER scope
    /// after the loop closes. The loop body itself can't observe
    /// whether such a var has a downstream use, but the walker has
    /// already locked it into `ssa_to_reg`, so dropping it from the
    /// live set without spilling would surface as `UndefinedSsaVar`
    /// at the outer consumer. Force-include outer vars in `live` so
    /// `partition_live_set` can route them to `cold` and `perform_split`
    /// spills them to heap — a later `resolve()` then faults them in
    /// via `LoadHeap` regardless of which template the outer use
    /// lands in.
    pub(super) fn split_in_per_iter(
        &mut self,
        body: &[ExtendedInstruction<F>],
        body_defined: &HashSet<SsaVar>,
    ) -> Result<(), WalkError> {
        let referenced = collect_referenced_ssa_vars(body);
        let enclosing: HashSet<SsaVar> = self.enclosing_iter_vars.iter().copied().collect();
        let live = self.compute_live_set(|v| {
            referenced.contains(v) || enclosing.contains(v) || !body_defined.contains(v)
        })?;
        dump_live_set_trace("mid_iter", live.len(), body.len(), self.current);
        // Mid-iter splits force-include enclosing iter vars in `hot`
        // regardless of first-use ordering — outer loops' iter_vars
        // must survive every inner split cheaply, and the inner
        // loop's iter_var binding is also load-bearing for the next
        // iteration's restore.
        let (hot, cold) = partition_live_set(&live, body, &enclosing);
        self.perform_split(&hot, &cold)
    }

    /// Build the deterministic live set for a split. Filters
    /// `ssa_to_reg` keys by `predicate`, sorts by `SsaVar.0` for
    /// proving-key stability, and rejects sets larger than
    /// [`MAX_CAPTURES`] (= `u16::MAX`, the absolute heap-slot ceiling).
    /// Sets in the `(MAX_CAPTURES_HOT, MAX_CAPTURES]` range are
    /// accepted and partitioned by `partition_live_set` into a
    /// hot capture set + a cold spill set.
    ///
    /// **Tracing**: when `LYSIS_DUMP_LIVESET=1` is set in the
    /// environment, every accept *and* reject path emits one stderr
    /// line that the caller (`do_split` / `split_in_per_iter`)
    /// supplements with a `kind=` tag. Pipe through
    /// `grep '\[walker\] live_set' | sort | uniq -c` to build a
    /// per-corpus histogram; see `dump_live_set_trace` below.
    pub(super) fn compute_live_set(
        &self,
        predicate: impl Fn(&SsaVar) -> bool,
    ) -> Result<Vec<SsaVar>, WalkError> {
        let mut live: Vec<SsaVar> = self
            .ssa_to_reg
            .keys()
            .copied()
            .filter(|v| predicate(v))
            .collect();
        // Deterministic order is load-bearing for proving-key
        // stability — without this the HashMap iteration order would
        // leak into capture_regs slot ids. SsaVar wraps `u32`; sort
        // by it directly rather than threading `Ord` through ir-core.
        live.sort_unstable_by_key(|v| v.0);
        if live.len() > MAX_CAPTURES {
            if std::env::var("LYSIS_DUMP_LIVESET").is_ok() {
                eprintln!(
                    "[walker] live_set kind=rejected live={} cap={}",
                    live.len(),
                    MAX_CAPTURES
                );
            }
            return Err(WalkError::LiveSetTooLarge {
                count: live.len(),
                max: MAX_CAPTURES,
            });
        }
        Ok(live)
    }

    /// Common post-live-set machinery shared by [`Self::do_split`]
    /// (top-level) and [`Self::split_in_per_iter`] (mid-iter).
    ///
    /// Spill discipline:
    ///
    ///  1. **Spill cold vars first** — for every cold var not already
    ///     in `ssa_to_heap`, allocate a slot via `heap_alloc`, emit
    ///     `StoreHeap { src_reg, slot }` into the *outgoing* template
    ///     buffer, and record the slot in `ssa_to_heap` so future
    ///     splits forward the same slot id rather than re-storing.
    ///  2. **Chain via captures** — emit the `InstantiateTemplate`
    ///     opcode passing only the *hot* vars as captures.
    ///  3. **Open the new template** — fresh allocator, `ssa_to_reg`
    ///     rebuilt with hot vars at their post-instantiate reg slots.
    ///     Cold vars are NOT in `ssa_to_reg`; they reload lazily
    ///     through [`Self::resolve`] on first use in the new body.
    pub(super) fn perform_split(
        &mut self,
        hot: &[SsaVar],
        cold: &[SsaVar],
    ) -> Result<(), WalkError> {
        // Step 1: spill cold vars. Order is deterministic by SsaVar.0
        // (cold is sorted because partition_live_set returns slices of
        // the sorted live set).
        for var in cold {
            self.spill_cold_var(*var);
        }

        // Step 2: build capture_regs for the hot partition only.
        let capture_regs: Vec<u8> = hot.iter().map(|v| self.ssa_to_reg[v]).collect();
        let next_template_id =
            u16::try_from(self.templates.len()).map_err(|_| WalkError::OperandOutOfRange {
                kind: "templates",
                limit: u32::from(u16::MAX),
                got: self.templates.len() as u32,
            })?;

        // Tail of the outgoing template: chain the next one and
        // close. `close_current_template` stamps frame_size and
        // appends `Return`.
        self.push_op(Opcode::InstantiateTemplate {
            template_id: next_template_id,
            capture_regs: Box::new(capture_regs),
            output_regs: Box::new(Vec::new()),
        });
        self.close_current_template();

        // Open the new template with a fresh frame state. The
        // executor's `InstantiateTemplate` handler places the caller's
        // `capture_regs[i]` value into the new frame's `reg i`
        // *before* the body executes — see `lysis::execute::dispatch`
        // for `InstantiateTemplate`. So the first `live.len()` regs
        // are already bound to the captured SSA vars; we just record
        // that mapping and start allocating fresh regs above them.
        let n_params = hot.len() as u8;
        self.templates.push(TemplateBuf::new(n_params));
        self.current = self.templates.len() - 1;
        self.allocator = RegAllocator::new_after_captures(n_params);
        let mut new_ssa_to_reg = HashMap::default();
        for (i, var) in hot.iter().enumerate() {
            new_ssa_to_reg.insert(*var, i as RegId);
        }
        self.ssa_to_reg = new_ssa_to_reg;
        self.one_reg = None;
        // Forward `walker_const` *unfiltered* across the split.
        //
        // Earlier revisions filtered this map by the live set
        // (`hot ∪ cold`), reasoning that "walker_const is just a
        // hint, dropping is sound." That reasoning is **wrong**:
        // `walker_const` is load-bearing for the
        // `SymbolicIndexedEffect` / `SymbolicArrayRead` /
        // `SymbolicShift` emit paths, which look up an `index_var`
        // / `shift_var` literal at walker time. A var's literal can
        // be in `walker_const` *without* being in `ssa_to_reg`
        // (typical case: a loop iter var that const-folded without
        // ever materialising as a reg), so it never enters the live
        // set, never gets forwarded, and post-split emission panics
        // with `SymbolicIndexedEffectNotEmittable`.
        //
        // SHA-256(64) is the canonical witness: 4 top-level splits
        // succeed (heap path works), then a downstream
        // `SymbolicIndexedEffect` whose `index_var` was a folded
        // literal trips the assertion in `emit_symbolic_indexed_effect`
        // because the new template's `walker_const` is empty.
        //
        // The map is lookup-only and never produces side-effects, so
        // forwarding stale entries is harmless: nobody asks for a
        // var that the new template doesn't reference. Memory cost
        // is bounded by the total number of compile-time-folded vars
        // across the program — small in practice.

        // `one` is re-loaded lazily on first use in the new
        // template — see `Walker::one`. This avoids the slot tax on
        // wide single-instruction templates (Decompose, Or) whose
        // body never references `one`.
        Ok(())
    }

    /// Spill a cold var to the program-global heap. Idempotent per
    /// `SsaVar`: if the var was already spilled at an earlier split
    /// (`ssa_to_heap.contains_key(&var)`), no new `StoreHeap` is
    /// emitted. This enforces the **single-static-store invariant**
    /// (one StoreHeap per slot) at the walker level, before the
    /// validator catches it.
    ///
    /// Pre-condition: `ssa_to_reg[&var]` is bound — the caller (which
    /// is always `perform_split`) has just computed the live set
    /// against `ssa_to_reg.keys()`, so every var in `cold` is by
    /// definition in `ssa_to_reg`.
    pub(super) fn spill_cold_var(&mut self, var: SsaVar) {
        if self.ssa_to_heap.contains_key(&var) {
            // Already spilled at an earlier split — re-use the slot.
            return;
        }
        let slot = self.heap_alloc;
        self.heap_alloc = self.heap_alloc.saturating_add(1);
        let src_reg = self.ssa_to_reg[&var];
        self.push_op(Opcode::StoreHeap { src_reg, slot });
        self.ssa_to_heap.insert(var, slot);
    }

    /// Stamp the current allocator's high-water mark onto the current
    /// template and append a terminating `Return`.
    pub(super) fn close_current_template(&mut self) {
        let frame_size = self.allocator.frame_size();
        let buf = &mut self.templates[self.current];
        buf.frame_size = frame_size;
        buf.opcodes.push(Opcode::Return);
    }
}
