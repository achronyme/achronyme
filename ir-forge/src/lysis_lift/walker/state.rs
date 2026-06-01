use super::*;

pub(super) struct TemplateBuf {
    pub(super) opcodes: Vec<Opcode>,
    /// Frame size = high-water mark of the allocator at close time.
    /// Stamped by `close_current_template`.
    pub(super) frame_size: u8,
    /// Number of capture regs the template expects from its
    /// `InstantiateTemplate` site. The executor fills regs `0..n_params`
    /// of the callee frame with the caller's `capture_regs` before
    /// running the body, so no `LoadCapture` opcodes are needed
    /// inside the body itself — the captures are addressable directly
    /// as regs `0..n_params`.
    pub(super) n_params: u8,
}

impl TemplateBuf {
    pub(super) fn new(n_params: u8) -> Self {
        Self {
            opcodes: Vec::new(),
            frame_size: 0,
            n_params,
        }
    }
}

/// Emits Lysis bytecode from an `ExtendedInstruction` stream.
pub struct Walker<F: FieldBackend> {
    /// Used exclusively for const-pool interning during the walk.
    /// Opcodes are NOT pushed through the builder until `finalize()`.
    pub(super) builder: ProgramBuilder<F>,
    /// Per-template opcode buffers. `templates[0]` is Template 0,
    /// always present and always the body the root frame instantiates.
    /// The split logic appends more buffers as needed.
    pub(super) templates: Vec<TemplateBuf>,
    /// Index of the template the walker is currently emitting into.
    pub(super) current: usize,
    /// One allocator per template — reset at split boundaries. With
    /// no split the wrapper keeps a single template so the allocator
    /// never resets.
    pub(super) allocator: RegAllocator,
    /// SsaVar → RegId mapping for the **current** template's frame.
    /// At a split boundary this is rebuilt for the new frame.
    pub(super) ssa_to_reg: HashMap<SsaVar, RegId>,
    /// Register holding the field element 1 in the **current** frame.
    /// Lazily allocated when the body contains a desugaring that
    /// references it (Not, Assert, IsNeq, IsLe, IsLeBounded).
    pub(super) one_reg: Option<RegId>,
    /// Walker-side constant-propagation map. Tracks SsaVars whose
    /// runtime value is statically known to fit in `i64` — populated
    /// by `Plain(Const)` and `Plain(Add/Sub/Mul/Neg/IntDiv/IntMod)`
    /// when all operands are themselves walker-const. Drained by
    /// `SymbolicIndexedEffect` to resolve the indexed write to a
    /// literal slot at walker time. Per-iteration unrolling is the
    /// only producer of "iter_var = literal" entries; outside that
    /// path the map only sees source-level constants.
    pub(super) walker_const: HashMap<SsaVar, i64>,
    /// Maps lift-time `TemplateId` (allocated by
    /// `lysis_lift::extract::TemplateRegistry`) to the walker's
    /// internal `templates` buffer index. The IR stream uses lift
    /// IDs (sequential from 0); the walker pre-reserves index 0 for
    /// the root wrapper, so a lifted `TemplateBody { id: TemplateId(0) }`
    /// lands at buffer index 1. The wire-level `template_id` in
    /// `Opcode::InstantiateTemplate` must match the buffer index, so
    /// every `emit_template_call` translates through this map.
    pub(super) template_id_map: HashMap<TemplateId, u16>,
    /// Stack of currently-active per-iteration `iter_var`s, ordered
    /// outermost → innermost. Pushed by `emit_loop_unroll_per_iter` on
    /// entry, popped on exit. Used by `split_in_per_iter` to force-live
    /// every enclosing loop's iter_var across mid-emit splits — without
    /// this, an inner per-iter unroll's split would lose the outer
    /// loop's iter_var binding from the post-split frame's `ssa_to_reg`,
    /// and the outer loop's next-iteration restore would fail with
    /// `UndefinedSsaVar`. Strictly more surgical than force-living all
    /// `walker_const` keys: it pinpoints exactly the iter_vars that
    /// must survive, not every compile-time-folded SsaVar.
    pub(super) enclosing_iter_vars: Vec<SsaVar>,
    /// Bump allocator for heap slots. Program-global (never reset
    /// between templates). Each `StoreHeap` emission claims the next
    /// free slot id and increments this counter. `finalize()` writes
    /// the final value into the v2 header's `heap_size_hint` field so
    /// the executor pre-sizes its heap. `u32` because the number of
    /// distinct spilled cold vars scales with circuit size — a
    /// >1.5 M-constraint circuit spills well past the u16 ceiling.
    pub(super) heap_alloc: u32,
    /// `SsaVar` → heap slot for vars that were spilled at any prior
    /// split. Persists across template boundaries (unlike
    /// `ssa_to_reg`, which is wiped at every `perform_split`). A var
    /// is in this map iff it was emitted as `StoreHeap` somewhere in
    /// the program; subsequent uses produce one `LoadHeap` per
    /// template body that references it.
    pub(super) ssa_to_heap: HashMap<SsaVar, u32>,
}

impl<F: FieldBackend> Walker<F> {
    pub fn new(family: FieldFamily) -> Self {
        Self {
            builder: ProgramBuilder::new(family),
            // Template 0 takes no captures from root.
            templates: vec![TemplateBuf::new(0)],
            current: 0,
            allocator: RegAllocator::new(),
            ssa_to_reg: HashMap::default(),
            one_reg: None,
            walker_const: HashMap::default(),
            template_id_map: HashMap::default(),
            enclosing_iter_vars: Vec::new(),
            heap_alloc: 0,
            ssa_to_heap: HashMap::default(),
        }
    }

    /// Lower an entire body into a finished [`Program`]. The body is
    /// emitted into Template 0; the program's root body is the trivial
    /// `InstantiateTemplate(0, [], [])` + `Halt` pair. Before each
    /// top-level emission the walker estimates the upcoming
    /// instruction's reg cost (see [`reg_cost_of_extinst`]) and
    /// chains a fresh template if it would push the current frame
    /// past `FRAME_CAP - FRAME_MARGIN`, forwarding live SSA vars as
    /// captures.
    ///
    /// Gap 2 Stage 4: before emission, the body is run through
    /// `lift_uniform_loops` — each `BindingTime::Uniform` `LoopUnroll`
    /// gets replaced with a `TemplateBody` + `TemplateCall` pair so
    /// the bytecode emission path can isolate wide single instructions
    /// (`Decompose(254)`, `BinSum(32, n)`) into their own 255-slot
    /// frames. `body` is consumed: `lift_uniform_loops` mutates it in
    /// Lazy accessor: returns the current frame's `one` register,
    /// allocating + emitting `LoadConst` on first call. Called from
    /// every desugaring that needs `one` (Not, Assert, IsNeq, IsLe,
    /// IsLeBounded). The InterningSink dedupes the resulting `Const`
    /// node across the whole program, so re-loading per template is
    /// free at the IR level.
    pub(super) fn one(&mut self) -> Result<RegId, WalkError> {
        if let Some(r) = self.one_reg {
            return Ok(r);
        }
        let idx = self.builder.intern_field(FieldElement::<F>::one());
        let reg = self.allocator.alloc()?;
        self.push_op(Opcode::LoadConst { dst: reg, idx });
        self.one_reg = Some(reg);
        Ok(reg)
    }

    /// Push an opcode into the current template's body buffer.
    pub(super) fn push_op(&mut self, op: Opcode) {
        self.templates[self.current].opcodes.push(op);
    }
    pub(super) fn bin(&mut self, lhs: SsaVar, rhs: SsaVar) -> Result<(RegId, RegId), WalkError> {
        // Resolve sequentially — `self.resolve` may mutate state to
        // emit a `LoadHeap` for a spilled var, so a side-effect-free
        // map().collect() over both is unsound.
        let l = self.resolve(lhs)?;
        let r = self.resolve(rhs)?;
        Ok((l, r))
    }

    /// Resolve a `SsaVar` to the reg it currently lives in. Hot path:
    /// `ssa_to_reg.get(&var)` returns `Some`. Cold path: when a split
    /// spilled this var to the heap (`ssa_to_heap.contains(&var)`)
    /// but the new template hasn't yet materialised it, emit a
    /// `LoadHeap` into a fresh reg, cache the (var, reg) binding so
    /// subsequent uses inside the same template body see it as hot,
    /// and return the fresh reg.
    ///
    /// This is the ONLY place lazy-reload is implemented — every
    /// emission site that resolves an operand SsaVar goes through
    /// here (or through `bin` / `bin3` / direct callers), so spilled
    /// vars are rebound transparently without per-site changes.
    pub(super) fn resolve(&mut self, var: SsaVar) -> Result<RegId, WalkError> {
        if let Some(&reg) = self.ssa_to_reg.get(&var) {
            return Ok(reg);
        }
        if let Some(&slot) = self.ssa_to_heap.get(&var) {
            let dst_reg = self.allocator.alloc()?;
            self.push_op(Opcode::LoadHeap { dst_reg, slot });
            self.ssa_to_reg.insert(var, dst_reg);
            return Ok(dst_reg);
        }
        Err(WalkError::UndefinedSsaVar(var))
    }

    pub(super) fn bind(&mut self, var: SsaVar, reg: RegId) {
        self.ssa_to_reg.insert(var, reg);
    }
}
