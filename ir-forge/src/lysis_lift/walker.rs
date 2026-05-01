//! ExtendedInstruction walker (RFC §6.3).
//!
//! Consumes a `Vec<ExtendedInstruction<F>>` and emits a Lysis
//! `Program<F>` whose execution reproduces the original instruction
//! stream modulo the interner's hash-cons deduplication.
//!
//! ## Scope
//!
//! Phase 3.B.7 (augmented by the 3.C-era deuda clearing) handles:
//!
//! - `Plain(Instruction<F>)` — every arithmetic, boolean, comparison,
//!   hash, constraint, and side-effect variant. Several lower via
//!   desugarings rather than dedicated opcodes:
//!     - `Not(x)`         → `Sub(one, x)`
//!     - `And(x,y)`       → `Mul(x, y)`
//!     - `Or(x,y)`        → `Add(x,y) - Mul(x,y)`
//!     - `Assert(x)`      → `AssertEq(x, one)`
//!     - `IsNeq(x,y)`     → `Sub(one, IsEq(x, y))`
//!     - `IsLe(x,y)`      → `Sub(one, IsLt(y, x))`
//!     - `IsLtBounded`    → `IsLt` (bitwidth hint dropped)
//!     - `IsLeBounded`    → `Sub(one, IsLt(y, x))`
//!     - `WitnessCall`    → `EmitWitnessCall` with Artik blob interning
//!
//!   The `one` register is lazily allocated at the top of `lower` only
//!   when the body contains at least one desugaring that needs it.
//! - `LoopUnroll` — emits the Lysis `LoopUnroll` opcode with an
//!   inline body. The executor's Phase 3.B.8 loop machinery takes
//!   care of iteration binding and hash-cons dedup within the body.
//!
//! Not handled (Phase 4):
//!
//! - `TemplateBody` / `TemplateCall` — template extraction is wired
//!   through `extract.rs`, but the bytecode emission of
//!   `DefineTemplate` + `InstantiateTemplate` flows through a
//!   different path that Phase 3.C will connect to the oracle gate.
//!   Walkers that hit these variants in Phase 3 return
//!   `WalkError::TemplateNotSupported`; the walker driver
//!   (future work) falls back to inline unrolling when that error
//!   appears.
//! - `Div` — field division `x / y = x * y^{-1}`. Requires emitting
//!   an inline Artik blob for the inverse + a range constraint. No
//!   precedent in this walker; deferred until a use case surfaces.
//! - `IntDiv` / `IntMod` — bounded integer arithmetic; the Lysis
//!   bytecode has no opcode for these today. Circom never emits them
//!   (signal arith is field-native).
//! - Negative loop bounds — `LoopUnroll` uses `u32` in the bytecode,
//!   so negative `i64` bounds are rejected up-front.
//! - `RangeCheck` / `Decompose` with bit counts > 255 — the Lysis
//!   opcodes carry the count as `u8`.
//!
//! ## Register allocation
//!
//! Bump allocation via `lysis::lower::RegAllocator`: every SsaVar
//! that defines a fresh value gets the next register, and the
//! mapping persists for the whole program (no release). Frame size
//! is the high water mark.
//!
//! ## Phase 1.5 — top-level template wrapping
//!
//! Earlier walker revisions emitted the entire body into the root
//! frame. The Lysis bytecode caps a frame at 255 registers (RFC §5.1
//! "dense bytecode" — frame_size is `u8`), so any program whose
//! lowered SSA exceeds that width tripped `FrameOverflow` even though
//! the underlying memory was nowhere near the limit. SHA-256(64) is
//! the canonical case.
//!
//! Phase 1.5 fixes this by always wrapping the body in Template 0.
//! The root body is the trivial sequence `InstantiateTemplate(0, [], [])`
//! followed by `Halt`, and all real work happens inside the template's
//! frame. Programs that fit in 255 regs see no behavioural change (the
//! materialized `InstructionKind` stream is identical), and programs
//! that don't will be split across multiple chained templates by the
//! M2-M4 split machinery layered on top of this wrapping.

use std::collections::{HashMap, HashSet};

use lysis::bytecode::encoding::encode_opcode;
use lysis::bytecode::Opcode;
use lysis::lower::{AllocError, RegAllocator, RegId};
use lysis::program::Program;
use lysis::ProgramBuilder;
use memory::{FieldBackend, FieldElement, FieldFamily};

use super::extract::{lift_uniform_loops, ExtractError, TemplateRegistry, MAX_FRAME_SIZE};
use crate::extended::{IndexedEffectKind, ShiftDirection};
use crate::{ExtendedInstruction, TemplateId};
use ir_core::{Instruction, SsaVar, Visibility};

/// Hard cap on the frame size (`u8` in RFC §5.1). The walker keeps
/// each template strictly below this — see [`reg_cost_of_emit`] for
/// the per-emit cost estimator that informs the split decision.
const FRAME_CAP: u32 = 255;
/// Margin of slack reserved on top of the cap so that the executor
/// always has room for the worst-case Phase-1.5 emission (Decompose
/// can allocate up to 255 slots in one go; a runaway single emit
/// surfaces as a clean `FrameOverflow` error rather than a corrupt
/// constraint stream).
const FRAME_MARGIN: u32 = 4;

/// Hard cap on the total live-set size handled by a single
/// `compute_live_set` call, including spilled cold vars. Anything
/// beyond this is a structural overflow (~MB-scale program); the
/// walker errors out cleanly with `LiveSetTooLarge`. The 64-cap
/// inherited from Phase 3.B was the *capture* limit; in Phase 4 it
/// is the *hot-partition* limit instead — see [`MAX_CAPTURES_HOT`].
/// Total live sets up to ~65535 fit naturally because heap slots
/// are u16-indexed.
const MAX_CAPTURES: usize = u16::MAX as usize;

/// Phase 4 hot-partition budget. The first `MAX_CAPTURES_HOT`
/// live SSA vars (sorted by *first-use* in the upcoming body window,
/// not by `SsaVar.0`) are passed as `capture_regs`; the remainder
/// are spilled to the program-global heap and reloaded lazily on
/// first use in the callee body. Setting this lower than
/// `FRAME_CAP - FRAME_MARGIN` reserves headroom for emit-time
/// scratch allocations in the new frame. See research report §6.4.
const MAX_CAPTURES_HOT: usize = 48;

/// Phase 4 follow-up — switch threshold between
/// `Opcode::EmitWitnessCall` (classic, register outputs) and
/// `Opcode::EmitWitnessCallHeap` (heap outputs). When a `WitnessCall`
/// produces more than this many outputs, the walker emits the heap
/// variant because the classic path would need `outputs.len()` fresh
/// regs and exceed `FRAME_CAP = 255` structurally — a single
/// instruction whose own cost is greater than the cap can't fit in
/// any frame, no matter how much split logic is layered on top.
///
/// Threshold rationale: SHA-256 emits `WitnessCall(out=256)`; this
/// constant catches that case while leaving headroom (200) for
/// witness calls with moderate output counts to still use the
/// classic path (which avoids a heap-slot per output).
const MAX_WITNESS_OUTPUTS_INLINE: usize = 200;

/// Errors raised by [`Walker::lower`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// Register file ran out.
    Alloc(AllocError),
    /// The body contains a `TemplateCall` or `TemplateBody`; Phase
    /// 3.B.7 only emits inline + `LoopUnroll`.
    TemplateNotSupported,
    /// An instruction variant is not emittable by the walker. Phase 3
    /// punts field-division and integer-arithmetic variants that
    /// require Phase-4 opcode extensions; other variants use this for
    /// genuine "not implemented yet" surface.
    UnsupportedInstruction { kind: &'static str },
    /// A `RangeCheck` / `Decompose` bit count exceeded what the
    /// Lysis opcode can carry (u8 — max 255 bits).
    OperandOutOfRange {
        kind: &'static str,
        limit: u32,
        got: u32,
    },
    /// An operand referenced an SsaVar that was never produced by an
    /// earlier instruction in the walk. Either the program is
    /// malformed or the walker is missing a variant.
    UndefinedSsaVar(SsaVar),
    /// `LoopUnroll.start` or `LoopUnroll.end` was negative; the
    /// bytecode's `u32` bounds can't represent it.
    NegativeLoopBound { start: i64, end: i64 },
    /// A `LoopUnroll` body exceeded the `u16` byte-length field.
    LoopBodyTooLong { bytes: u32 },
    /// A top-level split was triggered but the live set exceeded
    /// [`MAX_CAPTURES`]. Forwarding more than 64 SSA vars across a
    /// single split would defeat the point of the split (the new
    /// template starts with 64 reserved capture regs already). The
    /// fix is BTA + structural extraction (Phase 2 Gap 2), which
    /// avoids the wide live set in the first place.
    LiveSetTooLarge { count: usize, max: usize },
    /// A `SymbolicIndexedEffect` reached the walker but its
    /// `index_var` could not be const-folded to a literal `usize` at
    /// walker time. Gap 1 Stage 3 const-folds Add/Sub/Mul/Neg over
    /// loop-iter constants; anything outside that surface (Decompose
    /// indices, runtime witness reads) needs Phase 4 memory-op
    /// support and is rejected here rather than miscompiled.
    SymbolicIndexedEffectNotEmittable,
    /// `SymbolicIndexedEffect.index_var` const-folded but pointed at
    /// an array slot beyond the resolved `array_slots.len()`. The
    /// instantiate-time snapshot fixed the array width; an out-of-
    /// range index (negative or ≥ width) is a logic bug at lowering
    /// or instantiation, not something the walker can fix.
    SymbolicIndexedEffectIndexOutOfRange { idx: i64, len: usize },
    /// `SymbolicIndexedEffect.kind == Let` but `value_var` is `None`
    /// — the instantiator promised a value side it didn't supply.
    /// Should be impossible if Stage 2 is wired correctly.
    SymbolicIndexedEffectMissingValue,
    /// A `SymbolicArrayRead` reached the walker but its `index_var`
    /// could not be const-folded to a literal `usize`. Same surface
    /// limitation as [`Self::SymbolicIndexedEffectNotEmittable`] — the
    /// walker's const-prop only sees Add/Sub/Mul/Neg over loop-iter
    /// constants. (Gap 1.5 Stage 3.)
    SymbolicArrayReadNotEmittable,
    /// `SymbolicArrayRead.index_var` const-folded but pointed at an
    /// array slot beyond `array_slots.len()`. Bug at lowering or
    /// instantiation, not something the walker can fix.
    SymbolicArrayReadIndexOutOfRange { idx: i64, len: usize },
    /// A `SymbolicShift` reached the walker but its `shift_var`
    /// could not be const-folded to a non-negative integer at walker
    /// time. Same surface limitation as
    /// [`Self::SymbolicArrayReadNotEmittable`] — the walker's
    /// const-prop only sees Add/Sub/Mul/Neg over loop-iter
    /// constants. (Gap 3 Stage 3.)
    SymbolicShiftNotEmittable,
    /// `SymbolicShift.shift_var` const-folded but to a negative
    /// integer. The legacy `emit_shift_right`/`emit_shift_left`
    /// path uses a `u32` shift amount so negatives are a logic bug
    /// at lowering or instantiation, not something the walker can
    /// fix.
    SymbolicShiftNegativeAmount { shift: i64 },
    /// `TemplateBody.captures.len()` did not match the declared
    /// `n_params`. The lift always sets them equal; a mismatch is a
    /// pipeline corruption. (Gap 2.)
    TemplateCapturesMismatch { n_params: u8, captures_len: usize },
    /// `TemplateCall.outputs` is non-empty. Phase 3 lift uses
    /// **Option B** (loop runs inside the template, no return values
    /// — side-effects flow through the shared sink). Output wiring
    /// via `Opcode::TemplateOutput` is a Phase 4 deliverable.
    TemplateOutputsNotSupported,
    /// `TemplateCall.template_id` references a `TemplateId` whose
    /// matching `TemplateBody` was never emitted. Either the IR
    /// stream is malformed or the `TemplateBody` declaration sits
    /// AFTER its first call site (lift always emits the body
    /// immediately before the call so this should not happen in
    /// practice).
    UndefinedTemplateId(TemplateId),
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alloc(e) => write!(f, "walker: {e}"),
            Self::TemplateNotSupported => f.write_str(
                "walker: TemplateCall/TemplateBody not emitted yet (Phase 3 MVP uses LoopUnroll only)",
            ),
            Self::UnsupportedInstruction { kind } => {
                write!(f, "walker: instruction variant `{kind}` not supported (Phase 4)")
            }
            Self::OperandOutOfRange { kind, limit, got } => {
                write!(
                    f,
                    "walker: `{kind}` operand {got} exceeds Lysis opcode limit of {limit}"
                )
            }
            Self::UndefinedSsaVar(v) => write!(f, "walker: undefined SsaVar {v}"),
            Self::NegativeLoopBound { start, end } => {
                write!(f, "walker: LoopUnroll bounds must be ≥ 0 (got {start}..{end})")
            }
            Self::LoopBodyTooLong { bytes } => {
                write!(f, "walker: LoopUnroll body length {bytes} exceeds u16 max")
            }
            Self::LiveSetTooLarge { count, max } => write!(
                f,
                "walker: live set across top-level split has {count} SSA vars, exceeding MAX_CAPTURES={max} — Phase 2 BTA needed"
            ),
            Self::SymbolicIndexedEffectNotEmittable => f.write_str(
                "walker: SymbolicIndexedEffect index could not be const-folded at walker time — only Add/Sub/Mul/Neg over loop-iter constants are supported (Phase 4 memory ops would lift this)",
            ),
            Self::SymbolicIndexedEffectIndexOutOfRange { idx, len } => write!(
                f,
                "walker: SymbolicIndexedEffect resolved to index {idx} but array has {len} slots"
            ),
            Self::SymbolicIndexedEffectMissingValue => f.write_str(
                "walker: SymbolicIndexedEffect kind=Let but value_var=None — instantiator bug",
            ),
            Self::SymbolicArrayReadNotEmittable => f.write_str(
                "walker: SymbolicArrayRead index could not be const-folded at walker time — only Add/Sub/Mul/Neg over loop-iter constants are supported (Phase 4 memory ops would lift this)",
            ),
            Self::SymbolicArrayReadIndexOutOfRange { idx, len } => write!(
                f,
                "walker: SymbolicArrayRead resolved to index {idx} but array has {len} slots"
            ),
            Self::SymbolicShiftNotEmittable => f.write_str(
                "walker: SymbolicShift amount could not be const-folded at walker time — only Add/Sub/Mul/Neg over loop-iter constants are supported (Phase 4 memory ops would lift this)",
            ),
            Self::SymbolicShiftNegativeAmount { shift } => write!(
                f,
                "walker: SymbolicShift resolved to negative shift amount {shift} — shift amounts must be non-negative"
            ),
            Self::TemplateCapturesMismatch { n_params, captures_len } => write!(
                f,
                "walker: TemplateBody declares n_params={n_params} but captures.len()={captures_len} (lift pipeline bug)"
            ),
            Self::TemplateOutputsNotSupported => f.write_str(
                "walker: TemplateCall.outputs is non-empty (Option B lift uses side-effects only; output wiring is Phase 4)",
            ),
            Self::UndefinedTemplateId(id) => write!(
                f,
                "walker: TemplateCall references {id} but no matching TemplateBody emitted yet"
            ),
        }
    }
}

impl std::error::Error for WalkError {}

impl From<AllocError> for WalkError {
    fn from(e: AllocError) -> Self {
        Self::Alloc(e)
    }
}

/// One pending template body. Phase 1.5 always opens at least one
/// (Template 0); Phase 2 split machinery will append more.
struct TemplateBuf {
    opcodes: Vec<Opcode>,
    /// Frame size = high-water mark of the allocator at close time.
    /// Stamped by `close_current_template`.
    frame_size: u8,
    /// Number of capture regs the template expects from its
    /// `InstantiateTemplate` site. The executor fills regs `0..n_params`
    /// of the callee frame with the caller's `capture_regs` before
    /// running the body, so no `LoadCapture` opcodes are needed
    /// inside the body itself — the captures are addressable directly
    /// as regs `0..n_params`.
    n_params: u8,
}

impl TemplateBuf {
    fn new(n_params: u8) -> Self {
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
    builder: ProgramBuilder<F>,
    /// Per-template opcode buffers. `templates[0]` is Template 0,
    /// always present and always the body the root frame instantiates.
    /// Phase 2 split logic appends more.
    templates: Vec<TemplateBuf>,
    /// Index of the template the walker is currently emitting into.
    current: usize,
    /// One allocator per template — reset at split boundaries. Phase
    /// 1.5 keeps a single template so the allocator never resets.
    allocator: RegAllocator,
    /// SsaVar → RegId mapping for the **current** template's frame.
    /// At a split boundary this is rebuilt for the new frame.
    ssa_to_reg: HashMap<SsaVar, RegId>,
    /// Register holding the field element 1 in the **current** frame.
    /// Lazily allocated when the body contains a desugaring that
    /// references it (Not, Assert, IsNeq, IsLe, IsLeBounded).
    one_reg: Option<RegId>,
    /// Walker-side constant-propagation map. Tracks SsaVars whose
    /// runtime value is statically known to fit in `i64` — populated
    /// by `Plain(Const)` and `Plain(Add/Sub/Mul/Neg/IntDiv/IntMod)`
    /// when all operands are themselves walker-const. Drained by
    /// `SymbolicIndexedEffect` to resolve the indexed write to a
    /// literal slot at walker time. Per-iteration unrolling is the
    /// only producer of "iter_var = literal" entries; outside that
    /// path the map only sees source-level constants.
    walker_const: HashMap<SsaVar, i64>,
    /// Maps lift-time `TemplateId` (allocated by
    /// `lysis_lift::extract::TemplateRegistry`) to the walker's
    /// internal `templates` buffer index. The IR stream uses lift
    /// IDs (sequential from 0); the walker pre-reserves index 0 for
    /// the root wrapper, so a lifted `TemplateBody { id: TemplateId(0) }`
    /// lands at buffer index 1. The wire-level `template_id` in
    /// `Opcode::InstantiateTemplate` must match the buffer index, so
    /// every `emit_template_call` translates through this map.
    template_id_map: HashMap<TemplateId, u16>,
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
    enclosing_iter_vars: Vec<SsaVar>,
    /// Phase 4 — bump allocator for heap slots. Program-global
    /// (never reset between templates). Each `StoreHeap` emission
    /// claims the next free slot id and increments this counter.
    /// `finalize()` writes the final value into the v2 header's
    /// `heap_size_hint` field so the executor pre-sizes its heap.
    heap_alloc: u16,
    /// Phase 4 — `SsaVar` → heap slot for vars that were spilled at
    /// any prior split. Persists across template boundaries (unlike
    /// `ssa_to_reg`, which is wiped at every `perform_split`). A var
    /// is in this map iff it was emitted as `StoreHeap` somewhere in
    /// the program; subsequent uses produce one `LoadHeap` per
    /// template body that references it.
    ssa_to_heap: HashMap<SsaVar, u16>,
}

impl<F: FieldBackend> Walker<F> {
    pub fn new(family: FieldFamily) -> Self {
        Self {
            builder: ProgramBuilder::new(family),
            // Template 0 takes no captures from root.
            templates: vec![TemplateBuf::new(0)],
            current: 0,
            allocator: RegAllocator::new(),
            ssa_to_reg: HashMap::new(),
            one_reg: None,
            walker_const: HashMap::new(),
            template_id_map: HashMap::new(),
            enclosing_iter_vars: Vec::new(),
            heap_alloc: 0,
            ssa_to_heap: HashMap::new(),
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
    /// frames. The pass uses `Vec` ownership; we clone `body` once at
    /// the entry point and own the lifted result thereafter.
    pub fn lower(mut self, body: &[ExtendedInstruction<F>]) -> Result<Program<F>, WalkError> {
        let mut registry = TemplateRegistry::<F>::new();
        let lifted = lift_uniform_loops(body.to_vec(), &mut registry).map_err(|e| {
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
        })?;

        // Lazy `one` loading: deferred to first desugaring that needs
        // it, so wide single-instruction templates (Decompose, Or)
        // don't pay the slot tax up-front.
        let body = lifted;
        // Precompute last-use index map once. `do_split`'s live-set
        // predicate consults this O(1) instead of rebuilding a
        // referenced-SsaVar HashSet from `body[next_idx..]` on every
        // split (148 M visits across 1,288 SHA-256(64) splits in the
        // pre-fix profile, 99 % of `walker.lower`'s wall time).
        let last_use_idx = compute_last_use_idx(&body);
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
                    self.do_split(&body, i, &last_use_idx)?;
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
        self.finalize()
    }

    /// Lazy accessor: returns the current frame's `one` register,
    /// allocating + emitting `LoadConst` on first call. Called from
    /// every desugaring that needs `one` (Not, Assert, IsNeq, IsLe,
    /// IsLeBounded). The InterningSink dedupes the resulting `Const`
    /// node across the whole program, so re-loading per template is
    /// free at the IR level.
    fn one(&mut self) -> Result<RegId, WalkError> {
        if let Some(r) = self.one_reg {
            return Ok(r);
        }
        let idx = self.builder.intern_field(FieldElement::<F>::one()) as u16;
        let reg = self.allocator.alloc()?;
        self.push_op(Opcode::LoadConst { dst: reg, idx });
        self.one_reg = Some(reg);
        Ok(reg)
    }

    /// Push an opcode into the current template's body buffer.
    fn push_op(&mut self, op: Opcode) {
        self.templates[self.current].opcodes.push(op);
    }

    /// Chain a fresh template at a top-level boundary.
    ///
    /// Pre-conditions: `next_idx < body.len()` and the allocator is
    /// at-or-past [`SPLIT_THRESHOLD`].
    ///
    /// Effects: appends `InstantiateTemplate(next_id, captures, [])`
    /// to the current template's buffer, closes it, opens a new
    /// template, binds each captured SSA var into the new frame's
    /// reg `i` via `LoadCapture(i, i)`, and re-loads the `one` const
    /// if any of the remaining instructions still need it.
    fn do_split(
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
        // Partition by first-use ordering in the upcoming body.
        // Phase 4 §6.4: the first MAX_CAPTURES_HOT (≤ 48) referenced
        // earliest stay as captures; the rest spill to the heap and
        // reload lazily on first use.
        let upcoming = &body[next_idx..];
        let (hot, cold) = partition_live_set(&live, upcoming, &HashSet::new());
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
    fn split_in_per_iter(&mut self, body: &[ExtendedInstruction<F>]) -> Result<(), WalkError> {
        let referenced = collect_referenced_ssa_vars(body);
        let enclosing: HashSet<SsaVar> = self.enclosing_iter_vars.iter().copied().collect();
        let live = self.compute_live_set(|v| referenced.contains(v) || enclosing.contains(v))?;
        dump_live_set_trace("mid_iter", live.len(), body.len(), self.current);
        // Mid-iter splits force-include enclosing iter vars in `hot`
        // regardless of first-use ordering — outer loops' iter_vars
        // must survive every inner split cheaply, and the inner
        // loop's iter_var binding is also load-bearing for the next
        // iteration's restore (Gap 4 invariant).
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
    fn compute_live_set(
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
    /// (Phase 1.5 top-level) and [`Self::split_in_per_iter`] (Gap 4
    /// mid-iter).
    ///
    /// Phase 4 spill discipline (research report §6.4):
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
    fn perform_split(&mut self, hot: &[SsaVar], cold: &[SsaVar]) -> Result<(), WalkError> {
        // Step 1: spill cold vars. Order is deterministic by SsaVar.0
        // (cold is sorted because partition_live_set returns slices of
        // the sorted live set).
        for var in cold {
            self.spill_cold_var(*var);
        }

        // Step 2: build capture_regs for the hot partition only.
        let capture_regs: Vec<u8> = hot.iter().map(|v| self.ssa_to_reg[v]).collect();
        let next_template_id = self.templates.len() as u16;

        // Tail of the outgoing template: chain the next one and
        // close. `close_current_template` stamps frame_size and
        // appends `Return`.
        self.push_op(Opcode::InstantiateTemplate {
            template_id: next_template_id,
            capture_regs,
            output_regs: Vec::new(),
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
        let mut new_ssa_to_reg = HashMap::new();
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
        // succeed (Phase 4 heap path works), then a downstream
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

    /// Phase 4 — spill a cold var to the program-global heap. Idempotent
    /// per `SsaVar`: if the var was already spilled at an earlier
    /// split (`ssa_to_heap.contains_key(&var)`), no new `StoreHeap` is
    /// emitted. This enforces the **single-static-store invariant**
    /// (research report §6.4 + validator rule 13) at the walker
    /// level, before the validator catches it.
    ///
    /// Pre-condition: `ssa_to_reg[&var]` is bound — the caller (which
    /// is always `perform_split`) has just computed the live set
    /// against `ssa_to_reg.keys()`, so every var in `cold` is by
    /// definition in `ssa_to_reg`.
    fn spill_cold_var(&mut self, var: SsaVar) {
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
    fn close_current_template(&mut self) {
        let frame_size = self.allocator.frame_size();
        let buf = &mut self.templates[self.current];
        buf.frame_size = frame_size;
        buf.opcodes.push(Opcode::Return);
    }

    /// Assemble the final Program. The body order is
    /// `[DefineTemplate(i)]*  +  InstantiateTemplate(0, [], [])  +  Halt
    /// +  [Template 0 body]  +  [Template 1 body]  +  ...`. Offsets
    /// are stamped on each `DefineTemplate` so the executor can
    /// resolve `body_offset` → instruction index.
    fn finalize(mut self) -> Result<Program<F>, WalkError> {
        self.close_current_template();

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
                    capture_regs: Vec::new(),
                    output_regs: Vec::new(),
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
        // Phase 4: stamp the heap size hint so the executor pre-sizes
        // its heap to fit every slot allocated by `spill_cold_var`.
        self.builder.set_heap_size_hint(self.heap_alloc);
        Ok(self.builder.finish())
    }

    fn emit(&mut self, inst: &ExtendedInstruction<F>) -> Result<(), WalkError> {
        match inst {
            ExtendedInstruction::Plain(i) => self.emit_plain(i),
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body,
            } => self.emit_loop_unroll(*iter_var, *start, *end, body),
            ExtendedInstruction::TemplateCall {
                template_id,
                captures,
                outputs,
            } => self.emit_template_call(*template_id, captures, outputs),
            ExtendedInstruction::TemplateBody {
                id,
                frame_size,
                n_params,
                captures,
                body,
            } => self.emit_template_body(*id, *frame_size, *n_params, captures, body),
            ExtendedInstruction::SymbolicIndexedEffect {
                kind,
                array_slots,
                index_var,
                value_var,
                span: _,
            } => self.emit_symbolic_indexed_effect(*kind, array_slots, *index_var, *value_var),
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                span: _,
            } => self.emit_symbolic_array_read(*result_var, array_slots, *index_var),
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                num_bits,
                direction,
                span: _,
            } => self.emit_symbolic_shift(
                *result_var,
                *operand_var,
                *shift_var,
                *num_bits,
                *direction,
            ),
        }
    }

    /// Resolve a `SymbolicArrayRead` at walker time. Mirrors
    /// [`Self::emit_symbolic_indexed_effect`]: const-fold the index,
    /// pick the slot, rebind `result_var` to the slot's register.
    /// Requires `walker_const[index_var]` populated; the per-iteration
    /// walker is the only producer in Phase 2.
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
    fn emit_symbolic_array_read(
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
                let name_idx = self.builder.intern_string(name) as u16;
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
    /// unroll is the only producer in Phase 2.
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
    fn emit_symbolic_shift(
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
            let zero_idx = self.builder.intern_field(FieldElement::<F>::zero()) as u16;
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
                let power_idx = self.builder.intern_field(current_power) as u16;
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
    /// Outputs are not supported in the Phase 3 lift (Option B uses
    /// side-effects only — see `WalkError::TemplateOutputsNotSupported`).
    fn emit_template_call(
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
            capture_regs,
            output_regs: Vec::new(),
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
    fn emit_template_body(
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
        // (e.g. self-recursive templates, though Phase 3 lift never
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
    /// `walker_const[index_var]` populated — Stage 3's per-iteration
    /// loop unroll is the only producer in Phase 2.
    fn emit_symbolic_indexed_effect(
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
        // and `record_last_use_in_extinst` now include `array_slots`
        // in the live-set, ensuring perform_split spills them to
        // heap. Pre-Phase-2.A the synthesis path fired for
        // input-backed slots too, silently downgrading
        // `paddedIn_X (Public)` to a fresh `__lysis_sym_slot_X
        // (Witness)` wire — the cause of the
        // `var_postdecl_padding_e2e` regression.
        let target_reg = match self.resolve(target_var) {
            Ok(reg) => reg,
            Err(WalkError::UndefinedSsaVar(_)) => {
                let name = format!("__lysis_sym_slot_{}", target_var.0);
                let name_idx = self.builder.intern_string(name) as u16;
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

    fn emit_plain(&mut self, inst: &Instruction<F>) -> Result<(), WalkError> {
        match inst {
            Instruction::Const { result, value } => {
                let idx = self.builder.intern_field(*value) as u16;
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
                let name_idx = self.builder.intern_string(name.clone()) as u16;
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
            // Phase 1.B (BETA20-CLOSEOUT, 2026-04-30) — gated the
            // `prove {}` cross-path parity since LegacySink forwards
            // `Instruction::Div` verbatim. The walker_const const-fold
            // branch is intentionally skipped: field division has no
            // compile-time meaningful result for the usize-shaped
            // walker-side constants (which model loop indices, not
            // field elements).
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
            // Desugar: IsLtBounded(x,y,bits) ignores `bits` in Phase 3;
            // the bound is a soundness-preserving optimization hint
            // (upstream already range-checked operands to fit in
            // `bits`). Emit plain IsLt; Phase 4 adds a bounded opcode.
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
                    in_regs: vec![l, r],
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
                        let msg_idx = self.builder.intern_string(msg.clone()) as u16;
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
                        let msg_idx = self.builder.intern_string(msg.clone()) as u16;
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
                result: _,
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
            // Phase 1.5 promotes IntDiv/IntMod from "deferred to Phase
            // 4" to first-class walker output: SHA-256(64) emits
            // IntDiv from `int_div(...)` calls in `padBlocks`, and
            // the HARD GATE can't close without it. The Lysis
            // bytecode carries `EmitIntDiv` / `EmitIntMod` (codes
            // 0x4D / 0x4E) with `max_bits: u8`; programs whose
            // semantic max_bits exceeds 255 surface as
            // `OperandOutOfRange` so callers learn the limit at
            // walker time rather than as a silent constraint bug.
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
            // Two emit paths based on output count (Phase 4 follow-up):
            //
            //  - **Classic** (`EmitWitnessCall`): outputs ≤
            //    `MAX_WITNESS_OUTPUTS_INLINE`. Each output gets a
            //    fresh contiguous register; reg-allocator is
            //    bump-forward.
            //
            //  - **Heap** (`EmitWitnessCallHeap`): outputs >
            //    `MAX_WITNESS_OUTPUTS_INLINE`. The classic path can't
            //    fit because a single instruction's reg cost would
            //    exceed `FRAME_CAP = 255` structurally. Outputs go to
            //    fresh heap slots instead; downstream reads
            //    materialise via `LoadHeap` through `Walker::resolve`'s
            //    lazy-reload path. Canonical case: SHA-256's 256-bit
            //    output hash (256 outputs).
            Instruction::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                let blob_idx = self.builder.intern_artik_bytecode(program_bytes.clone()) as u16;

                if outputs.len() > MAX_WITNESS_OUTPUTS_INLINE {
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
                    let mut out_slots: Vec<u16> = Vec::with_capacity(outputs.len());
                    for o in outputs {
                        let slot = self.heap_alloc;
                        self.heap_alloc = self.heap_alloc.saturating_add(1);
                        self.ssa_to_heap.insert(*o, slot);
                        out_slots.push(slot);
                    }
                    self.push_op(Opcode::EmitWitnessCallHeap {
                        bytecode_const_idx: blob_idx,
                        inputs: classified_inputs,
                        out_slots,
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
                        in_regs,
                        out_regs,
                    });
                }
            }
        }
        Ok(())
    }

    fn emit_loop_unroll(
        &mut self,
        iter_var: SsaVar,
        start: i64,
        end: i64,
        body: &[ExtendedInstruction<F>],
    ) -> Result<(), WalkError> {
        if start < 0 || end < 0 {
            return Err(WalkError::NegativeLoopBound { start, end });
        }

        // Gap 1/1.5 Stage 3: when the body (recursively, through
        // nested LoopUnrolls) contains a `SymbolicIndexedEffect` or
        // `SymbolicArrayRead`, the runtime `LoopUnroll` opcode can't
        // carry either — both need a literal `iter_var = i` on every
        // iteration so the walker can const-fold the index. Per-iter
        // unroll the body at walker time. Loops without symbolic ops
        // keep the rolled `LoopUnroll` opcode + InterningSink dedup —
        // Phase 1.5's value isn't sacrificed for the rest of the
        // program.
        //
        // Gap 4 follow-up: also fall back to per-iter unroll when the
        // body is wide enough that a single rolled emission would
        // exhaust the frame cap. Rolled emit allocs sequentially; a
        // body needing >250 slots can't fit even in a fresh-after-split
        // frame. Per-iter unroll engages mid-iter `split_in_per_iter`
        // and chains chunks under cap. SHA-256(64)'s outer round loop
        // (~1779 estimated regs in a single rolled emission) hits this
        // path post-fallback.
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
    /// **Gap 4 — mid-iter split**: when a single iteration's body
    /// would itself overflow the available frame slots, we apply a
    /// `split_in_per_iter` mid-emission, mirroring Phase 1.5's
    /// top-level split but with a live set computed against the
    /// **whole** body (because subsequent iterations re-emit
    /// `body[0..N]` from the post-split frame and need every outer
    /// SsaVar reference to remain bound). The split chains a fresh
    /// template, body emission resumes there, and `pre_body_*`
    /// snapshots refresh so the next iteration's restore-and-emit
    /// cycle works against the new frame's state.
    fn emit_loop_unroll_per_iter(
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

    fn emit_loop_unroll_per_iter_inner(
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
            let const_idx =
                self.builder
                    .intern_field(FieldElement::<F>::from_u64(u64::from(i))) as u16;
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
                        self.split_in_per_iter(body)?;
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

    fn bin(&mut self, lhs: SsaVar, rhs: SsaVar) -> Result<(RegId, RegId), WalkError> {
        // Resolve sequentially — `self.resolve` may mutate state to
        // emit a `LoadHeap` for a spilled var, so a side-effect-free
        // map().collect() over both is unsound.
        let l = self.resolve(lhs)?;
        let r = self.resolve(rhs)?;
        Ok((l, r))
    }

    /// Resolve a `SsaVar` to the reg it currently lives in. Hot path:
    /// `ssa_to_reg.get(&var)` returns `Some`. Phase 4 cold path: when
    /// a split spilled this var to the heap (`ssa_to_heap.contains(&var)`)
    /// but the new template hasn't yet materialised it, emit a
    /// `LoadHeap` into a fresh reg, cache the (var, reg) binding so
    /// subsequent uses inside the same template body see it as hot,
    /// and return the fresh reg.
    ///
    /// This is the ONLY place lazy-reload is implemented — every
    /// emission site that resolves an operand SsaVar goes through
    /// here (or through `bin` / `bin3` / direct callers), so spilled
    /// vars are rebound transparently without per-site changes.
    fn resolve(&mut self, var: SsaVar) -> Result<RegId, WalkError> {
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

    fn bind(&mut self, var: SsaVar, reg: RegId) {
        self.ssa_to_reg.insert(var, reg);
    }
}

fn map_vis(v: Visibility) -> lysis::Visibility {
    match v {
        Visibility::Public => lysis::Visibility::Public,
        Visibility::Witness => lysis::Visibility::Witness,
    }
}

/// Compute the number of bytes an `ExtendedInstruction` body would
/// occupy when encoded. Walks the body without allocating registers;
/// each Instruction's size depends only on its variant plus (for
/// vector-carrying opcodes) the count of operands — both of which
/// are independent of the specific register assignment.
fn body_byte_size<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> Result<u32, WalkError> {
    let mut total: u32 = 0;
    for inst in body {
        total = total.saturating_add(extinst_byte_size(inst)?);
    }
    Ok(total)
}

fn extinst_byte_size<F: FieldBackend>(inst: &ExtendedInstruction<F>) -> Result<u32, WalkError> {
    match inst {
        ExtendedInstruction::Plain(i) => instruction_byte_size(i),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            // 1 tag + 1 reg + 4 start + 4 end + 2 body_len = 12
            let mut total = 12u32;
            total = total.saturating_add(body_byte_size(body)?);
            Ok(total)
        }
        // TemplateCall encodes as one `InstantiateTemplate` opcode in
        // the parent's body bytes. Compute its encoded size from a
        // placeholder shape — operand widths drive the size, not the
        // specific values.
        ExtendedInstruction::TemplateCall { captures, .. } => {
            let placeholder = Opcode::InstantiateTemplate {
                template_id: 0,
                capture_regs: vec![0u8; captures.len()],
                output_regs: Vec::new(),
            };
            let mut buf = Vec::new();
            encode_opcode(&placeholder, &mut buf);
            Ok(buf.len() as u32)
        }
        // TemplateBody emits sideways into its own template buffer,
        // not into the parent's body bytes — its contribution to the
        // parent's `body_len` is zero. (Walker `emit_template_body`
        // routes the actual bytecode emission through a separate
        // TemplateBuf.)
        ExtendedInstruction::TemplateBody { .. } => Ok(0),
        // TODO Gap 1 Stage 3: replace with the synthesized per-
        // iteration cost. Until the unfolding is implemented the
        // variant cannot reach this path through normal flow — it
        // surfaces only when test fixtures construct it directly.
        ExtendedInstruction::SymbolicIndexedEffect { .. } => {
            Err(WalkError::SymbolicIndexedEffectNotEmittable)
        }
        // Read-side per-iteration alias — Stage 3 of Gap 1.5 will
        // replace this with the unfolding cost (zero opcodes; size 0)
        // once the per-iter walker rebinds slot regs.
        ExtendedInstruction::SymbolicArrayRead { .. } => {
            Err(WalkError::SymbolicArrayReadNotEmittable)
        }
        // TODO Gap 3 Stage 3: replace with the synthesised per-
        // iteration cost (one EmitDecompose plus the recompose chain
        // of Const/Mul/Add opcodes for the resolved shift amount).
        // Until the unfolding is implemented the variant cannot
        // reach this path through normal flow.
        ExtendedInstruction::SymbolicShift { .. } => Err(WalkError::SymbolicShiftNotEmittable),
    }
}

fn instruction_byte_size<F: FieldBackend>(inst: &Instruction<F>) -> Result<u32, WalkError> {
    let ops = placeholder_opcodes(inst)?;
    let mut total: u32 = 0;
    for op in ops {
        let mut buf = Vec::new();
        encode_opcode(&op, &mut buf);
        total = total.saturating_add(buf.len() as u32);
    }
    Ok(total)
}

/// Dummy `Opcode`s whose cumulative encoded size matches what the
/// walker would emit for `inst` — including multi-opcode desugarings
/// (Not → Sub; Or → Add+Mul+Sub; Assert → AssertEq; etc). Used purely
/// for size computation — real emission flows through `ProgramBuilder`.
fn placeholder_opcodes<F: FieldBackend>(inst: &Instruction<F>) -> Result<Vec<Opcode>, WalkError> {
    let bin = |op: Opcode| vec![op];
    Ok(match inst {
        Instruction::Const { .. } => bin(Opcode::LoadConst { dst: 0, idx: 0 }),
        Instruction::Input { .. } => bin(Opcode::LoadInput {
            dst: 0,
            name_idx: 0,
            vis: lysis::Visibility::Public,
        }),
        Instruction::Add { .. } => bin(Opcode::EmitAdd {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Sub { .. } => bin(Opcode::EmitSub {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Mul { .. } => bin(Opcode::EmitMul {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Neg { .. } => bin(Opcode::EmitNeg { dst: 0, operand: 0 }),
        Instruction::Mux { .. } => bin(Opcode::EmitMux {
            dst: 0,
            cond: 0,
            then_v: 0,
            else_v: 0,
        }),
        Instruction::IsEq { .. } => bin(Opcode::EmitIsEq {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::IsLt { .. } => bin(Opcode::EmitIsLt {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::PoseidonHash { .. } => bin(Opcode::EmitPoseidonHash {
            dst: 0,
            in_regs: vec![0, 0],
        }),
        Instruction::AssertEq { message, .. } => bin(if message.is_some() {
            Opcode::EmitAssertEqMsg {
                lhs: 0,
                rhs: 0,
                msg_idx: 0,
            }
        } else {
            Opcode::EmitAssertEq { lhs: 0, rhs: 0 }
        }),
        Instruction::RangeCheck { bits, .. } => bin(Opcode::EmitRangeCheck {
            var: 0,
            max_bits: *bits as u8,
        }),
        Instruction::Decompose { num_bits, .. } => bin(Opcode::EmitDecompose {
            dst_arr: 0,
            src: 0,
            n_bits: *num_bits as u8,
        }),

        // ---------- desugarings ----------
        Instruction::Not { .. } => bin(Opcode::EmitSub {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::And { .. } => bin(Opcode::EmitMul {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::Or { .. } => vec![
            Opcode::EmitAdd {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
            Opcode::EmitMul {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
            Opcode::EmitSub {
                dst: 0,
                lhs: 0,
                rhs: 0,
            },
        ],
        Instruction::Assert { message, .. } => bin(if message.is_some() {
            Opcode::EmitAssertEqMsg {
                lhs: 0,
                rhs: 0,
                msg_idx: 0,
            }
        } else {
            Opcode::EmitAssertEq { lhs: 0, rhs: 0 }
        }),

        Instruction::IsNeq { .. } | Instruction::IsLe { .. } | Instruction::IsLeBounded { .. } => {
            let cmp = match inst {
                Instruction::IsNeq { .. } => Opcode::EmitIsEq {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
                _ => Opcode::EmitIsLt {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
            };
            vec![
                cmp,
                Opcode::EmitSub {
                    dst: 0,
                    lhs: 0,
                    rhs: 0,
                },
            ]
        }
        Instruction::IsLtBounded { .. } => bin(Opcode::EmitIsLt {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),

        Instruction::WitnessCall {
            outputs, inputs, ..
        } => bin(Opcode::EmitWitnessCall {
            bytecode_const_idx: 0,
            in_regs: vec![0u8; inputs.len()],
            out_regs: vec![0u8; outputs.len()],
        }),

        // Div shipped in Phase 1.B (BETA20-CLOSEOUT 2026-04-30):
        // one 3-byte EmitDiv opcode, same shape as EmitMul. The
        // R1CS backend handles field-div semantics downstream via
        // `divide_lcs`.
        Instruction::Div { .. } => bin(Opcode::EmitDiv {
            dst: 0,
            lhs: 0,
            rhs: 0,
        }),
        Instruction::IntDiv { max_bits, .. } => {
            if *max_bits > u32::from(u8::MAX) {
                return Err(WalkError::OperandOutOfRange {
                    kind: "IntDiv.max_bits",
                    limit: u32::from(u8::MAX),
                    got: *max_bits,
                });
            }
            bin(Opcode::EmitIntDiv {
                dst: 0,
                lhs: 0,
                rhs: 0,
                max_bits: *max_bits as u8,
            })
        }
        Instruction::IntMod { max_bits, .. } => {
            if *max_bits > u32::from(u8::MAX) {
                return Err(WalkError::OperandOutOfRange {
                    kind: "IntMod.max_bits",
                    limit: u32::from(u8::MAX),
                    got: *max_bits,
                });
            }
            bin(Opcode::EmitIntMod {
                dst: 0,
                lhs: 0,
                rhs: 0,
                max_bits: *max_bits as u8,
            })
        }
    })
}

/// `true` iff `body` (recursively, including nested `LoopUnroll`
/// bodies) contains at least one symbolic-index op — either a
/// `SymbolicIndexedEffect` (write) or a `SymbolicArrayRead` (read).
/// Drives the per-iteration unrolling decision in `emit_loop_unroll`:
/// the rolled runtime `LoopUnroll` opcode can't symbolic-resolve an
/// index against a literal `iter_var`, so any loop that contains
/// either op gets per-iter walker materialisation. Stops at the
/// first hit — short-circuits via `iter::any`.
fn body_has_symbolic_op<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    body.iter().any(|inst| match inst {
        ExtendedInstruction::SymbolicIndexedEffect { .. }
        | ExtendedInstruction::SymbolicArrayRead { .. }
        | ExtendedInstruction::SymbolicShift { .. } => true,
        ExtendedInstruction::LoopUnroll { body: nested, .. } => body_has_symbolic_op(nested),
        ExtendedInstruction::Plain(_)
        | ExtendedInstruction::TemplateCall { .. }
        | ExtendedInstruction::TemplateBody { .. } => false,
    })
}

/// Returns `true` when emitting `body` as a single rolled
/// `LoopUnroll` opcode would exceed the frame cap (≥ `FRAME_CAP -
/// FRAME_MARGIN` slots in one body emission). Used to force the
/// per-iter unroll path (`emit_loop_unroll_per_iter`) for loops
/// whose bodies are too wide for the rolled form even when they
/// don't carry symbolic ops. Per-iter unroll then chains the body
/// across post-Gap-4 mid-iter splits, keeping each chunk under cap.
///
/// Threshold is `FRAME_CAP - FRAME_MARGIN`: a body whose estimated
/// reg cost crosses that line would trigger `Alloc(FrameOverflow)`
/// during a fresh-frame emit, since cost saturates against the cap.
/// Sums recursively into nested LoopUnroll bodies so an outer rolled
/// loop containing a wide inner LoopUnroll also takes the per-iter
/// path. SHA-256(64)'s outer round loop trips this — body cost
/// estimate ≈ 1779 regs for a single rolled emission.
fn body_too_wide_for_rolled<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    let mut total: u32 = 0;
    for inst in body {
        total = total.saturating_add(reg_cost_of_extinst(inst));
        if total.saturating_add(FRAME_MARGIN) >= FRAME_CAP {
            return true;
        }
    }
    false
}

/// Best-effort `FieldElement → i64` conversion for walker-side
/// const-prop. Returns `Some(v)` only when `value`'s canonical limbs
/// fit in a non-negative `i64`. Negative values (stored as
/// `field_modulus - x`) are not recovered — they wouldn't fit anyway
/// and indices are non-negative by construction.
fn field_to_i64<F: FieldBackend>(value: &FieldElement<F>) -> Option<i64> {
    let limbs = value.to_canonical();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    i64::try_from(limbs[0]).ok()
}

/// Returns `true` iff the body (recursively) contains at least one
/// instruction whose desugaring references the `one` constant register.
/// Used by [`Walker::lower`] to decide whether to eagerly emit a
/// top-level `LoadConst(1)`.
fn body_needs_one_const<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    body.iter().any(|inst| match inst {
        ExtendedInstruction::Plain(i) => instruction_needs_one(i),
        ExtendedInstruction::LoopUnroll { body, .. } => body_needs_one_const(body),
        ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => {
            false
        }
        // The variant doesn't desugar through `one` directly. Stage 3
        // unfolds it into a `Plain(Instruction)` whose `instruction_
        // needs_one` is what actually matters; until then `false` is
        // safe (the variant only reaches a frame whose other
        // instructions already drove the answer).
        ExtendedInstruction::SymbolicIndexedEffect { .. } => false,
        // Read-side never desugars through `one` — the walker rebinds
        // an existing slot reg with no extra ops.
        ExtendedInstruction::SymbolicArrayRead { .. } => false,
        // Shift desugars to Decompose + Const/Mul/Add — none of those
        // touch the `one` register either.
        ExtendedInstruction::SymbolicShift { .. } => false,
    })
}

/// Compact trace summary used by the `LYSIS_WALKER_TRACE`
/// diagnostic. Returns a one-line description that surfaces the
/// instruction kind plus the most cost-relevant operand width.
fn extinst_summary<F: FieldBackend>(inst: &ExtendedInstruction<F>) -> String {
    match inst {
        ExtendedInstruction::Plain(i) => match i {
            Instruction::Decompose { num_bits, .. } => format!("Decompose({num_bits})"),
            Instruction::WitnessCall { outputs, .. } => {
                format!("WitnessCall(out={})", outputs.len())
            }
            Instruction::Or { .. } => "Or".into(),
            Instruction::IsNeq { .. } => "IsNeq".into(),
            Instruction::IsLe { .. } => "IsLe".into(),
            Instruction::IsLeBounded { .. } => "IsLeBounded".into(),
            Instruction::IntDiv { max_bits, .. } => format!("IntDiv(max_bits={max_bits})"),
            Instruction::IntMod { max_bits, .. } => format!("IntMod(max_bits={max_bits})"),
            Instruction::Div { .. } => "Div".into(),
            other => std::any::type_name_of_val(other).to_string(),
        },
        ExtendedInstruction::LoopUnroll {
            start, end, body, ..
        } => {
            format!("LoopUnroll[{start}..{end}, body_len={}]", body.len())
        }
        ExtendedInstruction::TemplateCall { template_id, .. } => {
            format!("TemplateCall({})", template_id.0)
        }
        ExtendedInstruction::TemplateBody { .. } => "TemplateBody".into(),
        ExtendedInstruction::SymbolicIndexedEffect {
            kind,
            array_slots,
            index_var,
            ..
        } => {
            format!(
                "SymbolicIndexedEffect({:?}, slots={}, idx_var={})",
                kind,
                array_slots.len(),
                index_var
            )
        }
        ExtendedInstruction::SymbolicArrayRead {
            result_var,
            array_slots,
            index_var,
            ..
        } => {
            format!(
                "SymbolicArrayRead(result={}, slots={}, idx_var={})",
                result_var,
                array_slots.len(),
                index_var
            )
        }
        ExtendedInstruction::SymbolicShift {
            result_var,
            operand_var,
            shift_var,
            num_bits,
            direction,
            ..
        } => {
            format!(
                "SymbolicShift({:?}, result={}, op={}, shift_var={}, num_bits={})",
                direction, result_var, operand_var, shift_var, num_bits
            )
        }
    }
}

/// Estimate how many fresh registers an `ExtendedInstruction` would
/// allocate if [`Walker::emit`] handled it under the current
/// per-template allocator. Used by [`Walker::lower`] to decide
/// whether to chain a new template *before* the next emission rather
/// than letting an oversized single instruction blow past the frame
/// cap.
///
/// The numbers must over-approximate, never under-approximate — an
/// underestimate would let `emit_plain` overflow during the alloc
/// loop with no graceful split. Conservative bounds:
///
/// - Most arithmetic ops cost 1 reg (the destination).
/// - `Or` desugars to Add+Mul+Sub ⇒ 3 regs.
/// - `IsNeq`/`IsLe`/`IsLeBounded` desugar to two ops ⇒ 2 regs.
/// - `Decompose(num_bits)` allocates `num_bits` consecutive slots.
/// - `WitnessCall` allocates one reg per output.
/// - `LoopUnroll` body bodies are emitted *once* (regs shared across
///   iterations); cost is the body's cost plus 1 (iter_var).
/// - Side-effect-only ops (`AssertEq`, `Assert`, `RangeCheck`, plain
///   `Input`) consume no destination — but `Input`/`Const` do (they
///   bind the result to a fresh reg).
fn reg_cost_of_extinst<F: FieldBackend>(inst: &ExtendedInstruction<F>) -> u32 {
    match inst {
        ExtendedInstruction::Plain(i) => reg_cost_of_instruction(i),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            // 1 for iter_var + sum of body costs (body emits once).
            let mut total: u32 = 1;
            for nested in body {
                total = total.saturating_add(reg_cost_of_extinst(nested));
            }
            total
        }
        // TemplateCall emits one InstantiateTemplate opcode in the
        // parent frame; captures resolve to existing regs without
        // allocating fresh ones. TemplateBody emits sideways into
        // its own template buffer, so it contributes nothing to the
        // parent frame's reg pressure.
        ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => 0,
        // Stage 3 will materialize one synthesized scalar op per
        // iteration of the enclosing LoopUnroll. The body emits
        // ONCE in bytecode (regs shared across iterations), so the
        // per-iteration alloc count is what matters: 1 for the dst
        // wire (the array element binding) plus 0-1 for an Input
        // (WitnessHint kind only). Use 2 as a safe upper bound — it
        // over-approximates and prevents a wide indexed effect from
        // overflowing pre-emit.
        ExtendedInstruction::SymbolicIndexedEffect { .. } => 2,
        // Read-side allocates no fresh reg — the walker rebinds
        // `result_var` to the slot's already-bound register. Cost 0
        // is exact, not over-approximated.
        ExtendedInstruction::SymbolicArrayRead { .. } => 0,
        // Stage 3 emits a Decompose + recompose chain per iteration.
        // The Decompose allocates `num_bits` consecutive slots; the
        // recompose chain accumulates into one further reg. Mirror
        // `Instruction::Decompose`'s cost (which also returns
        // `num_bits`) plus one for the accumulator. The body emits
        // ONCE inside the per-iter walker loop (regs shared across
        // iterations), so this is the exact alloc count, not an
        // over-approximation.
        ExtendedInstruction::SymbolicShift { num_bits, .. } => num_bits.saturating_add(1),
    }
}

/// Count the operand SsaVars that will trigger a `LoadHeap` emit
/// plus a fresh reg alloc inside [`Walker::resolve`] when this
/// instruction is emitted. Each cold operand costs 1 reg on top of
/// the instruction's own [`reg_cost_of_extinst`] (Phase 4 follow-up).
///
/// Without this count, the split-trigger underestimates: a single
/// emit can pull 3 cold operands and a result, costing 4 regs while
/// `reg_cost_of_extinst` reports 1. That mismatch is what surfaced
/// SHA-256(64)'s `FrameOverflow { requested: 255 }` after the first
/// 9 splits succeeded (research report §7.7 + Phase 4 follow-up).
///
/// "Cold" means: in `ssa_to_heap` (was spilled at some prior split)
/// and not in `ssa_to_reg` (not currently materialised in the frame).
/// A var that is in *both* maps was already lazy-loaded in this
/// template body and the reg slot is reused; it does not re-allocate.
#[allow(clippy::doc_lazy_continuation)] // false positive: docstring is fresh, not continuing the previous fn's bullet list
fn cold_load_cost<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    ssa_to_heap: &HashMap<SsaVar, u16>,
    ssa_to_reg: &HashMap<SsaVar, RegId>,
) -> u32 {
    if ssa_to_heap.is_empty() {
        // Fast path: no spilled vars exist program-wide yet, so no
        // operand can be cold. Shortcut for the corpus baseline.
        return 0;
    }
    // Phase 4 follow-up: heap-output `WitnessCall` reads its inputs
    // directly from heap slots via `InputSrc::Slot` — no `LoadHeap`
    // is emitted for cold inputs, so cold operands cost 0 frame regs.
    // Mirror the walker's emit-time branch in `emit_plain` so the
    // split-trigger doesn't over-estimate and fragment the program
    // unnecessarily.
    if let ExtendedInstruction::Plain(Instruction::WitnessCall { outputs, .. }) = inst {
        if outputs.len() > MAX_WITNESS_OUTPUTS_INLINE {
            return 0;
        }
    }
    let mut refs = HashSet::new();
    collect_in_extinst(inst, &mut refs);
    refs.iter()
        .filter(|v| ssa_to_heap.contains_key(v) && !ssa_to_reg.contains_key(v))
        .count() as u32
}

fn reg_cost_of_instruction<F: FieldBackend>(inst: &Instruction<F>) -> u32 {
    match inst {
        // Side-effect-only — no destination reg.
        Instruction::AssertEq { .. }
        | Instruction::Assert { .. }
        | Instruction::RangeCheck { .. } => 0,

        // Single-destination ops.
        Instruction::Const { .. }
        | Instruction::Input { .. }
        | Instruction::Add { .. }
        | Instruction::Sub { .. }
        | Instruction::Mul { .. }
        | Instruction::Div { .. }
        | Instruction::Neg { .. }
        | Instruction::Not { .. }
        | Instruction::And { .. }
        | Instruction::Mux { .. }
        | Instruction::IsEq { .. }
        | Instruction::IsLt { .. }
        | Instruction::IsLtBounded { .. }
        | Instruction::PoseidonHash { .. }
        | Instruction::IntDiv { .. }
        | Instruction::IntMod { .. } => 1,

        // Multi-step desugarings.
        Instruction::Or { .. } => 3,
        Instruction::IsNeq { .. } | Instruction::IsLe { .. } | Instruction::IsLeBounded { .. } => 2,

        // Variable-cost ops.
        Instruction::Decompose { num_bits, .. } => *num_bits,
        Instruction::WitnessCall { outputs, .. } => {
            // Outputs above the threshold land in heap slots, not
            // regs (Phase 4 follow-up). The cost estimator must
            // mirror the walker's emit-time branch: heap-output
            // variant is `cost = 0` for the frame, classic variant is
            // `cost = outputs.len()`.
            if outputs.len() > MAX_WITNESS_OUTPUTS_INLINE {
                0
            } else {
                outputs.len() as u32
            }
        }
    }
}

fn instruction_needs_one<F: FieldBackend>(inst: &Instruction<F>) -> bool {
    matches!(
        inst,
        Instruction::Not { .. }
            | Instruction::Assert { .. }
            | Instruction::IsNeq { .. }
            | Instruction::IsLe { .. }
            | Instruction::IsLeBounded { .. }
    )
}

/// Env-gated tracer for [`Walker::compute_live_set`] outcomes.
///
/// Set `LYSIS_DUMP_LIVESET=1` to emit one stderr line per accepted
/// split (rejected splits trace inside `compute_live_set` itself,
/// since they short-circuit before the caller sees the live count).
/// The output format is stable and grep-friendly:
///
/// ```text
/// [walker] live_set kind=top_level live=12 body=24 template=3
/// [walker] live_set kind=mid_iter  live=7  body=18 template=5
/// [walker] live_set kind=rejected  live=250 cap=64
/// ```
///
/// Intended for the Phase 4 research corpus pass: pipe a test run's
/// stderr through `grep '\[walker\] live_set' | awk '{print $3}' |
/// sort | uniq -c` to build the histogram referenced in
/// `.claude/plans/lysis-phase4-research-report.md` §2.7.1.
fn dump_live_set_trace(kind: &str, live_count: usize, body_len: usize, template_id: usize) {
    if std::env::var("LYSIS_DUMP_LIVESET").is_ok() {
        eprintln!(
            "[walker] live_set kind={kind} live={live_count} body={body_len} template={template_id}"
        );
    }
}

/// Phase 4 — partition a sorted live set into (hot, cold) by
/// **first-use index** in the upcoming body window. Vars referenced
/// earliest in the body are hot (passed as captures); vars referenced
/// later (or never within the scanned window) are cold (spilled to
/// the heap, reloaded lazily).
///
/// `force_hot` collects vars that must ride in the hot partition
/// regardless of first-use ordering — for `split_in_per_iter`, the
/// enclosing loop's iter_vars (Gap 4 invariant: outer iter_var must
/// survive every inner split cheaply, since the next-iteration
/// restore re-binds it from `ssa_to_reg`).
///
/// Tie-break: vars with equal first-use index sort by `SsaVar.0`
/// (the input order). This keeps capture slot ids deterministic
/// across runs even when many vars first appear in the same opcode.
///
/// Time complexity: O(scan_window + live.len() * log(live.len())).
/// Caller bounds the scan window at ≤ 256 instructions to keep this
/// O(N).
fn partition_live_set<F: FieldBackend>(
    live: &[SsaVar],
    upcoming_body: &[ExtendedInstruction<F>],
    force_hot: &HashSet<SsaVar>,
) -> (Vec<SsaVar>, Vec<SsaVar>) {
    // Scan window: bound at 256 to amortise O(N) over the whole
    // walker pass. SHA-256(64) round bodies are well under 256
    // instructions; for circuits with longer prologues the cap means
    // we under-promote a few late-referenced hot vars to cold, which
    // costs one LoadHeap each (≤ 1ms in the SHA-256 measurement).
    const SCAN_WINDOW: usize = 256;
    let scan = &upcoming_body[..upcoming_body.len().min(SCAN_WINDOW)];

    // Build first-use index. usize::MAX = "never seen in window".
    let mut first_use: HashMap<SsaVar, usize> = HashMap::with_capacity(live.len());
    let mut referenced_in_inst = HashSet::new();
    for (i, inst) in scan.iter().enumerate() {
        referenced_in_inst.clear();
        collect_in_extinst(inst, &mut referenced_in_inst);
        for v in &referenced_in_inst {
            first_use.entry(*v).or_insert(i);
        }
    }

    // Sort the live set by (force_hot first, then first_use, then SsaVar.0).
    // `force_hot` is collapsed to first_use=0 to push them to the front.
    let mut sorted = live.to_vec();
    sorted.sort_by_key(|v| {
        let key0 = if force_hot.contains(v) { 0 } else { 1 };
        let key1 = first_use.get(v).copied().unwrap_or(usize::MAX);
        (key0, key1, v.0)
    });

    let cap = MAX_CAPTURES_HOT.min(sorted.len());
    let cold = sorted.split_off(cap);
    let mut hot = sorted;
    // hot must come back sorted by SsaVar.0 to match the existing
    // capture-slot stability contract (compute_live_set sorts that
    // way before partition; perform_split assigns slot i = hot[i]).
    // The first-use ordering above is just for selection; once we've
    // picked `cap` hot vars, re-sort them by SsaVar.0 so capture
    // slots are deterministic.
    hot.sort_unstable_by_key(|v| v.0);
    let mut cold = cold;
    cold.sort_unstable_by_key(|v| v.0);
    (hot, cold)
}

/// Walk an `ExtendedInstruction` slice (recursing into LoopUnroll
/// bodies) and collect every SSA var that appears as an *operand*
/// — `result` slots are ignored because they are produced by the
/// instruction, not consumed. Used by [`Walker::do_split`] to
/// compute the live capture set at a top-level boundary.
///
/// Returns the FULL referenced set; never early-returns. The
/// previous early-return at `MAX_CAPTURES` was unsound: when a body
/// referenced more than `MAX_CAPTURES` distinct vars, vars that
/// happened to first appear after the cap were silently dropped from
/// the set. `compute_live_set` then filtered `ssa_to_reg` against an
/// incomplete set, dropping live vars from the post-split frame and
/// surfacing later as `UndefinedSsaVar` at the unbound consumer
/// (canonical case: SHA-256(64), where ~250 vars span any do_split).
/// Scanning the full body is O(N); the caller decides whether the
/// result fits via `compute_live_set`.
fn collect_referenced_ssa_vars<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> HashSet<SsaVar> {
    let mut out = HashSet::new();
    for inst in body {
        collect_in_extinst(inst, &mut out);
    }
    out
}

/// Collect every `SsaVar` *defined* (as a `result` / output) anywhere in
/// `body`. Mirrors [`collect_referenced_ssa_vars`] on the write side and
/// recurses through nested `LoopUnroll` / `TemplateBody` bodies so a
/// SsaVar produced N levels deep is still reported as body-defined at
/// the top level.
///
/// Used by [`Walker::emit_loop_unroll_per_iter_inner`] to strip
/// body-defined entries from `ssa_to_heap` at every iter restore: each
/// per-iter walk re-binds these vars to fresh values, so any prior
/// spill-and-dedup would silently forward iter-0's stale value to
/// iter-1+. Stripping forces the next mid-iter split to allocate a
/// fresh slot per iter, preserving validator rule 13's
/// single-static-store invariant *and* the per-iter SSA-after-unroll
/// semantics (each iter's body-defined values are distinct).
fn collect_defined_ssa_vars<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> HashSet<SsaVar> {
    let mut out = HashSet::new();
    for inst in body {
        collect_defined_in_extinst(inst, &mut out);
    }
    out
}

fn collect_defined_in_extinst<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    out: &mut HashSet<SsaVar>,
) {
    match inst {
        ExtendedInstruction::Plain(i) => {
            out.insert(i.result_var());
            for v in i.extra_result_vars() {
                out.insert(*v);
            }
        }
        ExtendedInstruction::LoopUnroll { body, .. } => {
            for nested in body {
                collect_defined_in_extinst(nested, out);
            }
        }
        ExtendedInstruction::TemplateBody { body, .. } => {
            for nested in body {
                collect_defined_in_extinst(nested, out);
            }
        }
        ExtendedInstruction::TemplateCall { outputs, .. } => {
            for v in outputs {
                out.insert(*v);
            }
        }
        ExtendedInstruction::SymbolicArrayRead { result_var, .. } => {
            out.insert(*result_var);
        }
        ExtendedInstruction::SymbolicShift { result_var, .. } => {
            out.insert(*result_var);
        }
        ExtendedInstruction::SymbolicIndexedEffect { .. } => {
            // Side-effect-only — writes into a slot the parent template
            // owns. No new SsaVar produced at this level.
        }
    }
}

/// Precompute, for every SSA var referenced anywhere in `body`, the
/// highest top-level body index at which it is referenced. The
/// `do_split` predicate `v ∈ referenced(body[next_idx..])` is then
/// equivalent to `last_use_idx[v] >= next_idx`.
///
/// The recursion mirrors [`collect_in_extinst`] exactly: references
/// inside a `LoopUnroll.body` count as references at the **outer**
/// body index that contains the LoopUnroll, because that is the
/// boundary at which a top-level split decides whether to capture
/// them.
///
/// Replaces the per-`do_split` rebuild that scanned `body[next_idx..]`
/// from scratch on every split (148 M instruction visits across 1,288
/// SHA-256(64) splits → 5.96 s in `walker.lower`). One forward pass
/// here is O(N) and the per-split cost drops to O(|ssa_to_reg|).
fn compute_last_use_idx<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> HashMap<SsaVar, usize> {
    let mut out: HashMap<SsaVar, usize> = HashMap::new();
    for (i, inst) in body.iter().enumerate() {
        record_last_use_in_extinst(inst, i, &mut out);
    }
    out
}

fn record_last_use_in_extinst<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    idx: usize,
    out: &mut HashMap<SsaVar, usize>,
) {
    match inst {
        ExtendedInstruction::Plain(i) => record_last_use_in_instruction(i, idx, out),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            for nested in body {
                record_last_use_in_extinst(nested, idx, out);
            }
        }
        ExtendedInstruction::TemplateCall { captures, .. } => {
            for v in captures {
                bump_last_use(out, *v, idx);
            }
        }
        ExtendedInstruction::TemplateBody { .. } => {}
        ExtendedInstruction::SymbolicIndexedEffect {
            array_slots,
            index_var,
            value_var,
            ..
        } => {
            // Mirrors `collect_in_extinst`: every slot in
            // `array_slots` is an enclosing-scope SsaVar (the parent
            // template's signal-element wire) and must survive any
            // top-level split between the LoopUnroll and its parent.
            // Without this, the live-set drops them and
            // `emit_symbolic_indexed_effect`'s synth-on-demand
            // fallback fires inside the post-split template,
            // creating a fresh witness wire that diverges from the
            // parent's `Public`-visibility binding.
            for slot in array_slots {
                bump_last_use(out, *slot, idx);
            }
            bump_last_use(out, *index_var, idx);
            if let Some(v) = value_var {
                bump_last_use(out, *v, idx);
            }
        }
        ExtendedInstruction::SymbolicArrayRead {
            array_slots,
            index_var,
            ..
        } => {
            for slot in array_slots {
                bump_last_use(out, *slot, idx);
            }
            bump_last_use(out, *index_var, idx);
        }
        ExtendedInstruction::SymbolicShift {
            operand_var,
            shift_var,
            ..
        } => {
            bump_last_use(out, *operand_var, idx);
            bump_last_use(out, *shift_var, idx);
        }
    }
}

fn record_last_use_in_instruction<F: FieldBackend>(
    inst: &Instruction<F>,
    idx: usize,
    out: &mut HashMap<SsaVar, usize>,
) {
    match inst {
        Instruction::Const { .. } | Instruction::Input { .. } => {}
        Instruction::Add { lhs, rhs, .. }
        | Instruction::Sub { lhs, rhs, .. }
        | Instruction::Mul { lhs, rhs, .. }
        | Instruction::Div { lhs, rhs, .. }
        | Instruction::And { lhs, rhs, .. }
        | Instruction::Or { lhs, rhs, .. }
        | Instruction::IsEq { lhs, rhs, .. }
        | Instruction::IsLt { lhs, rhs, .. }
        | Instruction::IsNeq { lhs, rhs, .. }
        | Instruction::IsLe { lhs, rhs, .. }
        | Instruction::IsLtBounded { lhs, rhs, .. }
        | Instruction::IsLeBounded { lhs, rhs, .. }
        | Instruction::AssertEq { lhs, rhs, .. }
        | Instruction::IntDiv { lhs, rhs, .. }
        | Instruction::IntMod { lhs, rhs, .. } => {
            bump_last_use(out, *lhs, idx);
            bump_last_use(out, *rhs, idx);
        }
        Instruction::Neg { operand, .. }
        | Instruction::Not { operand, .. }
        | Instruction::Assert { operand, .. }
        | Instruction::RangeCheck { operand, .. }
        | Instruction::Decompose { operand, .. } => {
            bump_last_use(out, *operand, idx);
        }
        Instruction::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => {
            bump_last_use(out, *cond, idx);
            bump_last_use(out, *if_true, idx);
            bump_last_use(out, *if_false, idx);
        }
        Instruction::PoseidonHash { left, right, .. } => {
            bump_last_use(out, *left, idx);
            bump_last_use(out, *right, idx);
        }
        Instruction::WitnessCall { inputs, .. } => {
            for v in inputs {
                bump_last_use(out, *v, idx);
            }
        }
    }
}

#[inline]
fn bump_last_use(out: &mut HashMap<SsaVar, usize>, v: SsaVar, idx: usize) {
    out.entry(v)
        .and_modify(|j| {
            if idx > *j {
                *j = idx;
            }
        })
        .or_insert(idx);
}

fn collect_in_extinst<F: FieldBackend>(inst: &ExtendedInstruction<F>, out: &mut HashSet<SsaVar>) {
    match inst {
        ExtendedInstruction::Plain(i) => collect_in_instruction(i, out),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            for nested in body {
                collect_in_extinst(nested, out);
            }
        }
        // TemplateCall.captures are uses in the parent scope — must
        // cross any top-level split between the call and its
        // surrounding template.
        ExtendedInstruction::TemplateCall { captures, .. } => {
            for v in captures {
                out.insert(*v);
            }
        }
        // TemplateBody emits sideways into its own template frame
        // and references its captures internally via reg 0..n_params.
        // The captures already appear in the matching TemplateCall's
        // capture list (guaranteed by the lift), so the live-set scan
        // doesn't need to add them again here.
        ExtendedInstruction::TemplateBody { .. } => {}
        // The variant references `index_var`, (for Let) `value_var`,
        // AND every SSA var in `array_slots` — the slots are sibling
        // `Plain(Input)` emissions in the parent template (for public
        // signal outputs the slots are pre-emitted; for internal
        // signals the symbolic emit path synthesizes them) and must
        // cross any top-level split that lands between the parent
        // template and the LoopUnroll. Pre-Phase-2.A this collector
        // omitted `array_slots` and relied on the synth-on-demand
        // fallback at `emit_symbolic_indexed_effect`'s `ssa_to_reg.
        // get(target).is_none()` branch to mint fresh `LoadInput`
        // wires inside the post-split template — but the synthesis
        // turned `paddedIn_X (Public)` into `__lysis_sym_slot_X
        // (Witness)`, leaving the public output wire unconstrained
        // and breaking witness eval (the witness map keyed by the
        // original Public name no longer matches the synthesized
        // Witness name). Carrying the slots through the live-set
        // forces `perform_split` to spill them to heap; the post-
        // split `resolve()` then auto-faults them via `LoadHeap` and
        // the synthesis branch becomes unreachable for input-backed
        // slots. (The synthesis path still survives as a fallback
        // for genuinely-internal signal slots that were never backed
        // by a `Plain(Input)` — those are witness wires by design.)
        ExtendedInstruction::SymbolicIndexedEffect {
            array_slots,
            index_var,
            value_var,
            ..
        } => {
            for slot in array_slots {
                out.insert(*slot);
            }
            out.insert(*index_var);
            if let Some(v) = value_var {
                out.insert(*v);
            }
        }
        // Read-side mirrors the write-side rationale; see above.
        ExtendedInstruction::SymbolicArrayRead {
            array_slots,
            index_var,
            ..
        } => {
            for slot in array_slots {
                out.insert(*slot);
            }
            out.insert(*index_var);
        }
        // Both `operand_var` and `shift_var` are enclosing-scope uses
        // that must cross any top-level split between the LoopUnroll's
        // parent template and the LoopUnroll itself. `result_var` is
        // a definition produced by the shift expansion, so it isn't
        // an operand.
        ExtendedInstruction::SymbolicShift {
            operand_var,
            shift_var,
            ..
        } => {
            out.insert(*operand_var);
            out.insert(*shift_var);
        }
    }
}

fn collect_in_instruction<F: FieldBackend>(inst: &Instruction<F>, out: &mut HashSet<SsaVar>) {
    match inst {
        Instruction::Const { .. } | Instruction::Input { .. } => {}
        Instruction::Add { lhs, rhs, .. }
        | Instruction::Sub { lhs, rhs, .. }
        | Instruction::Mul { lhs, rhs, .. }
        | Instruction::Div { lhs, rhs, .. }
        | Instruction::And { lhs, rhs, .. }
        | Instruction::Or { lhs, rhs, .. }
        | Instruction::IsEq { lhs, rhs, .. }
        | Instruction::IsLt { lhs, rhs, .. }
        | Instruction::IsNeq { lhs, rhs, .. }
        | Instruction::IsLe { lhs, rhs, .. }
        | Instruction::IsLtBounded { lhs, rhs, .. }
        | Instruction::IsLeBounded { lhs, rhs, .. }
        | Instruction::AssertEq { lhs, rhs, .. }
        | Instruction::IntDiv { lhs, rhs, .. }
        | Instruction::IntMod { lhs, rhs, .. } => {
            out.insert(*lhs);
            out.insert(*rhs);
        }
        Instruction::Neg { operand, .. }
        | Instruction::Not { operand, .. }
        | Instruction::Assert { operand, .. }
        | Instruction::RangeCheck { operand, .. }
        | Instruction::Decompose { operand, .. } => {
            out.insert(*operand);
        }
        Instruction::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => {
            out.insert(*cond);
            out.insert(*if_true);
            out.insert(*if_false);
        }
        Instruction::PoseidonHash { left, right, .. } => {
            out.insert(*left);
            out.insert(*right);
        }
        Instruction::WitnessCall { inputs, .. } => {
            for v in inputs {
                out.insert(*v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lysis::{execute, InterningSink, LysisConfig};
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use ir_core::Visibility as IrVisibility;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    fn plain(inst: Instruction<Bn254Fr>) -> ExtendedInstruction<Bn254Fr> {
        ExtendedInstruction::Plain(inst)
    }

    /// Emit + execute the body through a fresh InterningSink; return
    /// the materialized `Vec<InstructionKind>`.
    fn run(body: &[ExtendedInstruction<Bn254Fr>]) -> Vec<lysis::InstructionKind<Bn254Fr>> {
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(body).expect("lower");
        let mut sink = InterningSink::<Bn254Fr>::new();
        execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
        sink.materialize()
    }

    #[test]
    fn lowers_empty_body_to_halt_only() {
        let out = run(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn lowers_const_add_const() {
        let body = vec![
            plain(Instruction::Const {
                result: ssa(0),
                value: fe(7),
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(3),
            }),
            plain(Instruction::Add {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        // Two Consts + one Add.
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], lysis::InstructionKind::Const { .. }));
        assert!(matches!(out[1], lysis::InstructionKind::Const { .. }));
        assert!(matches!(out[2], lysis::InstructionKind::Add { .. }));
    }

    #[test]
    fn lowers_range_check_and_decompose() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::RangeCheck {
                result: ssa(0),
                operand: ssa(0),
                bits: 8,
            }),
            plain(Instruction::Decompose {
                result: ssa(0),
                bit_results: vec![ssa(1), ssa(2), ssa(3), ssa(4)],
                operand: ssa(0),
                num_bits: 4,
            }),
        ];
        let out = run(&body);
        // Input + RangeCheck + Decompose = 3 instructions.
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], lysis::InstructionKind::Input { .. }));
        assert!(matches!(out[1], lysis::InstructionKind::RangeCheck { .. }));
        let bit_count = match &out[2] {
            lysis::InstructionKind::Decompose { bit_results, .. } => bit_results.len(),
            _ => panic!(),
        };
        assert_eq!(bit_count, 4);
    }

    #[test]
    fn lowers_assert_eq_side_effect() {
        let body = vec![
            plain(Instruction::Const {
                result: ssa(0),
                value: fe(5),
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(5),
            }),
            plain(Instruction::AssertEq {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
                message: None,
            }),
        ];
        let out = run(&body);
        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 1);
    }

    #[test]
    fn lowers_loop_unroll_three_iterations() {
        // for i in 0..3: r_mul = i * i
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 3,
            body: vec![plain(Instruction::Mul {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(0),
            })],
        }];
        let out = run(&body);
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let muls = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
            .count();
        assert_eq!(consts, 3, "one Const per iteration (iter_var)");
        assert_eq!(muls, 3, "three Muls, one per iteration");
    }

    #[test]
    fn unfolds_symbolic_indexed_effect_per_iteration() {
        // Outer body sets up the slot wires + value source via real
        // Plain(Input) ops so the walker has them in `ssa_to_reg`
        // when the LoopUnroll body runs (mirrors the public-output
        // array case where slots are pre-emitted by scaffold).
        // SymbolicIndexedEffect(Let, [v_a, v_b, v_c], iter_var,
        // value_var) inside `for i in 0..3` should unroll into 3
        // AssertEqs, one per slot.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "slot_a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "slot_b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(2),
                name: "slot_c".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(3),
                name: "value".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(4),
                start: 0,
                end: 3,
                body: vec![ExtendedInstruction::SymbolicIndexedEffect {
                    kind: IndexedEffectKind::Let,
                    array_slots: vec![ssa(0), ssa(1), ssa(2)],
                    index_var: ssa(4),
                    value_var: Some(ssa(3)),
                    span: None,
                }],
            },
        ];
        let out = run(&body);

        // Inputs: 4 distinct names, all preserved.
        let inputs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
            .count();
        assert_eq!(inputs, 4, "4 named Inputs");

        // Consts: 3 distinct iter values (0, 1, 2). The InterningSink
        // dedupes equal values, but here all three are distinct.
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        assert_eq!(consts, 3, "one Const per iteration");

        // AssertEqs: 3 (one per iteration), never dedupe (side-effect).
        let asserts: Vec<_> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
                _ => None,
            })
            .collect();
        assert_eq!(asserts.len(), 3, "3 AssertEqs");
        // Each AssertEq's lhs should be the slot wire (Input result),
        // each rhs should be the value Input. Distinct lhs → 3 unique.
        let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
        assert_eq!(lhs_set.len(), 3, "3 distinct slot lhs");
        let rhs_set: std::collections::HashSet<_> = asserts.iter().map(|(_, r)| *r).collect();
        assert_eq!(rhs_set.len(), 1, "all 3 rhs point at the same value Input");
    }

    #[test]
    fn unfolds_symbolic_indexed_effect_with_affine_index() {
        // Body: for i in 0..3 { array[i + 2] := value }
        // The index `i + 2` is computed inside the body via a Const(2)
        // + Add op; walker_const must pick it up so the slot resolves
        // to array_slots[2..=4]. Pre-allocate 5 slots to host idx 2..4.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "s0".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "s1".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(2),
                name: "s2".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(3),
                name: "s3".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(4),
                name: "s4".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(5),
                name: "value".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(6),
                start: 0,
                end: 3,
                body: vec![
                    plain(Instruction::Const {
                        result: ssa(7),
                        value: fe(2),
                    }),
                    plain(Instruction::Add {
                        result: ssa(8),
                        lhs: ssa(6),
                        rhs: ssa(7),
                    }),
                    ExtendedInstruction::SymbolicIndexedEffect {
                        kind: IndexedEffectKind::Let,
                        array_slots: vec![ssa(0), ssa(1), ssa(2), ssa(3), ssa(4)],
                        index_var: ssa(8),
                        value_var: Some(ssa(5)),
                        span: None,
                    },
                ],
            },
        ];
        let out = run(&body);

        // 3 AssertEqs, lhs picking up slot 2, 3, 4 (i + 2 for i in 0..3).
        let asserts: Vec<_> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
                _ => None,
            })
            .collect();
        assert_eq!(asserts.len(), 3, "3 AssertEqs");
        let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
        assert_eq!(lhs_set.len(), 3, "3 distinct slots picked (i+2 for i=0..3)");
    }

    #[test]
    fn rejects_symbolic_indexed_effect_when_index_not_const_foldable() {
        // Index_var depends on an Input (runtime), not a loop-iter
        // const → walker can't resolve. Expect the dedicated error.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "slot".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "runtime_idx".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(2),
                name: "value".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(3),
                start: 0,
                end: 1,
                body: vec![ExtendedInstruction::SymbolicIndexedEffect {
                    kind: IndexedEffectKind::Let,
                    array_slots: vec![ssa(0)],
                    index_var: ssa(1),
                    value_var: Some(ssa(2)),
                    span: None,
                }],
            },
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert!(
            matches!(err, WalkError::SymbolicIndexedEffectNotEmittable),
            "got {err:?}"
        );
    }

    #[test]
    fn unfolds_symbolic_array_read_per_iteration() {
        // Outer body pre-emits 3 slot Inputs + a sink-target Input.
        // Inside `for i in 0..3 { sink := arr[i] }` the read binds
        // result_var to slot_i's reg per iteration; the trailing
        // AssertEq materialises one constraint per iteration with
        // rhs pointing at the iteration-specific slot.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "slot_a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "slot_b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(2),
                name: "slot_c".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(3),
                name: "sink_target".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(4),
                start: 0,
                end: 3,
                body: vec![
                    ExtendedInstruction::SymbolicArrayRead {
                        result_var: ssa(5),
                        array_slots: vec![ssa(0), ssa(1), ssa(2)],
                        index_var: ssa(4),
                        span: None,
                    },
                    plain(Instruction::AssertEq {
                        result: ssa(6),
                        lhs: ssa(3),
                        rhs: ssa(5),
                        message: None,
                    }),
                ],
            },
        ];
        let out = run(&body);

        // 4 named Inputs preserved.
        let inputs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
            .count();
        assert_eq!(inputs, 4);

        // 3 AssertEqs (one per iteration). Each rhs picks up a
        // different slot's reg because result_var rebinds per-iter.
        let asserts: Vec<_> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
                _ => None,
            })
            .collect();
        assert_eq!(asserts.len(), 3, "3 AssertEqs");
        let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
        assert_eq!(lhs_set.len(), 1, "all 3 lhs share the sink_target reg");
        let rhs_set: std::collections::HashSet<_> = asserts.iter().map(|(_, r)| *r).collect();
        assert_eq!(
            rhs_set.len(),
            3,
            "3 distinct slot rhs (rebind per iteration)"
        );
    }

    #[test]
    fn unfolds_symbolic_array_read_with_affine_index() {
        // Body: for i in 0..3 { sink := arr[i + 2] }. Index is computed
        // inside the body via Const(2) + Add; walker_const tracks the
        // fold and the read picks slots 2..=4.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "s0".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "s1".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(2),
                name: "s2".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(3),
                name: "s3".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(4),
                name: "s4".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(5),
                name: "sink_target".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(6),
                start: 0,
                end: 3,
                body: vec![
                    plain(Instruction::Const {
                        result: ssa(7),
                        value: fe(2),
                    }),
                    plain(Instruction::Add {
                        result: ssa(8),
                        lhs: ssa(6),
                        rhs: ssa(7),
                    }),
                    ExtendedInstruction::SymbolicArrayRead {
                        result_var: ssa(9),
                        array_slots: vec![ssa(0), ssa(1), ssa(2), ssa(3), ssa(4)],
                        index_var: ssa(8),
                        span: None,
                    },
                    plain(Instruction::AssertEq {
                        result: ssa(10),
                        lhs: ssa(5),
                        rhs: ssa(9),
                        message: None,
                    }),
                ],
            },
        ];
        let out = run(&body);

        let asserts: Vec<_> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
                _ => None,
            })
            .collect();
        assert_eq!(asserts.len(), 3, "3 AssertEqs");
        let rhs_set: std::collections::HashSet<_> = asserts.iter().map(|(_, r)| *r).collect();
        assert_eq!(rhs_set.len(), 3, "3 distinct slots picked (i+2 for i=0..3)");
    }

    #[test]
    fn rejects_symbolic_array_read_when_index_not_const_foldable() {
        // Index_var depends on a runtime Input (not a loop-iter
        // const) — walker can't resolve. Expect the dedicated error.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "slot".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "runtime_idx".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 1,
                body: vec![ExtendedInstruction::SymbolicArrayRead {
                    result_var: ssa(3),
                    array_slots: vec![ssa(0)],
                    index_var: ssa(1),
                    span: None,
                }],
            },
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert!(
            matches!(err, WalkError::SymbolicArrayReadNotEmittable),
            "got {err:?}"
        );
    }

    #[test]
    fn synthesises_witness_when_symbolic_array_read_slot_unbound() {
        // array_slots contains an SsaVar that was never pre-emitted —
        // the read-side now mirrors `emit_symbolic_indexed_effect` and
        // synthesises a witness `LoadInput` on demand. The output
        // stream materialises one Input for the slot and the read
        // result aliases it.
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 1,
            body: vec![ExtendedInstruction::SymbolicArrayRead {
                result_var: ssa(1),
                // ssa(99) is never bound by any earlier instruction;
                // the read-side now synthesises it as a witness wire.
                array_slots: vec![ssa(99)],
                index_var: ssa(0),
                span: None,
            }],
        }];
        let out = run(&body);

        // One synthesised Input (`__lysis_sym_slot_99`).
        let inputs: Vec<&str> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::Input { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(inputs.len(), 1, "one synthesised slot input");
        assert!(
            inputs[0].starts_with("__lysis_sym_slot_"),
            "synth name prefix: got {:?}",
            inputs[0]
        );
    }

    #[test]
    fn unfolds_symbolic_shift_per_iteration() {
        // Body: for i in 0..3 { sink := operand >> i }. Per-iteration
        // the walker resolves shift_var=i to a literal, decomposes
        // operand to 4 bits, and recomposes the kept high bits. We
        // count Decompose ops (one per iter, no dedup at executor
        // level since each iter's emission is structurally unique
        // until BTA Stage 4 lifts it) and AssertEqs (one per iter).
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "operand".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "sink".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 3,
                body: vec![
                    ExtendedInstruction::SymbolicShift {
                        result_var: ssa(3),
                        operand_var: ssa(0),
                        shift_var: ssa(2),
                        num_bits: 4,
                        direction: ShiftDirection::Right,
                        span: None,
                    },
                    plain(Instruction::AssertEq {
                        result: ssa(4),
                        lhs: ssa(1),
                        rhs: ssa(3),
                        message: None,
                    }),
                ],
            },
        ];
        let out = run(&body);

        // 3 Decomposes (one per iteration of the rolled loop).
        let decomps = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
            .count();
        assert_eq!(decomps, 3, "3 Decomposes, one per iteration");

        // 3 AssertEqs (one per iter). Each rhs picks up a different
        // recomposed wire because the kept-bit set + powers vary.
        let asserts: Vec<_> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::AssertEq { lhs, rhs, .. } => Some((*lhs, *rhs)),
                _ => None,
            })
            .collect();
        assert_eq!(asserts.len(), 3, "3 AssertEqs");
        let lhs_set: std::collections::HashSet<_> = asserts.iter().map(|(l, _)| *l).collect();
        assert_eq!(lhs_set.len(), 1, "all 3 lhs share the sink reg");
    }

    #[test]
    fn unfolds_symbolic_shift_left_with_affine_amount() {
        // Body: for i in 0..3 { sink := operand << (i + 1) }. Index is
        // computed inside the body via Const(1) + Add; walker_const
        // tracks the fold and the shift resolves to 1, 2, 3.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "operand".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "sink".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 3,
                body: vec![
                    plain(Instruction::Const {
                        result: ssa(3),
                        value: fe(1),
                    }),
                    plain(Instruction::Add {
                        result: ssa(4),
                        lhs: ssa(2),
                        rhs: ssa(3),
                    }),
                    ExtendedInstruction::SymbolicShift {
                        result_var: ssa(5),
                        operand_var: ssa(0),
                        shift_var: ssa(4),
                        num_bits: 4,
                        direction: ShiftDirection::Left,
                        span: None,
                    },
                    plain(Instruction::AssertEq {
                        result: ssa(6),
                        lhs: ssa(1),
                        rhs: ssa(5),
                        message: None,
                    }),
                ],
            },
        ];
        let out = run(&body);

        // Each iteration runs a Decompose. 3 iterations → 3 Decomposes.
        let decomps = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
            .count();
        assert_eq!(decomps, 3, "3 Decomposes, one per iteration");

        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 3, "3 AssertEqs");
    }

    #[test]
    fn rejects_symbolic_shift_when_amount_not_const_foldable() {
        // shift_var depends on a runtime Input (not a loop-iter const)
        // — walker can't resolve. Expect the dedicated error.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "operand".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "runtime_shift".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 1,
                body: vec![ExtendedInstruction::SymbolicShift {
                    result_var: ssa(3),
                    operand_var: ssa(0),
                    shift_var: ssa(1),
                    num_bits: 4,
                    direction: ShiftDirection::Right,
                    span: None,
                }],
            },
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert!(
            matches!(err, WalkError::SymbolicShiftNotEmittable),
            "got {err:?}"
        );
    }

    #[test]
    fn symbolic_shift_full_drop_yields_zero_const() {
        // shift = num_bits → result is the constant zero. The walker
        // emits one LoadConst(0) per iteration and no Decompose.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "operand".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(8),
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 1,
                body: vec![ExtendedInstruction::SymbolicShift {
                    result_var: ssa(3),
                    operand_var: ssa(0),
                    // shift_var bound to the source-level Const(8) so
                    // walker_const resolves to 8 — equals num_bits.
                    shift_var: ssa(1),
                    num_bits: 8,
                    direction: ShiftDirection::Right,
                    span: None,
                }],
            },
        ];
        let out = run(&body);

        let decomps = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
            .count();
        assert_eq!(decomps, 0, "no Decompose when shift drops everything");
    }

    #[test]
    fn refuses_template_call_with_outputs() {
        // Phase 3 Option B lift uses side-effects only — non-empty
        // outputs are reserved for Phase 4 (Opcode::TemplateOutput
        // wiring). Verify the walker rejects them rather than
        // silently miscompiling.
        let body = vec![ExtendedInstruction::TemplateCall {
            template_id: crate::TemplateId(0),
            captures: vec![],
            outputs: vec![ssa(0)],
        }];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse outputs");
        assert_eq!(err, WalkError::TemplateOutputsNotSupported);
    }

    #[test]
    fn rejects_template_body_captures_mismatch() {
        // n_params declares 2 but captures has 1 → pipeline corruption.
        let body = vec![ExtendedInstruction::TemplateBody {
            id: crate::TemplateId(1),
            frame_size: 4,
            n_params: 2,
            captures: vec![ssa(0)],
            body: vec![],
        }];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse mismatch");
        assert!(matches!(
            err,
            WalkError::TemplateCapturesMismatch {
                n_params: 2,
                captures_len: 1
            }
        ));
    }

    #[test]
    fn walker_lower_lifts_uniform_loops_internally() {
        // Stage 4 wiring: Walker::lower runs lift_uniform_loops as
        // its first step. A bare Uniform LoopUnroll handed to the
        // walker should land as a 2-template program (Template 0
        // root wrapper + Template 1 lifted body), even though the
        // caller never built the lift output explicitly.
        let outer_input = ssa(0);
        let iter_var = ssa(1);
        let body = vec![
            plain(Instruction::Input {
                result: outer_input,
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start: 0,
                end: 3,
                body: vec![plain(Instruction::Mul {
                    result: ssa(2),
                    lhs: outer_input,
                    rhs: outer_input,
                })],
            },
        ];

        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower OK");
        // Lift produced a template; walker has root + lifted = 2.
        assert_eq!(program.templates.len(), 2);
        assert_eq!(program.templates[1].n_params, 1, "outer_input captured");
    }

    #[test]
    fn lowers_template_body_plus_call_pair() {
        // Lift-shaped fixture: an outer Plain(Input) becomes an
        // OuterRef capture; a TemplateBody wraps a tiny LoopUnroll
        // that uses the captured input; a TemplateCall instantiates
        // it. The walker should emit one root template (Template 0,
        // the wrapper) plus the lifted template body. The execution
        // dispatch is exercised by lysis e2e tests; here we just
        // verify the walker doesn't error and produces a non-empty
        // program with the expected number of templates.
        let outer_input = ssa(0);
        let iter_var = ssa(1);
        let lifted = ExtendedInstruction::TemplateBody {
            id: crate::TemplateId(1),
            frame_size: 4,
            n_params: 1,
            captures: vec![outer_input],
            body: vec![ExtendedInstruction::LoopUnroll {
                iter_var,
                start: 0,
                end: 2,
                body: vec![plain(Instruction::Mul {
                    result: ssa(2),
                    lhs: outer_input,
                    rhs: outer_input,
                })],
            }],
        };
        let body = vec![
            plain(Instruction::Input {
                result: outer_input,
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            lifted,
            ExtendedInstruction::TemplateCall {
                template_id: crate::TemplateId(1),
                captures: vec![outer_input],
                outputs: vec![],
            },
        ];

        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower OK");
        // Templates: 0 (root wrapper) + 1 (lifted) = 2.
        assert_eq!(program.templates.len(), 2);
        // Template 1 carries n_params=1 (the captured outer input).
        assert_eq!(program.templates[1].n_params, 1);
        assert!(program.templates[1].frame_size >= 1);
    }

    #[test]
    fn refuses_negative_loop_bound() {
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: -1,
            end: 2,
            body: vec![],
        }];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert!(matches!(err, WalkError::NegativeLoopBound { .. }));
    }

    #[test]
    fn desugars_not_to_sub_with_one() {
        // Not(x) = 1 - x. Expect: LoadConst(1), Input(x), Sub(one, x).
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Not {
                result: ssa(1),
                operand: ssa(0),
            }),
        ];
        let out = run(&body);
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(consts, 1, "one pre-allocated Const for `one`");
        assert_eq!(subs, 1, "Not desugars to one Sub");
    }

    #[test]
    fn desugars_and_to_mul() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::And {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        // And does NOT need `one` — no extra Const emitted.
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let muls = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
            .count();
        assert_eq!(consts, 0, "no one-const needed when only And is used");
        assert_eq!(muls, 1, "And desugars to one Mul");
    }

    #[test]
    fn desugars_or_to_add_mul_sub() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Or {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        let adds = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Add { .. }))
            .count();
        let muls = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Mul { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(adds, 1);
        assert_eq!(muls, 1);
        assert_eq!(subs, 1);
    }

    #[test]
    fn desugars_assert_to_assert_eq_with_one() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Assert {
                result: ssa(1),
                operand: ssa(0),
                message: None,
            }),
        ];
        let out = run(&body);
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(consts, 1, "one pre-allocated Const for `one`");
        assert_eq!(asserts, 1, "Assert(x) desugars to AssertEq(x, one)");
    }

    #[test]
    fn desugars_not_inside_loop_body() {
        // The `one` Const is emitted ABOVE the loop so body_byte_size
        // stays correct. Use iter bounds that avoid collision with 1
        // (which would get hash-cons deduped against `one`): 3..6.
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 3,
            end: 6,
            body: vec![plain(Instruction::Not {
                result: ssa(1),
                operand: ssa(0),
            })],
        }];
        let out = run(&body);
        // Expect: 1 one-const + 3 distinct iter consts (3, 4, 5) + 3 Subs.
        let consts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Const { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(consts, 4, "one + 3 distinct iter vars");
        assert_eq!(subs, 3, "Not per iteration");
    }

    #[test]
    fn desugars_is_neq_to_is_eq_plus_sub() {
        // IsNeq(x,y) = 1 - IsEq(x,y).
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::IsNeq {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        let eqs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::IsEq { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(eqs, 1);
        assert_eq!(subs, 1);
    }

    #[test]
    fn desugars_is_le_to_is_lt_reversed_plus_sub() {
        // IsLe(x,y) = 1 - IsLt(y, x).
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::IsLe {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        let lts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::IsLt { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(lts, 1);
        assert_eq!(subs, 1);
    }

    #[test]
    fn desugars_is_lt_bounded_ignores_bitwidth_hint() {
        // In Phase 3 IsLtBounded lowers to plain IsLt; no extra Const/Sub.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::IsLtBounded {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
                bitwidth: 16,
            }),
        ];
        let out = run(&body);
        let lts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::IsLt { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(lts, 1);
        assert_eq!(subs, 0);
    }

    #[test]
    fn desugars_is_le_bounded_like_is_le() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::IsLeBounded {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
                bitwidth: 8,
            }),
        ];
        let out = run(&body);
        let lts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::IsLt { .. }))
            .count();
        let subs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Sub { .. }))
            .count();
        assert_eq!(lts, 1);
        assert_eq!(subs, 1);
    }

    #[test]
    fn lowers_witness_call_with_blob_and_multiple_outputs() {
        // Blob content is not validated at this layer — the walker just
        // interns the bytes and lets the executor decode.
        let blob = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::WitnessCall {
                outputs: vec![ssa(1), ssa(2), ssa(3)],
                inputs: vec![ssa(0)],
                program_bytes: blob,
            }),
        ];
        // `run` goes through a full execute via InterningSink. WitnessCall
        // is a side-effect that produces OPAQUE output slots — the
        // InterningSink does NOT dedupe it. We expect one WitnessCall in
        // the materialized output with 3 output slots.
        let out = run(&body);
        let calls: Vec<_> = out
            .iter()
            .filter_map(|i| match i {
                lysis::InstructionKind::WitnessCall { outputs, .. } => Some(outputs.len()),
                _ => None,
            })
            .collect();
        assert_eq!(calls, vec![3]);
    }

    #[test]
    fn lowers_div_to_emit_div() {
        // Phase 1.B (BETA20-CLOSEOUT 2026-04-30) promoted field Div
        // from "walker-rejected" to first-class output: `EmitDiv`
        // emits `Instruction::Div` to the sink, which the R1CS
        // backend lowers via `divide_lcs`. Required for `prove {}`
        // cross-path parity (LegacySink forwards Div verbatim).
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Div {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let out = run(&body);
        let divs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Div { .. }))
            .count();
        assert_eq!(divs, 1, "Div survives the walker");
    }

    #[test]
    fn lowers_int_div_and_int_mod() {
        // Phase 1.5 promoted IntDiv/IntMod from "rejected" to walker
        // output: SHA-256 needs them, so the bytecode now carries
        // EmitIntDiv / EmitIntMod opcodes. Verify materialized stream
        // contains both.
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::IntDiv {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
                max_bits: 8,
            }),
            plain(Instruction::IntMod {
                result: ssa(3),
                lhs: ssa(0),
                rhs: ssa(1),
                max_bits: 8,
            }),
        ];
        let out = run(&body);
        let divs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::IntDiv { .. }))
            .count();
        let mods = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::IntMod { .. }))
            .count();
        assert_eq!(divs, 1, "IntDiv survives the walker");
        assert_eq!(mods, 1, "IntMod survives the walker");
    }

    #[test]
    fn refuses_int_div_max_bits_overflow() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "a".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "b".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::IntDiv {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
                max_bits: 300,
            }),
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker
            .lower(&body)
            .expect_err("max_bits > u8 should refuse");
        assert!(matches!(
            err,
            WalkError::OperandOutOfRange {
                kind: "IntDiv.max_bits",
                ..
            }
        ));
    }

    #[test]
    fn refuses_range_check_bits_overflow() {
        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::RangeCheck {
                result: ssa(1),
                operand: ssa(0),
                bits: 300,
            }),
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert_eq!(
            err,
            WalkError::OperandOutOfRange {
                kind: "RangeCheck.bits",
                limit: 255,
                got: 300,
            }
        );
    }

    #[test]
    fn lowers_witness_call_empty_inputs() {
        // Zero inputs, single output.
        let body = vec![plain(Instruction::WitnessCall {
            outputs: vec![ssa(0)],
            inputs: vec![],
            program_bytes: vec![0xFF],
        })];
        let out = run(&body);
        let call_count = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::WitnessCall { .. }))
            .count();
        assert_eq!(call_count, 1);
    }

    #[test]
    fn witness_call_under_threshold_emits_classic_variant() {
        // 200 outputs is exactly at the threshold; classic path
        // because `outputs.len() > MAX_WITNESS_OUTPUTS_INLINE` is
        // false when outputs.len() == 200.
        let outputs: Vec<SsaVar> = (0..200u32).map(ssa).collect();
        let body = vec![plain(Instruction::WitnessCall {
            outputs,
            inputs: vec![],
            program_bytes: vec![0xFF],
        })];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");

        let classic_count = program
            .body
            .iter()
            .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCall { .. }))
            .count();
        let heap_count = program
            .body
            .iter()
            .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCallHeap { .. }))
            .count();
        assert_eq!(classic_count, 1);
        assert_eq!(heap_count, 0);
        assert_eq!(
            program.header.heap_size_hint, 0,
            "classic variant should not allocate heap slots"
        );
    }

    #[test]
    fn witness_call_over_threshold_emits_heap_variant() {
        // 256 outputs (canonical SHA-256 case): walker must switch
        // to the heap-output variant because classic would need 256
        // fresh regs and overflow `FRAME_CAP = 255`.
        let outputs: Vec<SsaVar> = (0..256u32).map(ssa).collect();
        let body = vec![plain(Instruction::WitnessCall {
            outputs,
            inputs: vec![],
            program_bytes: vec![0xFF],
        })];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");

        let classic_count = program
            .body
            .iter()
            .filter(|i| matches!(i.opcode, lysis::Opcode::EmitWitnessCall { .. }))
            .count();
        let heap_calls: Vec<&lysis::Opcode> = program
            .body
            .iter()
            .map(|i| &i.opcode)
            .filter(|op| matches!(op, lysis::Opcode::EmitWitnessCallHeap { .. }))
            .collect();
        assert_eq!(classic_count, 0);
        assert_eq!(heap_calls.len(), 1);
        if let lysis::Opcode::EmitWitnessCallHeap { out_slots, .. } = heap_calls[0] {
            assert_eq!(
                out_slots.len(),
                256,
                "256 outputs land in 256 distinct slots"
            );
        }
        assert_eq!(
            program.header.heap_size_hint, 256,
            "heap_size_hint reflects allocated slots"
        );
    }

    #[test]
    fn witness_call_heap_outputs_lazy_load_via_resolve_on_first_use() {
        // After the heap-variant call, an instruction that consumes
        // an output must trigger a `LoadHeap` emit through resolve().
        let outputs: Vec<SsaVar> = (0..256u32).map(ssa).collect();
        let body = vec![
            plain(Instruction::WitnessCall {
                outputs,
                inputs: vec![],
                program_bytes: vec![0xFF],
            }),
            // Reference output ssa(0) — should LoadHeap from slot 0
            // and then AssertEq it against itself (a trivial use).
            plain(Instruction::AssertEq {
                result: ssa(1000),
                lhs: ssa(0),
                rhs: ssa(0),
                message: None,
            }),
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");

        let load_heap_count = program
            .body
            .iter()
            .filter(|i| matches!(i.opcode, lysis::Opcode::LoadHeap { .. }))
            .count();
        assert!(
            load_heap_count >= 1,
            "expected at least one LoadHeap for ssa(0), got {load_heap_count}"
        );
    }

    /// Build a body that allocates more than `SPLIT_THRESHOLD` regs in
    /// the root frame so the walker is forced to chain a second
    /// template. The chain must remain semantically equivalent: every
    /// allocated wire is consumed by the final `AssertEq`, so split
    /// boundaries that drop a live var would surface as
    /// `UndefinedSsaVar`.
    #[test]
    fn split_fires_on_300_sequential_adds() {
        // x = Input; acc_0 = x; acc_{k+1} = acc_k + x; assert acc_300 == y.
        // 300 Adds → 301 reg allocations in root, comfortably past the
        // 240-reg threshold.
        let mut body = Vec::new();
        body.push(plain(Instruction::Input {
            result: ssa(0),
            name: "y".into(),
            visibility: IrVisibility::Public,
        }));
        body.push(plain(Instruction::Input {
            result: ssa(1),
            name: "x".into(),
            visibility: IrVisibility::Witness,
        }));
        for k in 0..300 {
            body.push(plain(Instruction::Add {
                result: ssa(2 + k),
                lhs: ssa(1 + k),
                rhs: ssa(1),
            }));
        }
        body.push(plain(Instruction::AssertEq {
            result: ssa(0xDEAD),
            lhs: ssa(2 + 299),
            rhs: ssa(0),
            message: None,
        }));

        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");
        // ≥ 2 templates means the split fired at least once.
        assert!(
            program.templates.len() >= 2,
            "expected split to chain ≥2 templates, got {}",
            program.templates.len()
        );
        // The split machinery never overflows the frame cap. Pre-emit
        // cost prediction can land a body right at FRAME_CAP -
        // FRAME_MARGIN, which for an Add (cost = 1) is slot 250.
        for t in &program.templates {
            assert!(
                t.frame_size <= 251,
                "template {} frame_size {} should stay near cap",
                t.id,
                t.frame_size
            );
        }
        // Execute through InterningSink and confirm the materialized
        // stream contains the AssertEq + 300 Adds (post-dedup the Adds
        // collapse to far fewer, but the AssertEq must survive).
        let mut sink = InterningSink::<Bn254Fr>::new();
        execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
        let out = sink.materialize();
        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 1, "AssertEq must survive across the split");
        // The two Inputs (x, y) must also survive — they're side-effects.
        let inputs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
            .count();
        assert_eq!(inputs, 2, "Inputs preserved across split");
    }

    /// Gap 4: a per-iter unrolled body whose single iteration would
    /// itself overflow the frame cap must trigger a mid-iter split. The
    /// chain must remain semantically equivalent across iterations:
    /// every iteration completes its body, the iter_var literal flows
    /// across the split (so SymbolicShift / SymbolicArrayRead still
    /// const-fold), and no template ever crosses [`FRAME_CAP`].
    #[test]
    fn mid_iter_split_handles_wide_per_iter_body() {
        // Per-iter body: SymbolicShift (forces per-iter unroll +
        // exercises the iter_var literal forwarding) + ~250 Adds
        // whose results are not consumed downstream. Each Add still
        // allocates a fresh reg so the alloc tally crosses
        // `FRAME_CAP - FRAME_MARGIN` mid-body, but the SsaVars stay
        // OUT of the live set (no later instruction references them),
        // keeping the capture count well under MAX_CAPTURES.
        const ADD_FAT_LEN: u32 = 250;
        let mut iter_body = Vec::new();
        iter_body.push(ExtendedInstruction::SymbolicShift {
            result_var: ssa(3),
            operand_var: ssa(0),
            shift_var: ssa(2),
            num_bits: 4,
            direction: ShiftDirection::Right,
            span: None,
        });
        for k in 0..ADD_FAT_LEN {
            iter_body.push(plain(Instruction::Add {
                result: ssa(100 + k),
                lhs: ssa(0),
                rhs: ssa(0),
            }));
        }
        // Final SymbolicShift: re-uses iter_var post-split. If the
        // walker_const[iter_var] forwarding is broken, this errors
        // with `SymbolicShiftNotEmittable`.
        iter_body.push(ExtendedInstruction::SymbolicShift {
            result_var: ssa(50),
            operand_var: ssa(0),
            shift_var: ssa(2),
            num_bits: 4,
            direction: ShiftDirection::Left,
            span: None,
        });
        // Side-effect: AssertEq survives interning across the split.
        iter_body.push(plain(Instruction::AssertEq {
            result: ssa(0xDEAD),
            lhs: ssa(50),
            rhs: ssa(1),
            message: None,
        }));

        let body = vec![
            plain(Instruction::Input {
                result: ssa(0),
                name: "operand".into(),
                visibility: IrVisibility::Witness,
            }),
            plain(Instruction::Input {
                result: ssa(1),
                name: "sink".into(),
                visibility: IrVisibility::Witness,
            }),
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 2,
                body: iter_body,
            },
        ];

        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");

        assert!(
            program.templates.len() >= 2,
            "expected mid-iter split to chain ≥2 templates, got {}",
            program.templates.len()
        );

        for t in &program.templates {
            assert!(
                t.frame_size <= 251,
                "template {} frame_size {} should stay near cap",
                t.id,
                t.frame_size
            );
        }

        // Both iterations must complete — at least one AssertEq per
        // iteration survives interning. The exact count after dedup is
        // ≥ 1; we assert ≥ 1 so the test is robust to interner tuning
        // but still proves the mid-split body executes through.
        let mut sink = InterningSink::<Bn254Fr>::new();
        execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
        let out = sink.materialize();
        let asserts = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::AssertEq { .. }))
            .count();
        assert!(
            asserts >= 1,
            "AssertEq must survive mid-iter splits, got {}",
            asserts
        );
        // Both Inputs survive (side-effects).
        let inputs = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Input { .. }))
            .count();
        assert_eq!(inputs, 2, "Inputs preserved across mid-iter split");
        // Decomposes survive — one per iteration of the rolled loop,
        // each in a different post-split frame for iters that crossed
        // a boundary. Lower bound: 1 (post-interning the structurally
        // identical decomposes may collapse).
        let decomps = out
            .iter()
            .filter(|i| matches!(i, lysis::InstructionKind::Decompose { .. }))
            .count();
        assert!(
            decomps >= 1,
            "Decompose from SymbolicShift must survive mid-iter split, got {}",
            decomps
        );
    }

    /// Even when no split is needed (small program), the walker still
    /// wraps the body in Template 0. Verify the template count is 1.
    #[test]
    fn small_program_uses_exactly_one_template() {
        let body = vec![
            plain(Instruction::Const {
                result: ssa(0),
                value: fe(7),
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(3),
            }),
            plain(Instruction::Add {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");
        assert_eq!(
            program.templates.len(),
            1,
            "small body should fit in Template 0 with no chain"
        );
    }

    // ---------------------------------------------------------------
    // Phase 4 — partition_live_set unit tests + heap-emission smoke.
    // ---------------------------------------------------------------

    #[test]
    fn partition_under_hot_cap_all_hot() {
        let live: Vec<SsaVar> = (0..10).map(ssa).collect();
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        let force = HashSet::new();
        let (hot, cold) = partition_live_set(&live, &body, &force);
        assert_eq!(hot.len(), 10);
        assert!(cold.is_empty());
    }

    #[test]
    fn partition_above_hot_cap_splits_at_max_captures_hot() {
        let live: Vec<SsaVar> = (0..60).map(ssa).collect();
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        let force = HashSet::new();
        let (hot, cold) = partition_live_set(&live, &body, &force);
        assert_eq!(hot.len(), MAX_CAPTURES_HOT);
        assert_eq!(cold.len(), 60 - MAX_CAPTURES_HOT);
    }

    #[test]
    fn partition_first_use_drives_hot_selection() {
        // 100 live vars; only ssa(50)..=ssa(97) are referenced in the
        // upcoming body window (in ascending order). Those 48
        // referenced-earliest become hot; the rest (0..50, 98, 99) cold.
        let live: Vec<SsaVar> = (0..100).map(ssa).collect();
        let body: Vec<ExtendedInstruction<Bn254Fr>> = (50u32..=97u32)
            .map(|i| {
                plain(Instruction::Add {
                    result: ssa(1000 + i),
                    lhs: ssa(i),
                    rhs: ssa(i),
                })
            })
            .collect();
        let force = HashSet::new();
        let (hot, cold) = partition_live_set(&live, &body, &force);
        assert_eq!(hot.len(), MAX_CAPTURES_HOT);
        let hot_set: HashSet<SsaVar> = hot.iter().copied().collect();
        for i in 50u32..=97 {
            assert!(hot_set.contains(&ssa(i)), "ssa({i}) should be hot");
        }
        // ssa(0..49) + ssa(98) + ssa(99) → all cold (52 items)
        assert_eq!(cold.len(), 100 - MAX_CAPTURES_HOT);
    }

    #[test]
    fn partition_force_hot_overrides_first_use() {
        // ssa(99) has first_use = MAX (not in body) but is force_hot.
        let mut live: Vec<SsaVar> = (0..50).map(ssa).collect();
        live.push(ssa(99));
        let body: Vec<ExtendedInstruction<Bn254Fr>> = (0u32..50)
            .map(|i| {
                plain(Instruction::Add {
                    result: ssa(1000 + i),
                    lhs: ssa(i),
                    rhs: ssa(i),
                })
            })
            .collect();
        let mut force = HashSet::new();
        force.insert(ssa(99));
        let (hot, cold) = partition_live_set(&live, &body, &force);
        assert!(
            hot.contains(&ssa(99)),
            "force_hot must override first-use ordering"
        );
        assert_eq!(hot.len(), MAX_CAPTURES_HOT);
        // 51 total - 48 hot = 3 cold
        assert_eq!(cold.len(), 51 - MAX_CAPTURES_HOT);
    }

    #[test]
    fn partition_outputs_sorted_by_ssa_var_id() {
        // The capture-slot stability contract requires hot/cold both
        // be sorted by SsaVar.0; the first-use selection happens
        // internally but does not leak into the output ordering.
        let live: Vec<SsaVar> = (0..60).map(ssa).collect();
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        let force = HashSet::new();
        let (hot, cold) = partition_live_set(&live, &body, &force);
        for w in hot.windows(2) {
            assert!(w[0].0 < w[1].0, "hot must be sorted by SsaVar.0");
        }
        for w in cold.windows(2) {
            assert!(w[0].0 < w[1].0, "cold must be sorted by SsaVar.0");
        }
    }

    /// Phase 4 §6.5 Commit 5.5 — heuristic vs naive comparison.
    ///
    /// Builds a synthetic post-split body where the live set has 100
    /// vars and the body references ssa(60..=99) earliest, then
    /// ssa(0..=59). With `MAX_CAPTURES_HOT=48`, the **first-use
    /// heuristic** picks ssa(60..=99) + 8 more (the 48 hot) and
    /// spills 52 cold; the **naive ordering** picks ssa(0..=47) hot
    /// and spills ssa(48..=99) cold.
    ///
    /// Observed metric: `LoadHeap` emissions in the first half of
    /// the body (the "early window"). The heuristic should always
    /// produce ≤ naive count there, since vars referenced earliest
    /// stay hot.
    ///
    /// Decision rule from research report §6.5: if the win is
    /// < 5 % the simpler naive ordering replaces the heuristic; if
    /// ≥ 20 % the heuristic is justified. This test prints the
    /// numbers so the user can read them during the Commit 5.5 sign-off
    /// without needing a separate criterion harness, and asserts the
    /// monotonicity property (heuristic never *worse* than naive on
    /// this fixture).
    #[test]
    fn heuristic_vs_naive_first_use_advantage() {
        let live: Vec<SsaVar> = (0..100).map(ssa).collect();
        // Body: first half references ssa(60..=99) (40 vars), second
        // half references ssa(0..=59) (60 vars). The first-use
        // heuristic captures 60..=99 + ssa(0..=7) = 48; naive
        // captures 0..=47 = 48 (different set).
        let body: Vec<ExtendedInstruction<Bn254Fr>> = (60u32..100)
            .chain(0u32..60)
            .map(|i| {
                plain(Instruction::Add {
                    result: ssa(1000 + i),
                    lhs: ssa(i),
                    rhs: ssa(i),
                })
            })
            .collect();
        let force = HashSet::new();

        let (heur_hot, heur_cold) = partition_live_set(&live, &body, &force);

        // Naive partition: sort live by SsaVar.0, take first 48 as hot.
        let mut sorted_live = live.clone();
        sorted_live.sort_unstable_by_key(|v| v.0);
        let naive_hot: Vec<SsaVar> = sorted_live[..MAX_CAPTURES_HOT].to_vec();
        let naive_cold: Vec<SsaVar> = sorted_live[MAX_CAPTURES_HOT..].to_vec();

        // For each strategy, count *unique* cold vars referenced
        // anywhere in the *first half* of the body (the early
        // window). Each unique cold var produces exactly one
        // `LoadHeap` per template body that references it (per
        // walker contract enforced by `Walker::resolve`).
        let count_loads_first_half = |cold: &[SsaVar]| -> usize {
            let cold_set: std::collections::HashSet<_> = cold.iter().copied().collect();
            let mut loaded: std::collections::HashSet<SsaVar> = std::collections::HashSet::new();
            for inst in body.iter().take(body.len() / 2) {
                let mut refs = std::collections::HashSet::new();
                collect_in_extinst(inst, &mut refs);
                for v in refs {
                    if cold_set.contains(&v) {
                        loaded.insert(v);
                    }
                }
            }
            loaded.len()
        };

        let heur_loads = count_loads_first_half(&heur_cold);
        let naive_loads = count_loads_first_half(&naive_cold);

        // Visible report — captured by `cargo test -- --nocapture` for
        // the §6.5 sign-off.
        eprintln!(
            "[lysis-spill-bench] heuristic_loads={heur_loads} \
             naive_loads={naive_loads} \
             win_pct={:.1}",
            if naive_loads == 0 {
                0.0
            } else {
                (naive_loads as f64 - heur_loads as f64) * 100.0 / naive_loads as f64
            }
        );

        // Sanity: hot and cold partition the live set in both cases.
        assert_eq!(heur_hot.len() + heur_cold.len(), live.len());
        assert_eq!(naive_hot.len() + naive_cold.len(), live.len());

        // Monotonicity: heuristic must not produce *more* LoadHeaps
        // in the early window than naive ordering. If this fails,
        // the heuristic has regressed and we should investigate
        // before keeping it (research report §6.5 + Reviewer 1.2).
        assert!(
            heur_loads <= naive_loads,
            "heuristic emitted {heur_loads} LoadHeaps in early window vs naive {naive_loads}; \
             expected heuristic ≤ naive (first-use ordering should never lose to SsaVar.0 ordering)"
        );
    }

    #[test]
    fn small_body_emits_no_heap_ops() {
        // Sanity: a program that fits in MAX_CAPTURES_HOT ought to
        // emit zero heap opcodes and leave heap_size_hint at 0. This
        // is the "no regression for the existing corpus" gate.
        let body = vec![
            plain(Instruction::Const {
                result: ssa(0),
                value: fe(7),
            }),
            plain(Instruction::Const {
                result: ssa(1),
                value: fe(3),
            }),
            plain(Instruction::Add {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }),
        ];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let program = walker.lower(&body).expect("lower");
        assert_eq!(program.header.heap_size_hint, 0);
        let heap_ops = program
            .body
            .iter()
            .filter(|i| {
                matches!(
                    i.opcode,
                    lysis::Opcode::StoreHeap { .. } | lysis::Opcode::LoadHeap { .. }
                )
            })
            .count();
        assert_eq!(heap_ops, 0);
    }
}
