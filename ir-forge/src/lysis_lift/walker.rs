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
use crate::extended::IndexedEffectKind;
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

/// Hard cap on the number of live SSA vars we forward as captures
/// across a split. Matches RFC §5.1: `InstantiateTemplate.capture_regs`
/// is length-prefixed by a `u8` (max 255), and the receiving frame
/// only has 255 reg slots, of which we want most available for actual
/// work in the new template body.
const MAX_CAPTURES: usize = 64;

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
    /// `SymbolicArrayRead` resolved its slot to an `SsaVar` that has
    /// no register binding. Read-side cannot synthesise a witness
    /// wire on demand the way `SymbolicIndexedEffect` does — a read
    /// of an unbound slot means upstream forgot to pre-emit the
    /// declaring `Plain(Input)` or `WitnessArrayDecl`. Surfaces the
    /// missing slot index for diagnosis.
    SymbolicArrayReadUnboundSlot { idx: usize, slot: SsaVar },
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
            Self::SymbolicArrayReadUnboundSlot { idx, slot } => write!(
                f,
                "walker: SymbolicArrayRead slot at index {idx} (SsaVar {slot}) has no register binding — upstream pre-emission missed this slot"
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
        for (i, inst) in body.iter().enumerate() {
            // Pre-emit split decision. Skip the check at i == 0 —
            // the allocator is at most at 1 (just the `one` const)
            // so no instruction can overflow on its first emission.
            if i > 0 {
                let cost = reg_cost_of_extinst(inst);
                let projected = self.allocator.next_slot().saturating_add(cost);
                if projected.saturating_add(FRAME_MARGIN) >= FRAME_CAP {
                    self.do_split(&body, i)?;
                }
            }
            self.emit(inst).map_err(|e| match e {
                WalkError::Alloc(_) => {
                    if std::env::var("LYSIS_WALKER_TRACE").is_ok() {
                        eprintln!(
                            "[walker] frame overflow at body idx {i}: {} (slot={}, cost_est={})",
                            extinst_summary(inst),
                            self.allocator.next_slot(),
                            reg_cost_of_extinst(inst)
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
    ) -> Result<(), WalkError> {
        // Live set: SSA vars defined in the current frame AND
        // referenced by some instruction in `body[next_idx..]`. The
        // `one` const is intentionally excluded — re-load is cheaper
        // than capture-bind, and the InterningSink dedupes anyway.
        let referenced = collect_referenced_ssa_vars(&body[next_idx..]);
        let mut live: Vec<SsaVar> = self
            .ssa_to_reg
            .keys()
            .copied()
            .filter(|v| referenced.contains(v))
            .collect();
        // Deterministic order is load-bearing for proving-key
        // stability — without this the HashMap iteration order would
        // leak into capture_regs slot ids. SsaVar wraps `u32`; sort
        // by it directly rather than threading `Ord` through ir-core.
        live.sort_unstable_by_key(|v| v.0);

        if live.len() > MAX_CAPTURES {
            return Err(WalkError::LiveSetTooLarge {
                count: live.len(),
                max: MAX_CAPTURES,
            });
        }

        let capture_regs: Vec<u8> = live.iter().map(|v| self.ssa_to_reg[v]).collect();
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
        let n_params = live.len() as u8;
        self.templates.push(TemplateBuf::new(n_params));
        self.current = self.templates.len() - 1;
        self.allocator = RegAllocator::new_after_captures(n_params);
        let mut new_ssa_to_reg = HashMap::new();
        for (i, var) in live.iter().enumerate() {
            new_ssa_to_reg.insert(*var, i as RegId);
        }
        self.ssa_to_reg = new_ssa_to_reg;
        self.one_reg = None;
        // walker_const doesn't survive a template boundary — it would
        // require forwarding compile-time-known SsaVars through
        // capture_regs as a separate metadata channel, which Phase 1.5
        // doesn't model. Per-iter unrolling stays inside one template
        // body so this only matters if a top-level split fires
        // mid-body, which the pre-emit cost predictor avoids.
        self.walker_const.clear();

        // `one` is re-loaded lazily on first use in the new
        // template — see `Walker::one`. This avoids the slot tax on
        // wide single-instruction templates (Decompose, Or) whose
        // body never references `one`.
        Ok(())
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
            // Stage 3 of Gap 3 replaces this with a per-iteration
            // resolver mirroring `emit_symbolic_indexed_effect`. Until
            // then the variant only reaches `emit` when test fixtures
            // construct it directly — flag and reject.
            ExtendedInstruction::SymbolicShift { .. } => Err(WalkError::SymbolicShiftNotEmittable),
        }
    }

    /// Resolve a `SymbolicArrayRead` at walker time. Mirrors
    /// [`Self::emit_symbolic_indexed_effect`] but without an `EmitAssertEq`
    /// or `LoadInput` — the read is a pure symbolic alias: rebind
    /// `result_var` to whichever register `array_slots[idx]` already
    /// occupies and let downstream uses see the slot's wire directly.
    /// Requires `walker_const[index_var]` populated; the per-iteration
    /// walker is the only producer in Phase 2.
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

        // Read-side cannot synthesise on demand: an unbound slot is an
        // upstream pre-emission bug (the declaring `Plain(Input)` or
        // `WitnessArrayDecl` should have run before this read). Surface
        // the missing slot for diagnosis rather than miscompiling.
        let slot_reg = self.ssa_to_reg.get(&slot_var).copied().ok_or(
            WalkError::SymbolicArrayReadUnboundSlot {
                idx,
                slot: slot_var,
            },
        )?;
        self.bind(result_var, slot_reg);
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

        // Resolve or synthesize the slot's reg. Internal-signal
        // arrays leave their slots as un-emitted placeholders at
        // instantiate time (see `instantiate/stmts.rs::emit_let_
        // indexed_const`'s lazy-binding behaviour); the symbolic
        // path can't rely on a prior `Plain(Input)` having bound
        // them. Synthesize a witness wire on demand.
        let target_reg = match self.ssa_to_reg.get(&target_var).copied() {
            Some(r) => r,
            None => {
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
            // Field division Div(x,y) = x * y^{-1} is witness-computed
            // (inverse via WitnessCall) + one range-check constraint
            // (y*inv == 1). Plumbing it here would require synthesizing
            // an inline Artik blob that computes inv = y^{-1}, which
            // has no current precedent in this walker.
            //
            // Circom lowering does NOT emit Div (signals multiply
            // only), and ProveIR's prove {} blocks rarely use field
            // division. If 3.C.8 surfaces a real use case, the fix is:
            //   1. Emit a WitnessCall with an Artik blob computing inv.
            //   2. Emit AssertEq(Mul(y, inv), one) to constrain inv.
            //   3. Emit Mul(x, inv) as the result.
            // For now, surface the rejection with a clear error.
            Instruction::Div { .. } => {
                return Err(WalkError::UnsupportedInstruction { kind: "Div" });
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
                message: _,
            } => {
                let (l, r) = self.bin(*lhs, *rhs)?;
                self.push_op(Opcode::EmitAssertEq { lhs: l, rhs: r });
            }
            Instruction::Assert {
                result: _, operand, ..
            } => {
                // Desugar: assert operand == 1.
                let one = self.one()?;
                let op = self.resolve(*operand)?;
                self.push_op(Opcode::EmitAssertEq { lhs: op, rhs: one });
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
            // allocate fresh output regs, and emit. The reg-allocator
            // scheme is bump-forward: each output takes the next slot
            // so they stay contiguous, which is what EmitWitnessCall's
            // encoding expects (see `lysis::program::execute`).
            Instruction::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                let blob_idx = self.builder.intern_artik_bytecode(program_bytes.clone()) as u16;
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
        if body_has_symbolic_op(body) {
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

        if self.one_reg.is_none() && body_needs_one_const(body) {
            let _ = self.one()?;
        }

        // Allocate iter_var's reg ONCE for the whole per-iter loop.
        let iter_reg = self.allocator.alloc()?;
        self.bind(iter_var, iter_reg);

        // Snapshot pre-body state. The HashMap clones are O(n) per
        // iteration but n is small in practice (body-local SsaVars
        // only); per-iter walker scope is meant for loops the InterningSink
        // wouldn't have helped on anyway.
        let pre_body_alloc_ckpt = self.allocator.checkpoint();
        let pre_body_bindings = self.ssa_to_reg.clone();
        let pre_body_walker_const = self.walker_const.clone();

        for i in start_u32..end_u32 {
            self.allocator.restore_to(pre_body_alloc_ckpt);
            self.ssa_to_reg = pre_body_bindings.clone();
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

            for inst in body {
                self.emit(inst)?;
            }
        }

        // Don't leak per-iter walker_const entries past the loop.
        self.walker_const = pre_body_walker_const;
        Ok(())
    }

    fn bin(&self, lhs: SsaVar, rhs: SsaVar) -> Result<(RegId, RegId), WalkError> {
        Ok((self.resolve(lhs)?, self.resolve(rhs)?))
    }

    fn resolve(&self, var: SsaVar) -> Result<RegId, WalkError> {
        self.ssa_to_reg
            .get(&var)
            .copied()
            .ok_or(WalkError::UndefinedSsaVar(var))
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
        Instruction::AssertEq { .. } => bin(Opcode::EmitAssertEq { lhs: 0, rhs: 0 }),
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
        Instruction::Assert { .. } => bin(Opcode::EmitAssertEq { lhs: 0, rhs: 0 }),

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

        // Div is still walker-rejected; the inline-Artik plumbing
        // for `x / y = x * y^{-1}` has no precedent in this walker
        // and circom signal-arith never emits it. IntDiv / IntMod
        // shipped in Phase 1.5 to unblock SHA-256.
        Instruction::Div { .. } => return Err(WalkError::UnsupportedInstruction { kind: "Div" }),
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
        Instruction::WitnessCall { outputs, .. } => outputs.len() as u32,
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

/// Walk an `ExtendedInstruction` slice (recursing into LoopUnroll
/// bodies) and collect every SSA var that appears as an *operand*
/// — `result` slots are ignored because they are produced by the
/// instruction, not consumed. Used by [`Walker::do_split`] to
/// compute the live capture set at a top-level boundary.
///
/// Caps the set early once it grows past [`MAX_CAPTURES`]: the
/// caller will reject anyway and continuing the scan is just work
/// we'd throw away.
fn collect_referenced_ssa_vars<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> HashSet<SsaVar> {
    let mut out = HashSet::new();
    for inst in body {
        collect_in_extinst(inst, &mut out);
        if out.len() > MAX_CAPTURES {
            // Don't waste cycles refining a set the caller will reject.
            return out;
        }
    }
    out
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
        // The variant references `index_var` and (for Let) `value_var`;
        // both are SSA vars defined in the enclosing scope and must
        // be carried as captures across any top-level split that
        // happens to land between the LoopUnroll's parent template
        // and the LoopUnroll itself.
        ExtendedInstruction::SymbolicIndexedEffect {
            index_var,
            value_var,
            ..
        } => {
            out.insert(*index_var);
            if let Some(v) = value_var {
                out.insert(*v);
            }
        }
        // Read-side mirrors the write-side rationale: `index_var` is
        // an enclosing-scope use that must cross a split boundary.
        // `array_slots` are NOT collected — slots come from a sibling
        // pre-Plain(Input) emission inside the same template, so a
        // split between the LoopUnroll and its parent never separates
        // them from this read. `result_var` is a definition produced
        // by the read itself, so it isn't an operand.
        ExtendedInstruction::SymbolicArrayRead { index_var, .. } => {
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
    fn rejects_symbolic_array_read_when_slot_unbound() {
        // array_slots contains an SsaVar that was never produced —
        // missing pre-emission upstream. Read-side cannot synthesise
        // (unlike write-side which auto-binds a witness wire). Expect
        // the dedicated UnboundSlot error.
        let body = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 1,
            body: vec![ExtendedInstruction::SymbolicArrayRead {
                result_var: ssa(1),
                // ssa(99) is never bound by any earlier instruction.
                array_slots: vec![ssa(99)],
                index_var: ssa(0),
                span: None,
            }],
        }];
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert!(
            matches!(err, WalkError::SymbolicArrayReadUnboundSlot { idx: 0, .. }),
            "got {err:?}"
        );
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
    fn refuses_div_with_clear_kind() {
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
        let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
        let err = walker.lower(&body).expect_err("should refuse");
        assert_eq!(err, WalkError::UnsupportedInstruction { kind: "Div" });
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
}
