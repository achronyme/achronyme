use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// Register file ran out.
    Alloc(AllocError),
    /// The body contains a `TemplateCall` or `TemplateBody`; the
    /// walker only emits inline + `LoopUnroll`.
    TemplateNotSupported,
    /// An instruction variant is not emittable by the walker. Used
    /// for variants the walker has not yet been taught to lower.
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
    /// [`MAX_CAPTURES`]. Forwarding more than the cap of SSA vars
    /// across a single split would defeat the point of the split
    /// (the new template starts with the reserved capture regs
    /// already). The fix is BTA and structural extraction, which
    /// avoids the wide live set in the first place.
    LiveSetTooLarge { count: usize, max: usize },
    /// A `SymbolicIndexedEffect` reached the walker but its
    /// `index_var` could not be const-folded to a literal `usize` at
    /// walker time. The const-folder handles Add/Sub/Mul/Neg over
    /// loop-iter constants; anything outside that surface (Decompose
    /// indices, runtime witness reads) needs runtime memory-op
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
    /// const-prop only sees Add/Sub/Mul/Neg over loop-iter constants.
    SymbolicShiftNotEmittable,
    /// `SymbolicShift.shift_var` const-folded but to a negative
    /// integer. The legacy `emit_shift_right`/`emit_shift_left`
    /// path uses a `u32` shift amount so negatives are a logic bug
    /// at lowering or instantiation, not something the walker can
    /// fix.
    SymbolicShiftNegativeAmount { shift: i64 },
    /// `TemplateBody.captures.len()` did not match the declared
    /// `n_params`. The lift always sets them equal; a mismatch is a
    /// pipeline corruption.
    TemplateCapturesMismatch { n_params: u8, captures_len: usize },
    /// `TemplateCall.outputs` is non-empty. The lift uses
    /// **Option B** (loop runs inside the template, no return values
    /// — side-effects flow through the shared sink). Output wiring
    /// via `Opcode::TemplateOutput` is not yet supported.
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
                "walker: TemplateCall/TemplateBody not emitted yet (walker uses LoopUnroll only)",
            ),
            Self::UnsupportedInstruction { kind } => {
                write!(f, "walker: instruction variant `{kind}` not supported")
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
                "walker: live set across top-level split has {count} SSA vars, exceeding MAX_CAPTURES={max} — BTA needed"
            ),
            Self::SymbolicIndexedEffectNotEmittable => f.write_str(
                "walker: SymbolicIndexedEffect index could not be const-folded at walker time — only Add/Sub/Mul/Neg over loop-iter constants are supported (runtime memory ops would lift this)",
            ),
            Self::SymbolicIndexedEffectIndexOutOfRange { idx, len } => write!(
                f,
                "walker: SymbolicIndexedEffect resolved to index {idx} but array has {len} slots"
            ),
            Self::SymbolicIndexedEffectMissingValue => f.write_str(
                "walker: SymbolicIndexedEffect kind=Let but value_var=None — instantiator bug",
            ),
            Self::SymbolicArrayReadNotEmittable => f.write_str(
                "walker: SymbolicArrayRead index could not be const-folded at walker time — only Add/Sub/Mul/Neg over loop-iter constants are supported (runtime memory ops would lift this)",
            ),
            Self::SymbolicArrayReadIndexOutOfRange { idx, len } => write!(
                f,
                "walker: SymbolicArrayRead resolved to index {idx} but array has {len} slots"
            ),
            Self::SymbolicShiftNotEmittable => f.write_str(
                "walker: SymbolicShift amount could not be const-folded at walker time — only Add/Sub/Mul/Neg over loop-iter constants are supported (runtime memory ops would lift this)",
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
                "walker: TemplateCall.outputs is non-empty (Option B lift uses side-effects only; output wiring is not yet supported)",
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
