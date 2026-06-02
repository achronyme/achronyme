//! `InstrSink` trait — abstraction over the emission target so
//! [`super::Instantiator`] can produce a `Vec<ExtendedInstruction<F>>`
//! body (Lysis lifter input) without inlining the emission logic
//! into the Instantiator.
//!
//! ## Sink contract
//!
//! Every emission site in `instantiate/{scaffold,exprs,stmts,bits}.rs`
//! routes through one of:
//! - `sink.fresh_var()`               — allocate a fresh SSA var
//! - `sink.push_inst(inst, span)`     — append an `Instruction` (returns the inst's result var)
//! - `sink.set_type(var, ty)`         — attach IrType
//! - `sink.set_name(var, name)`       — bind source name (mostly for inputs)
//! - `sink.set_input_span(name, span)` — attach span to an input decl
//!
//! `const_cache` / `const_values` stay on the Instantiator
//! (synchronisation with peephole const-fold requires atomic update
//! with the push).
//!
//! ## Single impl
//!
//! - [`ExtendedSink`] — wraps `&mut Vec<ExtendedInstruction<F>>`
//!   plus a parallel `IrProgram<F>` skeleton for `set_name` /
//!   `set_type` / span / input span side-channels. Wraps each
//!   pushed `Instruction` as `ExtendedInstruction::Plain(_)`. Loop
//!   emission diverges via `begin_symbolic_loop` /
//!   `finish_symbolic_loop`, producing one
//!   `ExtendedInstruction::LoopUnroll` node per for-loop.
//!
//! Object-safety is preserved: every method takes `&mut self` (or
//! `&self`) plus owned/borrowed scalars, no associated types, no
//! generic methods. The Instantiator holds
//! `Box<dyn InstrSink<F> + 'a>` without monomorphisation, keeping
//! compile time bounded even though there is currently only one
//! impl. The trait abstraction is preserved as the seam for future
//! sink variants (e.g. a hypothetical streaming sink for very large
//! programs).

use diagnostics::SpanRange;
use ir_core::{Instruction, IrProgram, IrType, SsaVar};
use memory::FieldBackend;

use crate::extended::{ExtendedInstruction, IndexedEffectKind, ShiftDirection};

/// The emission boundary between [`super::Instantiator`] and its
/// output stream. See module docs.
pub(crate) trait InstrSink<F: FieldBackend> {
    /// Allocate a fresh SSA var.
    fn fresh_var(&mut self) -> SsaVar;

    /// Append an instruction. Returns its result var (the same one
    /// the caller put in `inst.result_var()`). If `span` is `Some`,
    /// attaches it to the result var's span side-channel.
    fn push_inst(&mut self, inst: Instruction<F>, span: Option<&SpanRange>) -> SsaVar;

    /// Bind a source-level name to an SSA var (mostly for input
    /// declarations and named bindings — used by error messages and
    /// the inspector).
    fn set_name(&mut self, var: SsaVar, name: String);

    /// Whether this sink retains source-name/span side channels.
    fn keeps_metadata(&self) -> bool;

    /// Bind an IR type to an SSA var. Read by downstream passes
    /// (`bool_prop`, R1CS) to reason about boolean vs field-typed
    /// wires.
    fn set_type(&mut self, var: SsaVar, ty: IrType);

    /// Read the IR type for an SSA var, if previously bound.
    fn get_type(&self, var: SsaVar) -> Option<IrType>;

    /// Bind a source span to an input declaration name.
    fn set_input_span(&mut self, name: String, span: SpanRange);

    /// Current SSA var watermark (the id the next [`fresh_var`] would
    /// return). Used by `set_next_var` callers and by the
    /// canonicaliser.
    fn next_var(&self) -> u64;

    /// Begin a symbolic loop body — switch the sink's active push
    /// target to a fresh sub-buffer that
    /// [`Self::finish_symbolic_loop`] will fold into a
    /// [`ExtendedInstruction::LoopUnroll`].
    fn begin_symbolic_loop(&mut self);

    /// Finalise a symbolic loop body — pop the sub-buffer started by
    /// [`Self::begin_symbolic_loop`] and emit one
    /// [`ExtendedInstruction::LoopUnroll { iter_var, start, end, body }`]
    /// into the surrounding scope (the outer body, or the next-up loop
    /// if nested).
    fn finish_symbolic_loop(&mut self, iter_var: SsaVar, start: i64, end: i64);

    /// Push a [`ExtendedInstruction::SymbolicIndexedEffect`] into the
    /// active scope (the topmost loop sub-buffer if any, else the
    /// outer body). `array_slots` is the pre-resolved list of element
    /// SSA wires so the walker can per-iteration materialise without
    /// needing the instantiate-time env.
    fn push_symbolic_indexed_effect(
        &mut self,
        kind: IndexedEffectKind,
        array_slots: Vec<SsaVar>,
        index_var: SsaVar,
        value_var: Option<SsaVar>,
        span: Option<SpanRange>,
    );

    /// Push a [`ExtendedInstruction::SymbolicArrayRead`] into the
    /// active scope. The caller must have already minted `result_var`
    /// via [`Self::fresh_var`] and resolved `index_var` from the
    /// index expression. The walker (Gap 1.5 Stage 3) rebinds
    /// `result_var` to `array_slots[idx]`'s register per iteration,
    /// so no `Plain(Instruction)` is emitted alongside.
    fn push_symbolic_array_read(
        &mut self,
        result_var: SsaVar,
        array_slots: Vec<SsaVar>,
        index_var: SsaVar,
        span: Option<SpanRange>,
    );

    /// Push a [`ExtendedInstruction::SymbolicShift`] into the active
    /// scope. The caller must have already minted `result_var` via
    /// [`Self::fresh_var`], emitted `operand_var` via the normal
    /// `emit_expr` path, and resolved `shift_var` from the shift
    /// expression. The walker (Gap 3 Stage 3) const-folds `shift_var`
    /// per iteration and synthesises the equivalent Decompose +
    /// recompose chain that
    /// [`crate::instantiate::Instantiator::emit_shift_right`] /
    /// `emit_shift_left` would emit at instantiate time.
    fn push_symbolic_shift(
        &mut self,
        result_var: SsaVar,
        operand_var: SsaVar,
        shift_var: SsaVar,
        num_bits: u32,
        direction: ShiftDirection,
        span: Option<SpanRange>,
    );
}

// ---------------------------------------------------------------------
// ExtendedSink — wraps a Vec<ExtendedInstruction<F>> and a parallel
// IrProgram<F> skeleton for the metadata side-channels.
// ---------------------------------------------------------------------

/// Routes every sink call so the instruction stream lands in a
/// `Vec<ExtendedInstruction<F>>` (each push wrapped as `Plain(_)`)
/// while name/type/span metadata is recorded in a parallel
/// [`IrProgram<F>`] skeleton kept in `metadata`.
///
/// The `metadata` skeleton's `instructions` Vec stays empty for the
/// whole emission walk — only `next_var`, `var_names`, `var_types`,
/// `var_spans`, and `input_spans` are populated. This lets us reuse
/// the IrProgram API for the metadata channels without duplicating
/// HashMap bookkeeping.
///
/// Loop emission uses the dedicated `push_loop_unroll` hook: it swaps
/// the active push target to a sub-buffer for the body builder, then
/// emits a single `LoopUnroll { iter_var, start, end, body: sub_vec }`
/// to the outer stream.
pub(crate) struct ExtendedSink<'a, F: FieldBackend> {
    body: &'a mut Vec<ExtendedInstruction<F>>,
    /// Stack of nested-loop sub-buffers. Each [`begin_symbolic_loop`]
    /// pushes a fresh `Vec<ExtendedInstruction<F>>` here; while non-
    /// empty, every [`push_inst`] writes to the top of the stack
    /// instead of the outer `body`. [`finish_symbolic_loop`] pops the
    /// top, wraps it in [`ExtendedInstruction::LoopUnroll`], and
    /// emits the LoopUnroll into the next-up scope (the next-up
    /// stack entry, or `body` if the stack is now empty).
    loop_stack: Vec<Vec<ExtendedInstruction<F>>>,
    metadata: &'a mut IrProgram<F>,
    /// When `false`, [`set_name`], [`set_input_span`], and the span
    /// side-channel write inside [`push_inst`] are no-ops. These three
    /// channels are write-only during emission — nothing inside
    /// `instantiate/{scaffold,exprs,stmts,bits}.rs` ever reads them
    /// back — so a caller that intends to discard them downstream
    /// (chunk-drain + streaming-sink paths) saves the HashMap growth
    /// outright. In lean mode `set_type` / `get_type` use
    /// `lean_types`: the ternary type-propagation in `exprs.rs` reads
    /// `get_type` during emission, but downstream chunk-drain callers
    /// discard `var_types`, so retaining the HashMap is avoidable.
    keep_metadata: bool,
    lean_types: Vec<Option<IrType>>,
}

impl<'a, F: FieldBackend> ExtendedSink<'a, F> {
    pub(crate) fn new(
        body: &'a mut Vec<ExtendedInstruction<F>>,
        metadata: &'a mut IrProgram<F>,
    ) -> Self {
        Self {
            body,
            loop_stack: Vec::new(),
            metadata,
            keep_metadata: true,
            lean_types: Vec::new(),
        }
    }

    /// Same as [`Self::new`] but the name / input-span / per-var-span
    /// side-channels are dropped at the sink boundary. The downstream
    /// callers (chunk-drain + streaming-sink) free the maps the
    /// instant they take ownership of the `ExtendedIrProgram`, so
    /// building them in the first place is pure peak-RSS waste.
    pub(crate) fn new_lean(
        body: &'a mut Vec<ExtendedInstruction<F>>,
        metadata: &'a mut IrProgram<F>,
    ) -> Self {
        Self {
            body,
            loop_stack: Vec::new(),
            metadata,
            keep_metadata: false,
            lean_types: Vec::new(),
        }
    }

    /// Push a finished `ExtendedInstruction` into the active scope:
    /// the topmost loop sub-buffer if any, else the outer body.
    fn push_into_active(&mut self, entry: ExtendedInstruction<F>) {
        if let Some(top) = self.loop_stack.last_mut() {
            top.push(entry);
        } else {
            self.body.push(entry);
        }
    }
}

impl<'a, F: FieldBackend> InstrSink<F> for ExtendedSink<'a, F> {
    fn fresh_var(&mut self) -> SsaVar {
        self.metadata.fresh_var()
    }

    fn push_inst(&mut self, inst: Instruction<F>, span: Option<&SpanRange>) -> SsaVar {
        let var = inst.result_var();
        if self.keep_metadata {
            if let Some(s) = span {
                self.metadata.set_span(var, s.clone());
            }
        }
        self.push_into_active(ExtendedInstruction::Plain(inst));
        var
    }

    fn set_name(&mut self, var: SsaVar, name: String) {
        if self.keep_metadata {
            self.metadata.set_name(var, name);
        }
    }

    fn keeps_metadata(&self) -> bool {
        self.keep_metadata
    }

    fn set_type(&mut self, var: SsaVar, ty: IrType) {
        if self.keep_metadata {
            self.metadata.set_type(var, ty);
        } else {
            let idx = var.0 as usize;
            if idx >= self.lean_types.len() {
                self.lean_types.resize(idx + 1, None);
            }
            self.lean_types[idx] = Some(ty);
        }
    }

    fn get_type(&self, var: SsaVar) -> Option<IrType> {
        if self.keep_metadata {
            self.metadata.get_type(var)
        } else {
            self.lean_types.get(var.0 as usize).copied().flatten()
        }
    }

    fn set_input_span(&mut self, name: String, span: SpanRange) {
        if self.keep_metadata {
            self.metadata.set_input_span(name, span);
        }
    }

    fn next_var(&self) -> u64 {
        self.metadata.next_var()
    }

    fn begin_symbolic_loop(&mut self) {
        self.loop_stack.push(Vec::new());
    }

    fn finish_symbolic_loop(&mut self, iter_var: SsaVar, start: i64, end: i64) {
        let body = self
            .loop_stack
            .pop()
            .expect("finish_symbolic_loop without matching begin_symbolic_loop");
        self.push_into_active(ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body,
        });
    }

    fn push_symbolic_indexed_effect(
        &mut self,
        kind: IndexedEffectKind,
        array_slots: Vec<SsaVar>,
        index_var: SsaVar,
        value_var: Option<SsaVar>,
        span: Option<SpanRange>,
    ) {
        self.push_into_active(ExtendedInstruction::SymbolicIndexedEffect {
            kind,
            array_slots,
            index_var,
            value_var,
            span: span.map(Box::new),
        });
    }

    fn push_symbolic_array_read(
        &mut self,
        result_var: SsaVar,
        array_slots: Vec<SsaVar>,
        index_var: SsaVar,
        span: Option<SpanRange>,
    ) {
        self.push_into_active(ExtendedInstruction::SymbolicArrayRead {
            result_var,
            array_slots,
            index_var,
            span: span.map(Box::new),
        });
    }

    fn push_symbolic_shift(
        &mut self,
        result_var: SsaVar,
        operand_var: SsaVar,
        shift_var: SsaVar,
        num_bits: u32,
        direction: ShiftDirection,
        span: Option<SpanRange>,
    ) {
        self.push_into_active(ExtendedInstruction::SymbolicShift {
            result_var,
            operand_var,
            shift_var,
            num_bits,
            direction,
            span: span.map(Box::new),
        });
    }
}

#[cfg(test)]
mod tests;
