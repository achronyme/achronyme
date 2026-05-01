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
    fn next_var(&self) -> u32;

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
/// Loop emission (commit 2.5) added the dedicated `push_loop_unroll`
/// hook that swaps the active push target to a sub-buffer for the
/// body builder, then emits a single `LoopUnroll { iter_var, start,
/// end, body: sub_vec }` to the outer stream.
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
        if let Some(s) = span {
            self.metadata.set_span(var, s.clone());
        }
        self.push_into_active(ExtendedInstruction::Plain(inst));
        var
    }

    fn set_name(&mut self, var: SsaVar, name: String) {
        self.metadata.set_name(var, name);
    }

    fn set_type(&mut self, var: SsaVar, ty: IrType) {
        self.metadata.set_type(var, ty);
    }

    fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.metadata.get_type(var)
    }

    fn set_input_span(&mut self, name: String, span: SpanRange) {
        self.metadata.set_input_span(name, span);
    }

    fn next_var(&self) -> u32 {
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
            span,
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
            span,
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
            span,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::{Bn254Fr, FieldElement};

    type F = Bn254Fr;

    fn fe(n: u64) -> FieldElement<F> {
        FieldElement::from_u64(n)
    }

    #[test]
    fn extended_sink_wraps_each_inst_as_plain() {
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        let v0 = sink.fresh_var();
        sink.push_inst(
            Instruction::Const {
                result: v0,
                value: fe(3),
            },
            None,
        );
        sink.set_type(v0, IrType::Field);

        assert_eq!(body.len(), 1);
        assert!(matches!(body[0], ExtendedInstruction::Plain(_)));
        assert_eq!(metadata.len(), 0, "metadata.instructions stays empty");
        assert_eq!(metadata.next_var(), 1);
        assert_eq!(metadata.get_type(SsaVar(0)), Some(IrType::Field));
    }

    #[test]
    fn extended_sink_var_counter_advances_per_fresh_var() {
        // Equivalent emission program: two fresh vars + Const + Add.
        // The metadata IrProgram skeleton is the var-counter source of
        // truth; `body` carries the actual instructions wrapped as Plain.
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        let v0 = sink.fresh_var();
        let v1 = sink.fresh_var();
        sink.push_inst(
            Instruction::Const {
                result: v0,
                value: fe(0),
            },
            None,
        );
        sink.push_inst(
            Instruction::Add {
                result: v1,
                lhs: v0,
                rhs: v0,
            },
            None,
        );

        assert_eq!(metadata.next_var(), 2);
        assert_eq!(body.len(), 2);
    }

    #[test]
    fn extended_sink_emits_loop_unroll_with_symbolic_iter_var() {
        // Direct sink-level test: simulate what emit_range_loop will
        // do once wired in. The body emits one Mul that references
        // iter_var symbolically; finalising should produce a single
        // LoopUnroll containing exactly that one Plain instruction.
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        // Allocate a symbolic iter_var.
        let iter_var = sink.fresh_var();
        // Begin a symbolic loop scope.
        sink.begin_symbolic_loop();
        // Emit one body instruction that refs iter_var.
        let mul = sink.fresh_var();
        sink.push_inst(
            Instruction::Mul {
                result: mul,
                lhs: iter_var,
                rhs: iter_var,
            },
            None,
        );
        // Finalise.
        sink.finish_symbolic_loop(iter_var, 0, 4);

        // Outer body should have exactly one LoopUnroll node.
        assert_eq!(body.len(), 1, "one LoopUnroll in outer body");
        match &body[0] {
            ExtendedInstruction::LoopUnroll {
                iter_var: iv,
                start,
                end,
                body: loop_body,
            } => {
                assert_eq!(*iv, iter_var);
                assert_eq!(*start, 0);
                assert_eq!(*end, 4);
                assert_eq!(loop_body.len(), 1, "one Plain Mul inside the loop");
                match &loop_body[0] {
                    ExtendedInstruction::Plain(Instruction::Mul { lhs, rhs, .. }) => {
                        assert_eq!(*lhs, iter_var);
                        assert_eq!(*rhs, iter_var);
                    }
                    other => panic!("expected Plain(Mul), got {other:?}"),
                }
            }
            other => panic!("expected LoopUnroll, got {other:?}"),
        }
    }

    #[test]
    fn extended_sink_handles_nested_loops() {
        // for i in 0..3 { for j in 0..2 { Mul(j, j) } }
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        let i = sink.fresh_var();
        sink.begin_symbolic_loop();

        let j = sink.fresh_var();
        sink.begin_symbolic_loop();

        let mul = sink.fresh_var();
        sink.push_inst(
            Instruction::Mul {
                result: mul,
                lhs: j,
                rhs: j,
            },
            None,
        );

        sink.finish_symbolic_loop(j, 0, 2);
        sink.finish_symbolic_loop(i, 0, 3);

        assert_eq!(body.len(), 1, "one outer LoopUnroll");
        match &body[0] {
            ExtendedInstruction::LoopUnroll {
                body: outer_body, ..
            } => {
                assert_eq!(outer_body.len(), 1, "outer body has one inner LoopUnroll");
                assert!(matches!(
                    outer_body[0],
                    ExtendedInstruction::LoopUnroll { .. }
                ));
            }
            _ => panic!("expected outer LoopUnroll"),
        }
    }

    #[test]
    fn extended_sink_pushes_symbolic_indexed_effect() {
        // Simulate what `emit_let_indexed_symbolic` does inside a
        // symbolic loop body: begin loop, push effect, finish loop.
        // The resulting ExtendedInstruction tree must wrap the effect
        // inside the LoopUnroll body, not the outer scope.
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        let iter_var = sink.fresh_var();
        let slot0 = sink.fresh_var();
        let slot1 = sink.fresh_var();
        let value_var = sink.fresh_var();

        sink.begin_symbolic_loop();
        sink.push_symbolic_indexed_effect(
            IndexedEffectKind::Let,
            vec![slot0, slot1],
            iter_var,
            Some(value_var),
            None,
        );
        sink.finish_symbolic_loop(iter_var, 0, 2);

        assert_eq!(body.len(), 1, "one outer LoopUnroll");
        match &body[0] {
            ExtendedInstruction::LoopUnroll { body: inner, .. } => {
                assert_eq!(inner.len(), 1);
                match &inner[0] {
                    ExtendedInstruction::SymbolicIndexedEffect {
                        kind,
                        array_slots,
                        index_var,
                        value_var: vv,
                        ..
                    } => {
                        assert_eq!(*kind, IndexedEffectKind::Let);
                        assert_eq!(array_slots, &vec![slot0, slot1]);
                        assert_eq!(*index_var, iter_var);
                        assert_eq!(*vv, Some(value_var));
                    }
                    other => panic!("expected SymbolicIndexedEffect, got {other:?}"),
                }
            }
            other => panic!("expected LoopUnroll, got {other:?}"),
        }
    }

    #[test]
    fn extended_sink_pushes_symbolic_array_read() {
        // Mirror of the write-side test: simulate `emit_array_index_
        // symbolic` inside a symbolic loop body.
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        let iter_var = sink.fresh_var();
        let slot0 = sink.fresh_var();
        let slot1 = sink.fresh_var();
        let result_var = sink.fresh_var();

        sink.begin_symbolic_loop();
        sink.push_symbolic_array_read(result_var, vec![slot0, slot1], iter_var, None);
        sink.finish_symbolic_loop(iter_var, 0, 2);

        assert_eq!(body.len(), 1, "one outer LoopUnroll");
        match &body[0] {
            ExtendedInstruction::LoopUnroll { body: inner, .. } => {
                assert_eq!(inner.len(), 1);
                match &inner[0] {
                    ExtendedInstruction::SymbolicArrayRead {
                        result_var: rv,
                        array_slots,
                        index_var,
                        ..
                    } => {
                        assert_eq!(*rv, result_var);
                        assert_eq!(array_slots, &vec![slot0, slot1]);
                        assert_eq!(*index_var, iter_var);
                    }
                    other => panic!("expected SymbolicArrayRead, got {other:?}"),
                }
            }
            other => panic!("expected LoopUnroll, got {other:?}"),
        }
    }

    #[test]
    fn extended_sink_pushes_symbolic_shift() {
        // Mirror of the read- and write-side tests: simulate the
        // emit-site arm in `instantiate/exprs.rs` for `ShiftR`/`ShiftL`
        // when the shift amount is loop-iter-dependent.
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);

        let iter_var = sink.fresh_var();
        let operand_var = sink.fresh_var();
        let result_var = sink.fresh_var();

        sink.begin_symbolic_loop();
        sink.push_symbolic_shift(
            result_var,
            operand_var,
            iter_var,
            32,
            ShiftDirection::Right,
            None,
        );
        sink.finish_symbolic_loop(iter_var, 0, 32);

        assert_eq!(body.len(), 1, "one outer LoopUnroll");
        match &body[0] {
            ExtendedInstruction::LoopUnroll { body: inner, .. } => {
                assert_eq!(inner.len(), 1);
                match &inner[0] {
                    ExtendedInstruction::SymbolicShift {
                        result_var: rv,
                        operand_var: ov,
                        shift_var,
                        num_bits,
                        direction,
                        ..
                    } => {
                        assert_eq!(*rv, result_var);
                        assert_eq!(*ov, operand_var);
                        assert_eq!(*shift_var, iter_var);
                        assert_eq!(*num_bits, 32);
                        assert_eq!(*direction, ShiftDirection::Right);
                    }
                    other => panic!("expected SymbolicShift, got {other:?}"),
                }
            }
            other => panic!("expected LoopUnroll, got {other:?}"),
        }
    }

    #[test]
    fn extended_sink_records_input_span_in_metadata() {
        let span = SpanRange::point(5, 5, 0);
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut sink = ExtendedSink::new(&mut body, &mut metadata);
        sink.set_input_span("y".into(), span.clone());
        assert_eq!(metadata.get_input_span("y"), Some(&span));
    }
}
