//! `InstrSink` trait — abstraction over the emission target so
//! [`super::Instantiator`] can produce either flat
//! `Vec<Instruction<F>>` (legacy R1CS path) or
//! `Vec<ExtendedInstruction<F>>` (Lysis lifter input) without
//! duplicating the ~3,000 LOC of emission logic.
//!
//! Phase 3.C.6 Stage 2 commit 2.1 (see
//! `.claude/plans/lysis-phase-3c6.md`). At this commit the trait
//! lives alongside the existing direct-`program.push(...)` code and
//! is NOT wired in yet — that's commit 2.2's job. This commit
//! defines the contract and the two impls so the wiring change can
//! be a focused diff.
//!
//! ## Sink contract
//!
//! Every emission site in `instantiate/{scaffold,exprs,stmts,bits}.rs`
//! today calls one of:
//! - `program.fresh_var()`        — allocate a fresh SSA var
//! - `program.push(Instruction)`  — append (returns the inst's result var)
//! - `program.set_type(var, ty)`  — attach IrType
//! - `program.set_name(var, name)`— bind source name (mostly for inputs)
//! - `program.set_input_span(name, span)` — attach span to an input decl
//! - `Instantiator::push_inst(inst)` — convenience wrapper that calls
//!   `push` then `set_span` from `current_span`
//!
//! [`InstrSink`] mirrors this surface. The Instantiator (commit 2.2)
//! holds an `&mut dyn InstrSink<F>` instead of `program: IrProgram<F>`
//! and routes every call through the trait. `const_cache` /
//! `const_values` stay on the Instantiator (synchronisation with
//! peephole const-fold requires atomic update with the push, see
//! plan §3 "Why const_cache stays on Instantiator").
//!
//! ## Two impls in this commit
//!
//! - [`LegacySink`] — wraps `&mut IrProgram<F>`. Produces
//!   byte-identical output to the pre-trait pipeline. Used by the
//!   legacy `instantiate` / `instantiate_with_outputs` entry points.
//! - [`ExtendedSink`] — wraps `&mut Vec<ExtendedInstruction<F>>`
//!   plus a parallel `IrProgram<F>` skeleton for `set_name` /
//!   `set_type` / span / input span side-channels. Wraps each
//!   pushed `Instruction` as `ExtendedInstruction::Plain(_)`. Used
//!   (commit 2.4 onwards) by the new `instantiate_extended` API.
//!   Loop emission diverges in commit 2.5 via `push_loop_unroll`.
//!
//! Object-safety is preserved: every method takes `&mut self` (or
//! `&self`) plus owned/borrowed scalars, no associated types, no
//! generic methods. The Instantiator can hold
//! `Box<dyn InstrSink<F> + 'a>` (commit 2.2) without monomorphisation
//! per sink type — keeping compile time bounded.

use diagnostics::SpanRange;
use ir_core::{Instruction, IrProgram, IrType, SsaVar};
use memory::FieldBackend;

use crate::extended::{ExtendedInstruction, IndexedEffectKind};

/// How a sink wants the [`super::Instantiator::emit_range_loop`]
/// caller to handle a `for i in start..end { body }` construct.
///
/// Returned by [`InstrSink::loop_unroll_mode`]. The default is
/// [`Self::PerIteration`] (LegacySink behaviour); ExtendedSink
/// overrides to [`Self::Symbolic`] so the body emits exactly once
/// with `iter_var` bound symbolically and a single
/// [`ExtendedInstruction::LoopUnroll`] node carries the bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopUnrollMode {
    /// LegacySink — caller emits body once per iteration `start..end`,
    /// binding the loop var to a fresh `Const(i)` SSA wire each time.
    /// Byte-identical to the pre-trait pipeline.
    PerIteration,
    /// ExtendedSink — caller emits body once with the loop var bound
    /// to a fresh symbolic SSA slot. Sink has internally swapped to a
    /// sub-buffer; finalize via [`InstrSink::finish_symbolic_loop`].
    Symbolic,
}

/// The emission boundary between [`super::Instantiator`] and its
/// output stream. See module docs.
pub(crate) trait InstrSink<F: FieldBackend> {
    /// Allocate a fresh SSA var. Both sinks keep a parallel
    /// monotonic counter so the var ids are stable across the
    /// emission walk regardless of which sink is in use.
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

    /// How `for i in start..end { body }` should be emitted. See
    /// [`LoopUnrollMode`].
    ///
    /// Default: `PerIteration` (LegacySink path). ExtendedSink
    /// overrides to `Symbolic`.
    fn loop_unroll_mode(&self) -> LoopUnrollMode {
        LoopUnrollMode::PerIteration
    }

    /// Begin a symbolic loop body — switch the sink's active push
    /// target to a fresh sub-buffer that
    /// [`Self::finish_symbolic_loop`] will fold into a
    /// [`ExtendedInstruction::LoopUnroll`]. Only called when the
    /// preceding [`Self::loop_unroll_mode`] returned `Symbolic`.
    ///
    /// Default: `unreachable!` — `PerIteration` sinks never call this.
    fn begin_symbolic_loop(&mut self) {
        unreachable!("begin_symbolic_loop called on a sink whose loop_unroll_mode is PerIteration");
    }

    /// Finalise a symbolic loop body — pop the sub-buffer started by
    /// [`Self::begin_symbolic_loop`] and emit one
    /// [`ExtendedInstruction::LoopUnroll { iter_var, start, end, body }`]
    /// into the surrounding scope (the outer body, or the next-up loop
    /// if nested).
    ///
    /// Default: `unreachable!` — `PerIteration` sinks never call this.
    fn finish_symbolic_loop(&mut self, _iter_var: SsaVar, _start: i64, _end: i64) {
        unreachable!(
            "finish_symbolic_loop called on a sink whose loop_unroll_mode is PerIteration"
        );
    }

    /// Push a [`ExtendedInstruction::SymbolicIndexedEffect`] into the
    /// active scope (the topmost loop sub-buffer if any, else the
    /// outer body). Only callable when [`Self::loop_unroll_mode`]
    /// returns `Symbolic`; the caller must have used `Symbolic` mode
    /// to enter the surrounding loop. `array_slots` is the
    /// pre-resolved list of element SSA wires so the walker can
    /// per-iteration materialise without needing the instantiate-time
    /// env (closes risk-audit invariant #4 in the Gap 1 plan).
    ///
    /// Default: `unreachable!` — `PerIteration` sinks never call this.
    fn push_symbolic_indexed_effect(
        &mut self,
        _kind: IndexedEffectKind,
        _array_slots: Vec<SsaVar>,
        _index_var: SsaVar,
        _value_var: Option<SsaVar>,
        _span: Option<SpanRange>,
    ) {
        unreachable!(
            "push_symbolic_indexed_effect called on a sink whose loop_unroll_mode is PerIteration"
        );
    }
}

// ---------------------------------------------------------------------
// LegacySink — wraps an IrProgram<F>, byte-identical to the
// pre-trait emission path.
// ---------------------------------------------------------------------

/// Routes every sink call to a borrowed [`IrProgram<F>`]. The
/// instantiation entry points construct one of these around a fresh
/// program, hand it to the [`super::Instantiator`], and return the
/// program once the walk completes.
pub(crate) struct LegacySink<'a, F: FieldBackend> {
    program: &'a mut IrProgram<F>,
}

impl<'a, F: FieldBackend> LegacySink<'a, F> {
    pub(crate) fn new(program: &'a mut IrProgram<F>) -> Self {
        Self { program }
    }
}

impl<'a, F: FieldBackend> InstrSink<F> for LegacySink<'a, F> {
    fn fresh_var(&mut self) -> SsaVar {
        self.program.fresh_var()
    }

    fn push_inst(&mut self, inst: Instruction<F>, span: Option<&SpanRange>) -> SsaVar {
        let var = self.program.push(inst);
        if let Some(s) = span {
            self.program.set_span(var, s.clone());
        }
        var
    }

    fn set_name(&mut self, var: SsaVar, name: String) {
        self.program.set_name(var, name);
    }

    fn set_type(&mut self, var: SsaVar, ty: IrType) {
        self.program.set_type(var, ty);
    }

    fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.program.get_type(var)
    }

    fn set_input_span(&mut self, name: String, span: SpanRange) {
        self.program.set_input_span(name, span);
    }

    fn next_var(&self) -> u32 {
        self.program.next_var()
    }
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
/// Loop emission (commit 2.5) is the only place ExtendedSink diverges
/// from LegacySink — when the dedicated `push_loop_unroll` hook lands
/// it will swap the active push target to a sub-buffer for the body
/// builder, then emit a single `LoopUnroll { iter_var, start, end,
/// body: sub_vec }` to the outer stream.
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

    fn loop_unroll_mode(&self) -> LoopUnrollMode {
        LoopUnrollMode::Symbolic
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir_core::Visibility;
    use memory::{Bn254Fr, FieldElement};

    type F = Bn254Fr;

    fn fe(n: u64) -> FieldElement<F> {
        FieldElement::from_u64(n)
    }

    #[test]
    fn legacy_sink_pushes_to_program() {
        let mut program = IrProgram::<F>::new();
        let mut sink = LegacySink::new(&mut program);

        let v0 = sink.fresh_var();
        sink.push_inst(
            Instruction::Const {
                result: v0,
                value: fe(7),
            },
            None,
        );
        sink.set_type(v0, IrType::Field);

        assert_eq!(program.len(), 1);
        assert_eq!(program.next_var(), 1);
        assert_eq!(program.get_type(SsaVar(0)), Some(IrType::Field));
    }

    #[test]
    fn legacy_sink_attaches_span_when_provided() {
        let mut program = IrProgram::<F>::new();
        let mut sink = LegacySink::new(&mut program);
        let span = SpanRange::point(1, 1, 0);

        let v0 = sink.fresh_var();
        sink.push_inst(
            Instruction::Input {
                result: v0,
                name: "x".into(),
                visibility: Visibility::Witness,
            },
            Some(&span),
        );

        assert_eq!(program.get_span(v0), Some(&span));
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
    fn both_sinks_share_the_var_counter_semantics() {
        // Equivalent emission programs, different sinks. Both should
        // advance the var counter the same way.
        let mut a_program = IrProgram::<F>::new();
        let mut a_sink = LegacySink::new(&mut a_program);

        let mut b_body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut b_metadata = IrProgram::<F>::new();
        let mut b_sink = ExtendedSink::new(&mut b_body, &mut b_metadata);

        for sink in [&mut a_sink as &mut dyn InstrSink<F>, &mut b_sink] {
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
        }

        assert_eq!(a_program.next_var(), 2);
        assert_eq!(b_metadata.next_var(), 2);
        assert_eq!(a_program.len(), 2);
        assert_eq!(b_body.len(), 2);
    }

    #[test]
    fn legacy_sink_default_loop_mode_is_per_iteration() {
        let mut program = IrProgram::<F>::new();
        let sink = LegacySink::new(&mut program);
        assert_eq!(sink.loop_unroll_mode(), LoopUnrollMode::PerIteration);
    }

    #[test]
    fn extended_sink_loop_mode_is_symbolic() {
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let sink = ExtendedSink::new(&mut body, &mut metadata);
        assert_eq!(sink.loop_unroll_mode(), LoopUnrollMode::Symbolic);
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
    fn input_span_recorded_in_both_sinks() {
        let span = SpanRange::point(5, 5, 0);

        let mut program = IrProgram::<F>::new();
        let mut a_sink = LegacySink::new(&mut program);
        a_sink.set_input_span("x".into(), span.clone());
        assert_eq!(program.get_input_span("x"), Some(&span));

        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        let mut b_sink = ExtendedSink::new(&mut body, &mut metadata);
        b_sink.set_input_span("y".into(), span.clone());
        assert_eq!(metadata.get_input_span("y"), Some(&span));
    }
}
