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

use crate::extended::ExtendedInstruction;

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
#[allow(dead_code)] // Wired in by commit 2.4 (instantiate_extended API).
pub(crate) struct ExtendedSink<'a, F: FieldBackend> {
    body: &'a mut Vec<ExtendedInstruction<F>>,
    metadata: &'a mut IrProgram<F>,
}

#[allow(dead_code)] // Wired in by commit 2.4 (instantiate_extended API).
impl<'a, F: FieldBackend> ExtendedSink<'a, F> {
    pub(crate) fn new(
        body: &'a mut Vec<ExtendedInstruction<F>>,
        metadata: &'a mut IrProgram<F>,
    ) -> Self {
        Self { body, metadata }
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
        self.body.push(ExtendedInstruction::Plain(inst));
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
