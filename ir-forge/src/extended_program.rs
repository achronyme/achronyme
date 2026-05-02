//! `ExtendedIrProgram<F>` — the [`ExtendedInstruction`]-shaped
//! counterpart to [`IrProgram<F>`].
//!
//! Resolves round-7 watchpoint #1 (span placement). The ProveIR
//! compiler historically pushes `Instruction<F>` into `IrProgram`
//! and records spans in a side-band `var_spans: HashMap<SsaVar,
//! SpanRange>`. When migrating the compiler to emit
//! `ExtendedInstruction<F>` for Lysis, the question was: where do
//! spans live now? The three options (see RFC §3.1.1 notes):
//!
//! - **(a) `Plain(Instruction<F>, Span)`** — explicit span per
//!   entry. Rejected: forces every caller to plumb a span even
//!   when they don't have one; makes `Plain` awkward as a pure
//!   pass-through.
//! - **(b) side-band wrapper** — the existing pattern, lifted to
//!   an `ExtendedIrProgram<F>` that mirrors `IrProgram<F>`'s
//!   shape. **Chosen.** Minimal API churn: callers that used
//!   `push(inst)` now use `push_plain(inst)`; spans are set
//!   through the same `set_span` they already know.
//! - **(c) drop and re-derive from Lysis interner's span list**
//!   — only partially covers the case, because not every
//!   emission path goes through the interner (e.g., programs
//!   with `LoopUnroll` inline their body at bytecode-emit time;
//!   the span lives with the inlined body, not in the interner).
//!
//! With (b), the Lysis interner's `SpanList` is still useful — it
//! handles the N-occurrences-per-dedup'd-node case that a
//! `HashMap<SsaVar, _>` cannot represent. The interner's span list
//! is the per-node record; `ExtendedIrProgram.var_spans` is the
//! per-SSA-var record emitted by the *compiler* before Lysis ever
//! sees the tree.
//!
//! [`ExtendedInstruction`]: crate::prove_ir::ExtendedInstruction
//! [`IrProgram<F>`]: crate::types::IrProgram

use std::collections::HashMap;

use diagnostics::SpanRange;
use ir_core::{Instruction, IrProgram, IrType, SsaVar};
use memory::{Bn254Fr, FieldBackend};

use crate::extended::ExtendedInstruction;

/// `ExtendedInstruction`-shaped counterpart of [`IrProgram`]. Same
/// side-band metadata, same `fresh_var` / `set_span` API, but the
/// body is `Vec<ExtendedInstruction<F>>` so `TemplateBody`,
/// `TemplateCall`, and `LoopUnroll` can appear alongside the
/// pass-through `Plain(Instruction<F>)` nodes.
#[derive(Debug)]
pub struct ExtendedIrProgram<F: FieldBackend = Bn254Fr> {
    pub body: Vec<ExtendedInstruction<F>>,
    pub next_var: u32,
    pub var_names: HashMap<SsaVar, String>,
    pub var_types: HashMap<SsaVar, IrType>,
    pub input_spans: HashMap<String, SpanRange>,
    pub var_spans: HashMap<SsaVar, SpanRange>,
}

impl<F: FieldBackend> Default for ExtendedIrProgram<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> ExtendedIrProgram<F> {
    pub fn new() -> Self {
        Self {
            body: Vec::new(),
            next_var: 0,
            var_names: HashMap::new(),
            var_types: HashMap::new(),
            input_spans: HashMap::new(),
            var_spans: HashMap::new(),
        }
    }

    /// Allocate a fresh SSA variable. Same numbering convention as
    /// `IrProgram::fresh_var` so the two programs can be compared
    /// side-by-side during migration.
    pub fn fresh_var(&mut self) -> SsaVar {
        let v = SsaVar(self.next_var);
        self.next_var += 1;
        v
    }

    /// Push a pass-through `Plain` instruction and return its
    /// result variable — the drop-in replacement for
    /// `IrProgram::push`.
    pub fn push_plain(&mut self, inst: Instruction<F>) -> SsaVar {
        let v = inst.result_var();
        self.body.push(ExtendedInstruction::Plain(inst));
        v
    }

    /// Push any `ExtendedInstruction` (template body, template
    /// call, loop, or plain). Returns nothing because non-`Plain`
    /// variants don't have a single primary SsaVar to report
    /// (`TemplateCall` may bind multiple outputs; `TemplateBody`
    /// doesn't bind any).
    pub fn push(&mut self, node: ExtendedInstruction<F>) {
        self.body.push(node);
    }

    pub fn set_name(&mut self, var: SsaVar, name: String) {
        self.var_names.insert(var, name);
    }

    pub fn set_type(&mut self, var: SsaVar, ty: IrType) {
        self.var_types.insert(var, ty);
    }

    pub fn set_span(&mut self, var: SsaVar, span: SpanRange) {
        self.var_spans.insert(var, span);
    }

    pub fn set_input_span(&mut self, name: String, span: SpanRange) {
        self.input_spans.insert(name, span);
    }

    pub fn get_name(&self, var: SsaVar) -> Option<&str> {
        self.var_names.get(&var).map(String::as_str)
    }

    pub fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.var_types.get(&var).copied()
    }

    pub fn get_span(&self, var: SsaVar) -> Option<&SpanRange> {
        self.var_spans.get(&var)
    }

    /// `true` when every body entry is `Plain` — i.e., no Lysis-
    /// specific structure has been introduced yet. A program in
    /// this state can be projected losslessly back into
    /// `IrProgram<F>` via [`Self::try_into_ir_program`].
    pub fn is_fully_plain(&self) -> bool {
        self.body.iter().all(ExtendedInstruction::is_plain)
    }

    /// Project into `IrProgram<F>` if every body node is `Plain`.
    /// Returns `Err(Box<self>)` otherwise so the caller can inspect
    /// what's holding the conversion back. The `Box` keeps the
    /// `Result` small (clippy's `result_large_err`).
    pub fn try_into_ir_program(self) -> Result<IrProgram<F>, Box<Self>> {
        if !self.is_fully_plain() {
            return Err(Box::new(self));
        }
        let mut out = IrProgram {
            instructions: Vec::with_capacity(self.body.len()),
            next_var: self.next_var,
            var_names: self.var_names,
            var_types: self.var_types,
            input_spans: self.input_spans,
            var_spans: self.var_spans,
        };
        for node in self.body {
            match node {
                ExtendedInstruction::Plain(inst) => out.instructions.push(inst),
                _ => unreachable!("checked via is_fully_plain"),
            }
        }
        Ok(out)
    }
}

/// Migration helper: wrap an existing `IrProgram<F>` as an
/// `ExtendedIrProgram<F>` by mapping every instruction to
/// `Plain`. Side-band metadata (spans, names, types) moves over
/// unchanged.
impl<F: FieldBackend> From<IrProgram<F>> for ExtendedIrProgram<F> {
    fn from(p: IrProgram<F>) -> Self {
        let body = p
            .instructions
            .into_iter()
            .map(ExtendedInstruction::Plain)
            .collect();
        Self {
            body,
            next_var: p.next_var,
            var_names: p.var_names,
            var_types: p.var_types,
            input_spans: p.input_spans,
            var_spans: p.var_spans,
        }
    }
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::extended::TemplateId;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    fn span(a: usize, b: usize) -> SpanRange {
        SpanRange::new(a, b, 1, a + 1, 1, b + 1)
    }

    #[test]
    fn new_program_is_empty() {
        let p = ExtendedIrProgram::<Bn254Fr>::new();
        assert_eq!(p.body.len(), 0);
        assert_eq!(p.next_var, 0);
        assert!(p.is_fully_plain()); // vacuously
    }

    #[test]
    fn push_plain_tracks_next_var() {
        let mut p = ExtendedIrProgram::<Bn254Fr>::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        p.push_plain(Instruction::Const {
            result: v0,
            value: fe(1),
        });
        p.push_plain(Instruction::Const {
            result: v1,
            value: fe(2),
        });
        assert_eq!(p.body.len(), 2);
        assert_eq!(p.next_var, 2);
    }

    #[test]
    fn span_storage_matches_ir_program_api() {
        let mut p = ExtendedIrProgram::<Bn254Fr>::new();
        let v = p.fresh_var();
        p.set_span(v, span(10, 20));
        assert_eq!(p.get_span(v).cloned(), Some(span(10, 20)));
        assert_eq!(p.get_span(SsaVar(99)), None);
    }

    #[test]
    fn is_fully_plain_detects_lysis_variants() {
        let mut p = ExtendedIrProgram::<Bn254Fr>::new();
        p.push_plain(Instruction::Const {
            result: SsaVar(0),
            value: fe(1),
        });
        assert!(p.is_fully_plain());

        p.push(ExtendedInstruction::TemplateCall {
            template_id: TemplateId(0),
            captures: vec![],
            outputs: vec![],
        });
        assert!(!p.is_fully_plain());
    }

    #[test]
    fn try_into_ir_program_round_trips_when_plain() {
        let mut p = ExtendedIrProgram::<Bn254Fr>::new();
        let v0 = p.fresh_var();
        p.set_span(v0, span(0, 5));
        p.push_plain(Instruction::Const {
            result: v0,
            value: fe(7),
        });
        let ir = p.try_into_ir_program().expect("all plain");
        assert_eq!(ir.instructions.len(), 1);
        assert_eq!(ir.var_spans.get(&v0).cloned(), Some(span(0, 5)));
        assert_eq!(ir.next_var, 1);
    }

    #[test]
    fn try_into_ir_program_refuses_non_plain() {
        let mut p = ExtendedIrProgram::<Bn254Fr>::new();
        p.push(ExtendedInstruction::TemplateCall {
            template_id: TemplateId(1),
            captures: vec![],
            outputs: vec![],
        });
        let err = p.try_into_ir_program().expect_err("has TemplateCall");
        assert_eq!(err.body.len(), 1);
    }

    #[test]
    fn from_ir_program_preserves_metadata() {
        let mut ir = IrProgram::<Bn254Fr>::new();
        let v = ir.fresh_var();
        ir.set_name(v, "x".into());
        ir.set_span(v, span(3, 8));
        ir.push(Instruction::Const {
            result: v,
            value: fe(42),
        });
        let ext: ExtendedIrProgram<Bn254Fr> = ir.into();
        assert_eq!(ext.body.len(), 1);
        assert_eq!(ext.get_name(v), Some("x"));
        assert_eq!(ext.get_span(v).cloned(), Some(span(3, 8)));
        assert!(ext.is_fully_plain());
    }

    #[test]
    fn migration_via_from_is_lossless_round_trip() {
        // ir → ext → ir preserves everything when no Lysis-specific
        // variants are introduced in the middle.
        let mut orig = IrProgram::<Bn254Fr>::new();
        let v0 = orig.fresh_var();
        let v1 = orig.fresh_var();
        let v2 = orig.fresh_var();
        orig.set_name(v0, "a".into());
        orig.set_name(v1, "b".into());
        orig.push(Instruction::Const {
            result: v0,
            value: fe(1),
        });
        orig.push(Instruction::Const {
            result: v1,
            value: fe(2),
        });
        orig.push(Instruction::Add {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let ext: ExtendedIrProgram<Bn254Fr> = orig.into();
        let back = ext.try_into_ir_program().expect("all plain");
        assert_eq!(back.instructions.len(), 3);
        assert_eq!(back.next_var, 3);
        assert_eq!(back.get_name(v0), Some("a"));
        assert_eq!(back.get_name(v1), Some("b"));
    }
}
