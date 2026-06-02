use std::collections::HashMap;

use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldBackend};

use super::{Instruction, SsaVar};

/// The IR-level type of an SSA variable (for gradual type checking).
///
/// ```
/// use ir_core::types::IrType;
///
/// let t = IrType::Field;
/// assert_eq!(format!("{t}"), "Field");
/// assert_eq!(t, IrType::Field);
/// assert_ne!(t, IrType::Bool);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IrType {
    Field,
    Bool,
}

impl std::fmt::Display for IrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrType::Field => write!(f, "Field"),
            IrType::Bool => write!(f, "Bool"),
        }
    }
}

/// A flat SSA program — a sequence of instructions.
///
/// ```
/// use ir_core::types::{IrProgram, IrType, Instruction, SsaVar};
/// use memory::FieldElement;
///
/// let mut prog: IrProgram = IrProgram::new();
/// let v = prog.fresh_var();
/// prog.push(Instruction::Const { result: v, value: FieldElement::from_u64(42) });
/// assert_eq!(prog.len(), 1);
/// assert_eq!(v, SsaVar(0));
///
/// // Type metadata starts empty
/// assert!(prog.get_type(v).is_none());
/// prog.set_type(v, IrType::Field);
/// assert_eq!(prog.get_type(v), Some(IrType::Field));
/// ```
///
/// Fields are `pub` because `ir-core` is the leaf vocabulary crate
/// and downstream IR owners (`ir` for flat SSA passes, `ir-forge` for
/// ProveIR-side operations) need direct field access for in-place
/// rewrites. External consumers (cli, circom, compiler, proving)
/// should prefer the accessor methods (`instructions()`,
/// `next_var()`, `set_name()`, etc.) — they carry the stable API
/// contract — but this is a convention, not a compile-time fence.
/// Hiding the fields behind `pub(crate)` would force passes,
/// evaluator, and ProveIR walker infrastructure across `ir` and
/// `ir-forge` to go through trait objects, with no real gain pre-1.0.
#[derive(Debug)]
pub struct IrProgram<F: FieldBackend = Bn254Fr> {
    pub instructions: Vec<Instruction<F>>,
    pub next_var: u64,
    pub var_names: HashMap<SsaVar, String>,
    pub var_types: HashMap<SsaVar, IrType>,
    pub input_spans: HashMap<String, SpanRange>,
    pub var_spans: HashMap<SsaVar, SpanRange>,
}

impl<F: FieldBackend> Default for IrProgram<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> IrProgram<F> {
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            next_var: 0,
            var_names: HashMap::new(),
            var_types: HashMap::new(),
            input_spans: HashMap::new(),
            var_spans: HashMap::new(),
        }
    }

    /// Allocate a fresh SSA variable.
    pub fn fresh_var(&mut self) -> SsaVar {
        let v = SsaVar(self.next_var);
        self.next_var += 1;
        v
    }

    /// Append an instruction and return its result variable.
    pub fn push(&mut self, inst: Instruction<F>) -> SsaVar {
        let v = inst.result_var();
        self.instructions.push(inst);
        v
    }

    /// Associate a source-level name with an SSA variable (for error messages).
    pub fn set_name(&mut self, var: SsaVar, name: String) {
        self.var_names.insert(var, name);
    }

    /// Look up the source-level name for an SSA variable.
    pub fn get_name(&self, var: SsaVar) -> Option<&str> {
        self.var_names.get(&var).map(|s| s.as_str())
    }

    /// Associate an IR type with an SSA variable.
    pub fn set_type(&mut self, var: SsaVar, ty: IrType) {
        self.var_types.insert(var, ty);
    }

    /// Look up the IR type for an SSA variable.
    pub fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.var_types.get(&var).copied()
    }

    /// Associate a source span with an SSA variable (for source mapping).
    pub fn set_span(&mut self, var: SsaVar, span: SpanRange) {
        self.var_spans.insert(var, span);
    }

    /// Look up the source span for an SSA variable.
    pub fn get_span(&self, var: SsaVar) -> Option<&SpanRange> {
        self.var_spans.get(&var)
    }

    /// Borrow the instruction stream as a read-only slice.
    pub fn instructions(&self) -> &[Instruction<F>] {
        &self.instructions
    }

    /// Iterator over instructions.
    pub fn iter(&self) -> std::slice::Iter<'_, Instruction<F>> {
        self.instructions.iter()
    }

    /// Mutable iterator over instructions (for in-place rewrite passes).
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Instruction<F>> {
        self.instructions.iter_mut()
    }

    /// Borrow the instruction stream as a mutable slice (for in-place
    /// indexed mutation). Slice — not `&mut Vec` — so callers cannot
    /// resize the program through this handle.
    pub fn instructions_mut(&mut self) -> &mut [Instruction<F>] {
        &mut self.instructions
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// True iff the program has no instructions.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Reserve capacity for at least `additional` more instructions.
    pub fn reserve(&mut self, additional: usize) {
        self.instructions.reserve(additional);
    }

    /// Drop instructions for which `keep` returns false (DCE pattern).
    pub fn retain_instructions<P>(&mut self, keep: P)
    where
        P: FnMut(&Instruction<F>) -> bool,
    {
        self.instructions.retain(keep);
    }

    /// Drain all instructions, leaving the program empty (const-fold pattern).
    pub fn drain_instructions(&mut self) -> std::vec::Drain<'_, Instruction<F>> {
        self.instructions.drain(..)
    }

    /// Replace the instruction stream wholesale.
    pub fn set_instructions(&mut self, insts: Vec<Instruction<F>>) {
        self.instructions = insts;
    }

    /// Consume the program and return the owned instruction stream.
    /// Useful for tests that just want to assert on the generated IR
    /// shape without keeping the surrounding metadata around.
    pub fn into_instructions(self) -> Vec<Instruction<F>> {
        self.instructions
    }

    /// Current `next_var` watermark (the id the next `fresh_var()` will return).
    pub fn next_var(&self) -> u64 {
        self.next_var
    }

    /// Force the `next_var` watermark — needed by passes that re-number SSA
    /// (canonicalization, oracle harness setup). Avoid in normal compile paths;
    /// use `fresh_var()` instead.
    pub fn set_next_var(&mut self, n: u64) {
        self.next_var = n;
    }

    /// Associate a source span with an input declaration (by name).
    pub fn set_input_span(&mut self, name: String, span: SpanRange) {
        self.input_spans.insert(name, span);
    }

    /// Look up the source span for an input declaration.
    pub fn get_input_span(&self, name: &str) -> Option<&SpanRange> {
        self.input_spans.get(name)
    }

    /// Iterator over `(SsaVar, &str)` of source-level names.
    pub fn iter_names(&self) -> impl Iterator<Item = (SsaVar, &str)> {
        self.var_names.iter().map(|(v, n)| (*v, n.as_str()))
    }
}

impl<F: FieldBackend> std::fmt::Display for IrProgram<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for inst in &self.instructions {
            let var = inst.result_var();
            write!(f, "  {inst}")?;
            // Show source-level name as comment (skip for Input — name already visible)
            if !matches!(inst, Instruction::Input { .. }) {
                if let Some(name) = self.var_names.get(&var) {
                    write!(f, "  ; {name}")?;
                }
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
