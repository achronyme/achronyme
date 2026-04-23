use std::collections::HashMap;

use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldBackend, FieldElement};

/// An SSA variable — defined exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaVar(pub u32);

/// Whether a circuit input is public (instance) or private (witness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Witness,
}

impl std::fmt::Display for SsaVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%{}", self.0)
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Witness => write!(f, "witness"),
        }
    }
}

/// A single SSA instruction.
///
/// Each instruction defines exactly one `result` variable. The program is a
/// flat list of these instructions — no phi-nodes needed because circuits have
/// no dynamic branching.
#[derive(Debug, Clone)]
pub enum Instruction<F: FieldBackend = Bn254Fr> {
    /// A compile-time constant field element.
    Const {
        result: SsaVar,
        value: FieldElement<F>,
    },
    /// A circuit input (public or witness).
    Input {
        result: SsaVar,
        name: String,
        visibility: Visibility,
    },
    /// result = lhs + rhs
    Add {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = lhs - rhs
    Sub {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = lhs * rhs
    Mul {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = lhs / rhs
    Div {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// result = -operand
    Neg { result: SsaVar, operand: SsaVar },
    /// result = cond ? if_true : if_false (boolean MUX)
    Mux {
        result: SsaVar,
        cond: SsaVar,
        if_true: SsaVar,
        if_false: SsaVar,
    },
    /// Constraint: lhs == rhs. Result is an alias for lhs.
    AssertEq {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        /// Optional user-provided message shown on failure.
        message: Option<String>,
    },
    /// result = poseidon(left, right)
    PoseidonHash {
        result: SsaVar,
        left: SsaVar,
        right: SsaVar,
    },
    /// Range check: asserts operand fits in `bits` bits (0 ≤ operand < 2^bits).
    /// Result is an alias for operand.
    RangeCheck {
        result: SsaVar,
        operand: SsaVar,
        bits: u32,
    },
    /// Logical NOT: result = 1 - operand (operand must be boolean).
    Not { result: SsaVar, operand: SsaVar },
    /// Logical AND: result = lhs * rhs (both must be boolean).
    And {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Logical OR: result = lhs + rhs - lhs*rhs (both must be boolean).
    Or {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Equality check: result = 1 if lhs == rhs, 0 otherwise.
    IsEq {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Not-equal check: result = 1 if lhs != rhs, 0 otherwise.
    IsNeq {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Less-than check: result = 1 if lhs < rhs, 0 otherwise.
    /// Unbounded: full 252-bit decomposition (~761 constraints). Safe by default.
    ///
    /// **Signed-range comparison contract:** field elements are interpreted as
    /// signed integers in `[-(p-1)/2, (p-1)/2]`, matching the VM's signed
    /// semantics. This is required for correct behaviour of `abs()`, `min()`,
    /// `max()`, and user-written comparisons compiled through ProveIR.
    /// Backends (R1CS, Plonkish) MUST implement this contract.
    IsLt {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Less-or-equal check: result = 1 if lhs <= rhs, 0 otherwise.
    /// Unbounded: full 252-bit decomposition. Safe by default.
    ///
    /// **Signed-range comparison contract:** same semantics as `IsLt` — see above.
    IsLe {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
    },
    /// Bounded less-than: result = 1 if lhs < rhs, 0 otherwise.
    /// Both operands proven to fit in `bitwidth` bits via prior RangeCheck.
    /// Uses n+1 bit decomposition (~n+3 constraints). Emitted by bound_inference pass.
    IsLtBounded {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        bitwidth: u32,
    },
    /// Bounded less-or-equal: result = 1 if lhs <= rhs, 0 otherwise.
    /// Both operands proven to fit in `bitwidth` bits via prior RangeCheck.
    IsLeBounded {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        bitwidth: u32,
    },
    /// Assertion: enforces operand == 1 (boolean). Side-effecting.
    Assert {
        result: SsaVar,
        operand: SsaVar,
        /// Optional user-provided message shown on failure.
        message: Option<String>,
    },

    /// Decompose a value into individual bits (LSB first).
    ///
    /// `bit_results[i]` is the i-th bit (0 or 1).
    /// Constrains: each bit is boolean, `Σ bit_i * 2^i == operand`.
    /// `result` is an alias for `operand` (like RangeCheck).
    Decompose {
        result: SsaVar,
        bit_results: Vec<SsaVar>,
        operand: SsaVar,
        num_bits: u32,
    },

    /// Integer quotient: `result = floor(lhs / rhs)`.
    ///
    /// Constrains: `lhs = rhs * result + remainder`, `0 <= remainder < rhs`.
    /// `max_bits` is the bit-width bound for range checks on the quotient.
    IntDiv {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        max_bits: u32,
    },

    /// Integer remainder: `result = lhs - rhs * floor(lhs / rhs)`.
    ///
    /// Constrains: `lhs = rhs * quotient + result`, `0 <= result < rhs`.
    /// `max_bits` is the bit-width bound for range checks.
    IntMod {
        result: SsaVar,
        lhs: SsaVar,
        rhs: SsaVar,
        max_bits: u32,
    },

    /// Artik witness-calculator call. The prover executes the embedded
    /// Artik bytecode against the current values of `inputs` at
    /// witness-generation time and assigns the results to `outputs` in
    /// order. Emits no constraints — the outputs are witness-only
    /// wires exactly like `Input { visibility: Witness }`, but their
    /// values come from `program_bytes` instead of the caller's JSON.
    ///
    /// `outputs[0]` is the primary result wire; `outputs[1..]` are
    /// extras (used when the lifted circom function returned an
    /// array, one slot per element). At least one output is
    /// guaranteed by the lift.
    WitnessCall {
        outputs: Vec<SsaVar>,
        inputs: Vec<SsaVar>,
        /// Serialized Artik program — validated once on emission; the
        /// prover decodes + executes it at witness-gen time.
        program_bytes: Vec<u8>,
    },
}

impl<F: FieldBackend> Instruction<F> {
    /// The SSA variable defined by this instruction.
    pub fn result_var(&self) -> SsaVar {
        match self {
            Instruction::Const { result, .. }
            | Instruction::Input { result, .. }
            | Instruction::Add { result, .. }
            | Instruction::Sub { result, .. }
            | Instruction::Mul { result, .. }
            | Instruction::Div { result, .. }
            | Instruction::Neg { result, .. }
            | Instruction::Mux { result, .. }
            | Instruction::AssertEq { result, .. }
            | Instruction::PoseidonHash { result, .. }
            | Instruction::RangeCheck { result, .. }
            | Instruction::Not { result, .. }
            | Instruction::And { result, .. }
            | Instruction::Or { result, .. }
            | Instruction::IsEq { result, .. }
            | Instruction::IsNeq { result, .. }
            | Instruction::IsLt { result, .. }
            | Instruction::IsLe { result, .. }
            | Instruction::IsLtBounded { result, .. }
            | Instruction::IsLeBounded { result, .. }
            | Instruction::Assert { result, .. }
            | Instruction::Decompose { result, .. }
            | Instruction::IntDiv { result, .. }
            | Instruction::IntMod { result, .. } => *result,
            Instruction::WitnessCall { outputs, .. } => outputs
                .first()
                .copied()
                .expect("WitnessCall must have at least one output — enforced by the lift"),
        }
    }

    /// Returns additional result variables beyond the primary `result`.
    /// `Decompose` produces the bit variables; `WitnessCall` produces
    /// the secondary output slots (for array-return lifts).
    pub fn extra_result_vars(&self) -> &[SsaVar] {
        match self {
            Instruction::Decompose { bit_results, .. } => bit_results,
            Instruction::WitnessCall { outputs, .. } if outputs.len() > 1 => &outputs[1..],
            _ => &[],
        }
    }

    /// Returns true if this instruction has side effects (cannot be eliminated).
    pub fn has_side_effects(&self) -> bool {
        matches!(
            self,
            Instruction::AssertEq { .. }
                | Instruction::Input { .. }
                | Instruction::RangeCheck { .. }
                | Instruction::Assert { .. }
                | Instruction::Decompose { .. }
                | Instruction::WitnessCall { .. }
        )
    }

    /// Returns the SSA variables used (read) by this instruction.
    pub fn operands(&self) -> Vec<SsaVar> {
        match self {
            Instruction::Const { .. } | Instruction::Input { .. } => vec![],
            Instruction::Add { lhs, rhs, .. }
            | Instruction::Sub { lhs, rhs, .. }
            | Instruction::Mul { lhs, rhs, .. }
            | Instruction::Div { lhs, rhs, .. } => vec![*lhs, *rhs],
            Instruction::Neg { operand, .. }
            | Instruction::Not { operand, .. }
            | Instruction::Assert { operand, .. } => vec![*operand],
            Instruction::And { lhs, rhs, .. }
            | Instruction::Or { lhs, rhs, .. }
            | Instruction::IsEq { lhs, rhs, .. }
            | Instruction::IsNeq { lhs, rhs, .. }
            | Instruction::IsLt { lhs, rhs, .. }
            | Instruction::IsLe { lhs, rhs, .. }
            | Instruction::IsLtBounded { lhs, rhs, .. }
            | Instruction::IsLeBounded { lhs, rhs, .. } => vec![*lhs, *rhs],
            Instruction::Mux {
                cond,
                if_true,
                if_false,
                ..
            } => vec![*cond, *if_true, *if_false],
            Instruction::AssertEq { lhs, rhs, .. } => vec![*lhs, *rhs],
            Instruction::PoseidonHash { left, right, .. } => vec![*left, *right],
            Instruction::RangeCheck { operand, .. } | Instruction::Decompose { operand, .. } => {
                vec![*operand]
            }
            Instruction::IntDiv { lhs, rhs, .. } | Instruction::IntMod { lhs, rhs, .. } => {
                vec![*lhs, *rhs]
            }
            Instruction::WitnessCall { inputs, .. } => inputs.clone(),
        }
    }
}

impl<F: FieldBackend> std::fmt::Display for Instruction<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Instruction::Const { result, value } => write!(f, "{result} = Const({value})"),
            Instruction::Input {
                result,
                name,
                visibility,
            } => write!(f, "{result} = Input(\"{name}\", {visibility})"),
            Instruction::Add { result, lhs, rhs } => {
                write!(f, "{result} = Add({lhs}, {rhs})")
            }
            Instruction::Sub { result, lhs, rhs } => {
                write!(f, "{result} = Sub({lhs}, {rhs})")
            }
            Instruction::Mul { result, lhs, rhs } => {
                write!(f, "{result} = Mul({lhs}, {rhs})")
            }
            Instruction::Div { result, lhs, rhs } => {
                write!(f, "{result} = Div({lhs}, {rhs})")
            }
            Instruction::Neg { result, operand } => write!(f, "{result} = Neg({operand})"),
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => write!(f, "{result} = Mux({cond}, {if_true}, {if_false})"),
            Instruction::AssertEq {
                result,
                lhs,
                rhs,
                message,
            } => match message {
                Some(msg) => write!(f, "{result} = AssertEq({lhs}, {rhs}, \"{msg}\")"),
                None => write!(f, "{result} = AssertEq({lhs}, {rhs})"),
            },
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => write!(f, "{result} = PoseidonHash({left}, {right})"),
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => write!(f, "{result} = RangeCheck({operand}, {bits})"),
            Instruction::Not { result, operand } => write!(f, "{result} = Not({operand})"),
            Instruction::And { result, lhs, rhs } => {
                write!(f, "{result} = And({lhs}, {rhs})")
            }
            Instruction::Or { result, lhs, rhs } => {
                write!(f, "{result} = Or({lhs}, {rhs})")
            }
            Instruction::IsEq { result, lhs, rhs } => {
                write!(f, "{result} = IsEq({lhs}, {rhs})")
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                write!(f, "{result} = IsNeq({lhs}, {rhs})")
            }
            Instruction::IsLt { result, lhs, rhs } => {
                write!(f, "{result} = IsLt({lhs}, {rhs})")
            }
            Instruction::IsLe { result, lhs, rhs } => {
                write!(f, "{result} = IsLe({lhs}, {rhs})")
            }
            Instruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => write!(f, "{result} = IsLtBounded({lhs}, {rhs}, {bitwidth})"),
            Instruction::IsLeBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => write!(f, "{result} = IsLeBounded({lhs}, {rhs}, {bitwidth})"),
            Instruction::Assert {
                result,
                operand,
                message,
            } => match message {
                Some(msg) => write!(f, "{result} = Assert({operand}, \"{msg}\")"),
                None => write!(f, "{result} = Assert({operand})"),
            },
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let bits_str: Vec<String> = bit_results.iter().map(|b| b.to_string()).collect();
                write!(
                    f,
                    "{result} = Decompose({operand}, {num_bits}) -> [{}]",
                    bits_str.join(", ")
                )
            }
            Instruction::IntDiv {
                result,
                lhs,
                rhs,
                max_bits,
            } => write!(f, "{result} = IntDiv({lhs}, {rhs}, {max_bits})"),
            Instruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => write!(f, "{result} = IntMod({lhs}, {rhs}, {max_bits})"),
            Instruction::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                let out_list = outputs
                    .iter()
                    .map(|v| format!("{v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let in_list = inputs
                    .iter()
                    .map(|v| format!("{v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "[{out_list}] = WitnessCall([{in_list}], <{} bytes>)",
                    program_bytes.len()
                )
            }
        }
    }
}

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
/// The stronger `pub(crate)` encapsulation from P3 only made sense
/// when IrProgram lived in the `ir` crate; after the Phase 7 split
/// into `ir-core` + `ir` + `ir-forge`, accessor-only access would
/// require duplicating the entire passes + evaluator + ProveIR
/// walker infrastructure behind trait objects, for no real gain
/// pre-1.0.
/// accessor methods (`push`, `iter`, `len`, `set_name`, etc.) so the
/// internal storage shape can evolve without breaking downstream code.
#[derive(Debug)]
pub struct IrProgram<F: FieldBackend = Bn254Fr> {
    pub instructions: Vec<Instruction<F>>,
    pub next_var: u32,
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
    pub fn next_var(&self) -> u32 {
        self.next_var
    }

    /// Force the `next_var` watermark — needed by passes that re-number SSA
    /// (canonicalization, oracle harness setup). Avoid in normal compile paths;
    /// use `fresh_var()` instead.
    pub fn set_next_var(&mut self, n: u32) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_var_increments() {
        let mut p: IrProgram = IrProgram::new();
        assert_eq!(p.fresh_var(), SsaVar(0));
        assert_eq!(p.fresh_var(), SsaVar(1));
        assert_eq!(p.fresh_var(), SsaVar(2));
        assert_eq!(p.next_var, 3);
    }

    #[test]
    fn result_var_extracts_correctly() {
        let inst: Instruction = Instruction::Add {
            result: SsaVar(42),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
        };
        assert_eq!(inst.result_var(), SsaVar(42));
    }

    #[test]
    fn push_appends_and_returns_result() {
        let mut p: IrProgram = IrProgram::new();
        let v = p.fresh_var();
        let r = p.push(Instruction::Const {
            result: v,
            value: FieldElement::from_u64(99),
        });
        assert_eq!(r, SsaVar(0));
        assert_eq!(p.instructions.len(), 1);
    }

    #[test]
    fn has_side_effects() {
        let assert_inst: Instruction = Instruction::AssertEq {
            result: SsaVar(0),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
            message: None,
        };
        assert!(assert_inst.has_side_effects());

        let add_inst: Instruction = Instruction::Add {
            result: SsaVar(0),
            lhs: SsaVar(1),
            rhs: SsaVar(2),
        };
        assert!(!add_inst.has_side_effects());
    }

    #[test]
    fn set_get_type_round_trip() {
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        assert!(p.get_type(v0).is_none());
        p.set_type(v0, IrType::Field);
        p.set_type(v1, IrType::Bool);
        assert_eq!(p.get_type(v0), Some(IrType::Field));
        assert_eq!(p.get_type(v1), Some(IrType::Bool));
    }

    #[test]
    fn ir_type_display() {
        assert_eq!(format!("{}", IrType::Field), "Field");
        assert_eq!(format!("{}", IrType::Bool), "Bool");
    }

    #[test]
    fn operands_returns_correct_vars() {
        let mux: Instruction = Instruction::Mux {
            result: SsaVar(10),
            cond: SsaVar(1),
            if_true: SsaVar(2),
            if_false: SsaVar(3),
        };
        assert_eq!(mux.operands(), vec![SsaVar(1), SsaVar(2), SsaVar(3)]);

        let c = Instruction::Const {
            result: SsaVar(0),
            value: FieldElement::ZERO,
        };
        assert!(c.operands().is_empty());
    }

    #[test]
    fn ssa_var_display() {
        assert_eq!(format!("{}", SsaVar(0)), "%0");
        assert_eq!(format!("{}", SsaVar(42)), "%42");
    }

    #[test]
    fn visibility_display() {
        assert_eq!(format!("{}", Visibility::Public), "public");
        assert_eq!(format!("{}", Visibility::Witness), "witness");
    }

    #[test]
    fn instruction_display() {
        let inst: Instruction = Instruction::Input {
            result: SsaVar(0),
            name: "x".into(),
            visibility: Visibility::Public,
        };
        assert_eq!(format!("{inst}"), "%0 = Input(\"x\", public)");

        let inst: Instruction = Instruction::Mul {
            result: SsaVar(2),
            lhs: SsaVar(0),
            rhs: SsaVar(1),
        };
        assert_eq!(format!("{inst}"), "%2 = Mul(%0, %1)");

        let inst: Instruction = Instruction::Const {
            result: SsaVar(3),
            value: FieldElement::from_u64(42),
        };
        assert_eq!(format!("{inst}"), "%3 = Const(42)");

        let inst: Instruction = Instruction::RangeCheck {
            result: SsaVar(5),
            operand: SsaVar(4),
            bits: 8,
        };
        assert_eq!(format!("{inst}"), "%5 = RangeCheck(%4, 8)");

        let inst: Instruction = Instruction::Mux {
            result: SsaVar(6),
            cond: SsaVar(0),
            if_true: SsaVar(1),
            if_false: SsaVar(2),
        };
        assert_eq!(format!("{inst}"), "%6 = Mux(%0, %1, %2)");
    }

    #[test]
    fn program_display() {
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        p.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let v1 = p.fresh_var();
        p.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = p.fresh_var();
        p.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        p.set_name(v2, "product".into());

        let output = format!("{p}");
        assert!(output.contains("%0 = Input(\"x\", public)"));
        assert!(output.contains("%1 = Input(\"y\", witness)"));
        assert!(output.contains("%2 = Mul(%0, %1)  ; product"));
    }

    #[test]
    fn set_get_span_round_trip() {
        let mut p: IrProgram = IrProgram::new();
        let v0 = p.fresh_var();
        let v1 = p.fresh_var();
        let span = SpanRange::new(10, 20, 3, 5, 3, 15);
        assert!(p.get_span(v0).is_none());
        p.set_span(v0, span.clone());
        assert_eq!(p.get_span(v0), Some(&span));
        assert!(p.get_span(v1).is_none());
    }

    // `var_spans_survive_dce` moved to `ir/src/passes/dce.rs` — it exercises
    // the DCE pass, which lives in `ir` not `ir-core`.
}
