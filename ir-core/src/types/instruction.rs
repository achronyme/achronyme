use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::{SsaVar, Visibility};

/// Payload of [`Instruction::WitnessCall`].
///
/// Carried behind a `Box` so the rare witness-calculator variant does
/// not force every other `Instruction` variant to pay for its three
/// `Vec` headers. The boxed payload keeps the enum compact at the
/// cost of one extra heap allocation per emitted call (negligible:
/// witness calls are sparse compared to arithmetic instructions).
#[derive(Debug, Clone)]
pub struct WitnessCallBody {
    pub outputs: Vec<SsaVar>,
    pub inputs: Vec<SsaVar>,
    /// Serialized Artik program — validated once on emission; the
    /// prover decodes + executes it at witness-gen time.
    pub program_bytes: Vec<u8>,
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
    ///
    /// Payload is boxed; see [`WitnessCallBody`].
    WitnessCall(Box<WitnessCallBody>),
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
            Instruction::WitnessCall(call) => call
                .outputs
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
            Instruction::WitnessCall(call) if call.outputs.len() > 1 => &call.outputs[1..],
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
                | Instruction::WitnessCall(_)
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
            Instruction::WitnessCall(call) => call.inputs.clone(),
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
            Instruction::WitnessCall(call) => {
                let out_list = call
                    .outputs
                    .iter()
                    .map(|v| format!("{v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let in_list = call
                    .inputs
                    .iter()
                    .map(|v| format!("{v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "[{out_list}] = WitnessCall([{in_list}], <{} bytes>)",
                    call.program_bytes.len()
                )
            }
        }
    }
}
