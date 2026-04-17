//! ProveIR data types — a pre-compiled circuit template representation.
//!
//! ProveIR sits between the AST and IR SSA: validated, desugared, functions
//! inlined, but loops and conditionals are preserved (not unrolled/mux'd).
//! It is parametric on "captures" — values from the outer scope that are
//! resolved at instantiation time (Phase B).
//!
//! All types are serializable via serde (Phase C) for embedding in `.achb`
//! bytecode files. Spans are skipped during serialization since they are
//! only useful at compile time.

use bincode::Options;
use diagnostics::SpanRange;
use memory::field::PrimeId;
use serde::{Deserialize, Serialize};

use crate::types::IrType;

pub mod display;
pub mod field_const;
pub use field_const::FieldConst;

// ---------------------------------------------------------------------------
// Top-level ProveIR
// ---------------------------------------------------------------------------

/// A pre-compiled circuit template, ready for instantiation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProveIR {
    /// Optional name for profiler/inspector identification.
    pub name: Option<String>,
    /// Variables the verifier knows (explicitly declared by user).
    pub public_inputs: Vec<ProveInputDecl>,
    /// Variables only the prover knows (auto-inferred or explicit).
    pub witness_inputs: Vec<ProveInputDecl>,
    /// Template parameters — values from outer scope that affect circuit
    /// structure or constraints.
    pub captures: Vec<CaptureDef>,
    /// The circuit body — validated, desugared, functions inlined.
    pub body: Vec<CircuitNode>,
    /// Array captures from the outer scope. Used at instantiation to
    /// reconstruct `InstEnvValue::Array` entries from individual element captures.
    pub capture_arrays: Vec<CaptureArrayDef>,
}

/// Magic header bytes for serialized ProveIR.
const PROVE_IR_MAGIC: &[u8; 4] = b"ACHP";

/// Format version (increment when enum variants change or fields are added).
/// v2: added `capture_arrays` field to ProveIR.
/// v3: added `message` field to CircuitNode::AssertEq.
/// v4: added PrimeId byte after version (multi-prime support).
/// v5: CircuitExpr::Const uses FieldConst ([u8;32] canonical LE) instead of FieldElement.
const PROVE_IR_FORMAT_VERSION: u8 = 5;

/// Maximum allowed size for deserialized ProveIR data (64 MB).
/// Prevents allocation bombs from crafted length prefixes.
const PROVE_IR_MAX_SIZE: u64 = 64 * 1024 * 1024;

impl ProveIR {
    /// Serialize to bytes with magic header, version, and prime identity.
    ///
    /// Format v4: `[MAGIC:4][VERSION:1][PRIME_ID:1][BINCODE_PAYLOAD]`
    pub fn to_bytes(&self, prime_id: PrimeId) -> Result<Vec<u8>, String> {
        let payload =
            bincode::serialize(self).map_err(|e| format!("ProveIR serialization failed: {e}"))?;
        let mut out = Vec::with_capacity(6 + payload.len());
        out.extend_from_slice(PROVE_IR_MAGIC);
        out.push(PROVE_IR_FORMAT_VERSION);
        out.push(prime_id.to_byte());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Validate structural invariants that the compiler guarantees but
    /// could be violated by crafted bytes.
    pub fn validate(&self) -> Result<(), String> {
        // Collect known capture names for cross-reference validation.
        let capture_names: std::collections::HashSet<&str> =
            self.captures.iter().map(|c| c.name.as_str()).collect();

        // Validate capture references in input array sizes.
        for input in self.public_inputs.iter().chain(self.witness_inputs.iter()) {
            if let Some(ArraySize::Capture(ref name)) = input.array_size {
                if !capture_names.contains(name.as_str()) {
                    return Err(format!(
                        "invalid ProveIR: array size references unknown capture `{name}`"
                    ));
                }
            }
        }

        for node in &self.body {
            validate_node(node, &capture_names)?;
        }
        Ok(())
    }

    /// Deserialize from bytes, validating magic header, version, and invariants.
    ///
    /// Returns the deserialized `ProveIR` and the `PrimeId` from the header.
    /// Accepts v3 (legacy, no prime — defaults to BN254) and v4 (with prime byte).
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, PrimeId), String> {
        if bytes.len() < 5 {
            return Err("ProveIR data too short (missing header)".into());
        }
        if &bytes[..4] != PROVE_IR_MAGIC {
            return Err(format!(
                "invalid ProveIR magic: expected {:?}, got {:?}",
                PROVE_IR_MAGIC,
                &bytes[..4]
            ));
        }
        let version = bytes[4];
        let (prime_id, payload) = match version {
            3 | 4 => {
                // Legacy v3: no PrimeId byte, assume BN254
                // Legacy v4: has PrimeId byte, uses FieldElement<Bn254Fr> layout
                // Both use the old serialization format — require recompile.
                return Err(format!(
                    "ProveIR format version {version} is no longer supported \
                     (current: {PROVE_IR_FORMAT_VERSION}). Please recompile the source."
                ));
            }
            PROVE_IR_FORMAT_VERSION => {
                // v5: PrimeId byte at offset 5, payload starts at 6.
                // CircuitExpr::Const uses FieldConst ([u8;32] canonical LE).
                if bytes.len() < 6 {
                    return Err("ProveIR v5 data too short (missing prime byte)".into());
                }
                let pid = PrimeId::from_byte(bytes[5]).ok_or_else(|| {
                    format!("unknown PrimeId byte 0x{:02x} in ProveIR header", bytes[5])
                })?;
                (pid, &bytes[6..])
            }
            _ => {
                return Err(format!(
                    "unsupported ProveIR format version: expected {}, got {}",
                    PROVE_IR_FORMAT_VERSION, version
                ));
            }
        };
        let prove_ir: Self = bincode::options()
            .with_limit(PROVE_IR_MAX_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes() // payload may be embedded in a larger buffer
            .deserialize(payload)
            .map_err(|e| format!("ProveIR deserialization failed: {e}"))?;
        prove_ir.validate()?;
        Ok((prove_ir, prime_id))
    }
}

/// Maximum allowed bits for RangeCheck (BN254 field is ~254 bits).
const MAX_RANGE_CHECK_BITS: u32 = 253;

fn validate_node(
    node: &CircuitNode,
    capture_names: &std::collections::HashSet<&str>,
) -> Result<(), String> {
    match node {
        CircuitNode::Let { value, .. } => validate_expr(value),
        CircuitNode::LetArray { elements, .. } => {
            for e in elements {
                validate_expr(e)?;
            }
            Ok(())
        }
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            validate_expr(lhs)?;
            validate_expr(rhs)
        }
        CircuitNode::Assert { expr, .. } => validate_expr(expr),
        CircuitNode::For { range, body, .. } => {
            // Validate ForRange::WithCapture references a known capture.
            if let ForRange::WithCapture { end_capture, .. } = range {
                if !capture_names.contains(end_capture.as_str()) {
                    return Err(format!(
                        "invalid ProveIR: loop bound references unknown capture `{end_capture}`"
                    ));
                }
            }
            // WithExpr end bounds are validated at instantiation time
            // when capture values are resolved.
            for n in body {
                validate_node(n, capture_names)?;
            }
            Ok(())
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            validate_expr(cond)?;
            for n in then_body {
                validate_node(n, capture_names)?;
            }
            for n in else_body {
                validate_node(n, capture_names)?;
            }
            Ok(())
        }
        CircuitNode::Expr { expr, .. } => validate_expr(expr),
        CircuitNode::Decompose { value, .. } => validate_expr(value),
        CircuitNode::WitnessHint { hint, .. } => validate_expr(hint),
        CircuitNode::LetIndexed { index, value, .. } => {
            validate_expr(index)?;
            validate_expr(value)
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            validate_expr(index)?;
            validate_expr(hint)
        }
    }
}

fn validate_expr(expr: &CircuitExpr) -> Result<(), String> {
    match expr {
        CircuitExpr::PoseidonMany(args) if args.len() < 2 => Err(format!(
            "invalid ProveIR: poseidon_many has {} args (need >= 2)",
            args.len()
        )),
        CircuitExpr::RangeCheck { bits, .. } if *bits == 0 || *bits > MAX_RANGE_CHECK_BITS => {
            Err(format!(
                "invalid ProveIR: range_check bits={bits} (must be 1..={MAX_RANGE_CHECK_BITS})"
            ))
        }
        // Recurse into sub-expressions
        CircuitExpr::BinOp { lhs, rhs, .. }
        | CircuitExpr::Comparison { lhs, rhs, .. }
        | CircuitExpr::BoolOp { lhs, rhs, .. } => {
            validate_expr(lhs)?;
            validate_expr(rhs)
        }
        CircuitExpr::UnaryOp { operand, .. } => validate_expr(operand),
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            validate_expr(cond)?;
            validate_expr(if_true)?;
            validate_expr(if_false)
        }
        CircuitExpr::PoseidonHash { left, right } => {
            validate_expr(left)?;
            validate_expr(right)
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args {
                validate_expr(a)?;
            }
            Ok(())
        }
        CircuitExpr::RangeCheck { value, .. } => validate_expr(value),
        CircuitExpr::MerkleVerify { root, leaf, .. } => {
            validate_expr(root)?;
            validate_expr(leaf)
        }
        CircuitExpr::ArrayIndex { index, .. } => validate_expr(index),
        CircuitExpr::Pow { base, .. } => validate_expr(base),
        CircuitExpr::IntDiv { lhs, rhs, .. } | CircuitExpr::IntMod { lhs, rhs, .. } => {
            validate_expr(lhs)?;
            validate_expr(rhs)
        }
        CircuitExpr::BitAnd { lhs, rhs, .. }
        | CircuitExpr::BitOr { lhs, rhs, .. }
        | CircuitExpr::BitXor { lhs, rhs, .. } => {
            validate_expr(lhs)?;
            validate_expr(rhs)
        }
        CircuitExpr::BitNot { operand, .. } => validate_expr(operand),
        CircuitExpr::ShiftR { operand, shift, .. } | CircuitExpr::ShiftL { operand, shift, .. } => {
            validate_expr(operand)?;
            validate_expr(shift)
        }
        // Leaf nodes — no sub-expressions
        CircuitExpr::Const(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Capture(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => Ok(()),
    }
}

/// An input declaration (public or witness).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProveInputDecl {
    pub name: String,
    pub array_size: Option<ArraySize>,
    pub ir_type: IrType,
}

/// Array size: either a compile-time literal or a captured value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ArraySize {
    Literal(usize),
    Capture(String),
}

/// A captured variable from the outer scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureDef {
    pub name: String,
    pub usage: CaptureUsage,
}

/// An array variable captured from the outer scope.
///
/// At instantiation, the individual element captures (`name_0`, `name_1`, …)
/// are reassembled into an `InstEnvValue::Array` so that array-consuming
/// constructs like `merkle_verify` can resolve the array by name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureArrayDef {
    /// The original array variable name in the outer scope (e.g., `"path"`).
    pub name: String,
    /// Number of elements in the array.
    pub size: usize,
}

/// How a captured variable is used in the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureUsage {
    /// Only affects structure (loop bounds, array sizes, exponents).
    /// Inlined as a constant during instantiation — NOT a circuit input.
    StructureOnly,
    /// Used in constraint expressions. Becomes a witness input.
    CircuitInput,
    /// Both structural and in constraints.
    Both,
}

// ---------------------------------------------------------------------------
// Circuit nodes (statement-level)
// ---------------------------------------------------------------------------

/// A node in the circuit body.
///
/// Spans are skipped during serialization — they are compile-time metadata
/// for error reporting and are not needed at runtime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CircuitNode {
    /// Immutable scalar binding: `let name = value`
    Let {
        name: String,
        value: CircuitExpr,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Array binding: `let name = [e0, e1, ...]`
    LetArray {
        name: String,
        elements: Vec<CircuitExpr>,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Equality constraint: `assert_eq(lhs, rhs)` or `assert_eq(lhs, rhs, "msg")`
    AssertEq {
        lhs: CircuitExpr,
        rhs: CircuitExpr,
        /// Optional user-provided message shown on failure.
        message: Option<String>,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Boolean constraint: `assert(expr)` or `assert(expr, "msg")` — expr must be 1
    Assert {
        expr: CircuitExpr,
        /// Optional user-provided message shown on failure.
        message: Option<String>,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// For loop (preserved, unrolled during instantiation)
    For {
        var: String,
        range: ForRange,
        body: Vec<CircuitNode>,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Conditional (preserved, converted to Mux during instantiation)
    If {
        cond: CircuitExpr,
        then_body: Vec<CircuitNode>,
        else_body: Vec<CircuitNode>,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Bare expression (e.g., a builtin call with side effects)
    Expr {
        expr: CircuitExpr,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Bit decomposition: `let name = decompose(value, num_bits)`
    /// Creates an array of bit variables (LSB first).
    Decompose {
        name: String,
        value: CircuitExpr,
        num_bits: u32,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Witness hint: `signal <-- expr` in Circom.
    ///
    /// The signal becomes a witness input variable (zero constraints).
    /// The hint expression is evaluated off-circuit by the prover to compute
    /// the witness value. Only `===` constraints verify the value.
    WitnessHint {
        name: String,
        hint: CircuitExpr,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Indexed let binding: `array[index] = value` inside a for loop.
    ///
    /// During instantiation, `index` resolves to a compile-time constant `i`,
    /// and the node becomes a scalar `Let { name: "{array}_{i}", value }`.
    /// Also updates the array's env entry so that later `ArrayIndex` reads work.
    LetIndexed {
        array: String,
        index: CircuitExpr,
        value: CircuitExpr,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Indexed witness hint: `array[index] <-- hint` inside a for loop.
    ///
    /// During instantiation, resolves to a scalar `WitnessHint { name: "{array}_{i}" }`.
    WitnessHintIndexed {
        array: String,
        index: CircuitExpr,
        hint: CircuitExpr,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
}

impl CircuitNode {
    /// Extract the source span from any node variant.
    pub fn span(&self) -> Option<&SpanRange> {
        match self {
            CircuitNode::Let { span, .. }
            | CircuitNode::LetArray { span, .. }
            | CircuitNode::AssertEq { span, .. }
            | CircuitNode::Assert { span, .. }
            | CircuitNode::For { span, .. }
            | CircuitNode::If { span, .. }
            | CircuitNode::Expr { span, .. }
            | CircuitNode::Decompose { span, .. }
            | CircuitNode::WitnessHint { span, .. }
            | CircuitNode::LetIndexed { span, .. }
            | CircuitNode::WitnessHintIndexed { span, .. } => span.as_ref(),
        }
    }
}

// ---------------------------------------------------------------------------
// For loop range
// ---------------------------------------------------------------------------

/// Range of a for loop in ProveIR.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ForRange {
    /// Both bounds are compile-time literals: `0..5`
    Literal { start: u64, end: u64 },
    /// End bound is a captured value: `0..n`
    WithCapture { start: u64, end_capture: String },
    /// End bound is a computed expression over captures: `0..(n+1)`
    ///
    /// Used when a component passes a computed template argument as a loop
    /// bound (e.g., `Num2Bits(n+1)` inside LessThan). The expression is
    /// evaluated at instantiation time when capture values are known.
    WithExpr {
        start: u64,
        end_expr: Box<CircuitExpr>,
    },
    /// Iterate over a named array variable
    Array(String),
}

// ---------------------------------------------------------------------------
// Circuit expressions (tree structure)
// ---------------------------------------------------------------------------

/// An expression in the circuit template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CircuitExpr {
    /// Compile-time constant (field-erased canonical bytes).
    Const(FieldConst),
    /// Reference to a public or witness input.
    Input(String),
    /// Reference to a captured template parameter.
    Capture(String),
    /// Reference to a local let-binding.
    Var(String),

    /// Arithmetic: +, -, *, /
    BinOp {
        op: CircuitBinOp,
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
    },
    /// Unary: -, !
    UnaryOp {
        op: CircuitUnaryOp,
        operand: Box<CircuitExpr>,
    },
    /// Comparison: ==, !=, <, <=, >, >=
    Comparison {
        op: CircuitCmpOp,
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
    },
    /// Boolean logic: &&, ||
    BoolOp {
        op: CircuitBoolOp,
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
    },

    /// Conditional selection: mux(cond, if_true, if_false)
    Mux {
        cond: Box<CircuitExpr>,
        if_true: Box<CircuitExpr>,
        if_false: Box<CircuitExpr>,
    },

    /// Poseidon 2-to-1 hash.
    PoseidonHash {
        left: Box<CircuitExpr>,
        right: Box<CircuitExpr>,
    },
    /// Poseidon N-ary hash (left-fold).
    PoseidonMany(Vec<CircuitExpr>),
    /// Range check: value fits in `bits` bits.
    RangeCheck { value: Box<CircuitExpr>, bits: u32 },
    /// Merkle membership verification.
    MerkleVerify {
        root: Box<CircuitExpr>,
        leaf: Box<CircuitExpr>,
        path: String,
        indices: String,
    },

    /// Array indexing: `array[index]`
    ArrayIndex {
        array: String,
        index: Box<CircuitExpr>,
    },
    /// Array length (compile-time if literal, capture if dynamic).
    ArrayLen(String),

    /// Power: `base ^ exp` (exp must be a constant u64).
    Pow { base: Box<CircuitExpr>, exp: u64 },

    /// Integer quotient: `floor(lhs / rhs)`.
    IntDiv {
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
        max_bits: u32,
    },
    /// Integer remainder: `lhs - rhs * floor(lhs / rhs)`.
    IntMod {
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
        max_bits: u32,
    },

    /// Bitwise AND: decompose both operands, multiply each bit pair, recompose.
    BitAnd {
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
        num_bits: u32,
    },
    /// Bitwise OR: decompose both, or = a + b - a*b per bit, recompose.
    BitOr {
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
        num_bits: u32,
    },
    /// Bitwise XOR: decompose both, xor = a + b - 2*a*b per bit, recompose.
    BitXor {
        lhs: Box<CircuitExpr>,
        rhs: Box<CircuitExpr>,
        num_bits: u32,
    },
    /// Bitwise NOT: decompose, flip each bit (1 - bit), recompose.
    BitNot {
        operand: Box<CircuitExpr>,
        num_bits: u32,
    },
    /// Right shift by constant amount: decompose, drop low bits, recompose.
    ShiftR {
        operand: Box<CircuitExpr>,
        shift: Box<CircuitExpr>,
        num_bits: u32,
    },
    /// Left shift: decompose, prepend zeros, recompose.
    ShiftL {
        operand: Box<CircuitExpr>,
        shift: Box<CircuitExpr>,
        num_bits: u32,
    },
}

// ---------------------------------------------------------------------------
// Operator enums (separate from AST's BinOp to exclude Mod/Pow)
// ---------------------------------------------------------------------------

/// Arithmetic binary operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitBinOp {
    Add,
    Sub,
    Mul,
    Div,
}

/// Unary operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitUnaryOp {
    Neg,
    Not,
}

/// Comparison operators available in circuits.
///
/// **Ordering semantics contract (Phase B):**
/// `Eq` and `Neq` are well-defined over field elements. However, `Lt`, `Le`,
/// `Gt`, and `Ge` have no standard ordering on a finite field (all elements
/// are in `[0, p-1]`). These operators are emitted by method desugarings
/// (`abs()`, `min()`, `max()`) and user-written comparisons.
///
/// Phase B (instantiation) MUST interpret ordering operators using a
/// **signed-range comparison gadget**: the field element is treated as a
/// two's-complement signed integer in `[-(p-1)/2, (p-1)/2]`, matching the
/// VM's signed integer semantics. This requires range decomposition
/// constraints (typically ~254 binary constraints for BN254).
///
/// Without this gadget, ordering comparisons produce incorrect results
/// (e.g., `abs()` would never negate because all field elements ≥ 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitCmpOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Boolean operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitBoolOp {
    And,
    Or,
}



#[cfg(test)]
mod tests;
