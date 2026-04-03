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
use memory::{FieldBackend, FieldElement};
use serde::{Deserialize, Serialize};

use crate::types::IrType;

// ---------------------------------------------------------------------------
// FieldConst — field-erased constant (canonical LE bytes)
// ---------------------------------------------------------------------------

/// A field-erased constant stored as 32 canonical little-endian bytes.
///
/// This allows ProveIR to remain non-generic while storing constants from
/// any supported prime field. The `PrimeId` in the serialization header
/// tells the instantiator which `FieldElement<F>` to reconstruct.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FieldConst([u8; 32]);

impl std::fmt::Debug for FieldConst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show as hex for readability
        let limbs = [
            u64::from_le_bytes(self.0[0..8].try_into().unwrap()),
            u64::from_le_bytes(self.0[8..16].try_into().unwrap()),
            u64::from_le_bytes(self.0[16..24].try_into().unwrap()),
            u64::from_le_bytes(self.0[24..32].try_into().unwrap()),
        ];
        if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
            write!(f, "FieldConst({})", limbs[0])
        } else {
            write!(
                f,
                "FieldConst(0x{:016x}{:016x}{:016x}{:016x})",
                limbs[3], limbs[2], limbs[1], limbs[0]
            )
        }
    }
}

impl FieldConst {
    /// The additive identity (zero) — same in all fields.
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// The multiplicative identity (one) — same in all fields.
    pub fn one() -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        Self(bytes)
    }

    /// Create from a small integer. Valid in all fields (all moduli > 2^64).
    pub fn from_u64(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&v.to_le_bytes());
        Self(bytes)
    }

    /// Create from a `FieldElement<F>` by extracting canonical LE bytes.
    pub fn from_field<F: FieldBackend>(fe: FieldElement<F>) -> Self {
        Self(fe.to_le_bytes())
    }

    /// Reconstruct a `FieldElement<F>` from the stored bytes.
    /// Returns `None` if the bytes are not valid in field `F` (e.g., >= modulus).
    pub fn to_field<F: FieldBackend>(&self) -> Option<FieldElement<F>> {
        FieldElement::<F>::from_le_bytes(&self.0)
    }

    /// Extract as u64 if the value fits. Returns `None` if upper bytes are nonzero.
    pub fn to_u64(&self) -> Option<u64> {
        if self.0[8..].iter().any(|&b| b != 0) {
            return None;
        }
        Some(u64::from_le_bytes(self.0[..8].try_into().unwrap()))
    }

    /// Check if this is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Create from a decimal string (e.g., `"218882428718392752..."`).
    ///
    /// Stores the raw integer as LE bytes — no modular reduction.
    /// Returns `None` if the string is invalid or the value exceeds 32 bytes.
    pub fn from_decimal_str(s: &str) -> Option<Self> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut bytes = [0u8; 32];
        for &ch in s.as_bytes() {
            let digit = (ch - b'0') as u16;
            // Multiply current value by 10, then add digit
            let mut carry = digit;
            for byte in bytes.iter_mut() {
                let v = (*byte as u16) * 10 + carry;
                *byte = v as u8;
                carry = v >> 8;
            }
            if carry != 0 {
                return None; // overflow: value doesn't fit in 256 bits
            }
        }
        Some(Self(bytes))
    }

    /// Create from a hex string (with or without `0x`/`0X` prefix).
    ///
    /// Stores the raw integer as LE bytes — no modular reduction.
    /// Returns `None` if the string is invalid or exceeds 32 bytes (64 hex digits).
    pub fn from_hex_str(s: &str) -> Option<Self> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        if hex.is_empty() || hex.len() > 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let digits = hex.as_bytes();
        let mut byte_idx = 0;
        let mut i = digits.len();
        while i > 0 {
            let lo = fc_hex_val(digits[i - 1])?;
            i -= 1;
            let hi = if i > 0 {
                i -= 1;
                fc_hex_val(digits[i])?
            } else {
                0
            };
            bytes[byte_idx] = (hi << 4) | lo;
            byte_idx += 1;
        }
        Some(Self(bytes))
    }

    /// Raw bytes access.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Parse a single hex digit to its value.
fn fc_hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

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
        CircuitExpr::BitNot { operand, .. }
        | CircuitExpr::ShiftR { operand, .. }
        | CircuitExpr::ShiftL { operand, .. } => validate_expr(operand),
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
            | CircuitNode::WitnessHint { span, .. } => span.as_ref(),
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
        shift: u32,
        num_bits: u32,
    },
    /// Left shift by constant amount: decompose, prepend zeros, recompose.
    ShiftL {
        operand: Box<CircuitExpr>,
        shift: u32,
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

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

use std::fmt;

impl fmt::Display for ProveIR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Captures
        if !self.captures.is_empty() {
            writeln!(f, "  Captures:")?;
            for cap in &self.captures {
                let usage = match cap.usage {
                    CaptureUsage::StructureOnly => "structure",
                    CaptureUsage::CircuitInput => "witness",
                    CaptureUsage::Both => "witness+structure",
                };
                writeln!(f, "    {:<20} ({})", cap.name, usage)?;
            }
        }
        if !self.capture_arrays.is_empty() {
            for arr in &self.capture_arrays {
                writeln!(f, "    {:<20} (array, len={})", arr.name, arr.size)?;
            }
        }

        // Inputs
        if !self.public_inputs.is_empty() {
            writeln!(f, "  Public inputs:")?;
            for inp in &self.public_inputs {
                write!(f, "    {}: {}", inp.name, inp.ir_type)?;
                if let Some(ref sz) = inp.array_size {
                    write!(f, "[{}]", sz)?;
                }
                writeln!(f)?;
            }
        }
        if !self.witness_inputs.is_empty() {
            writeln!(f, "  Witness inputs:")?;
            for inp in &self.witness_inputs {
                write!(f, "    {}: {}", inp.name, inp.ir_type)?;
                if let Some(ref sz) = inp.array_size {
                    write!(f, "[{}]", sz)?;
                }
                writeln!(f)?;
            }
        }

        // Body
        if !self.body.is_empty() {
            writeln!(f, "  Body:")?;
            for node in &self.body {
                write_node(f, node, 2)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for ArraySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArraySize::Literal(n) => write!(f, "{n}"),
            ArraySize::Capture(name) => write!(f, "{name}"),
        }
    }
}

fn write_node(f: &mut fmt::Formatter<'_>, node: &CircuitNode, indent: usize) -> fmt::Result {
    let pad = "    ".repeat(indent);
    match node {
        CircuitNode::Let { name, value, .. } => {
            writeln!(f, "{pad}let {name} = {value}")
        }
        CircuitNode::LetArray { name, elements, .. } => {
            write!(f, "{pad}let {name} = [")?;
            for (i, e) in elements.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{e}")?;
            }
            writeln!(f, "]")
        }
        CircuitNode::AssertEq {
            lhs, rhs, message, ..
        } => {
            write!(f, "{pad}assert_eq({lhs}, {rhs}")?;
            if let Some(msg) = message {
                write!(f, ", \"{msg}\"")?;
            }
            writeln!(f, ")")
        }
        CircuitNode::Assert { expr, message, .. } => {
            write!(f, "{pad}assert({expr}")?;
            if let Some(msg) = message {
                write!(f, ", \"{msg}\"")?;
            }
            writeln!(f, ")")
        }
        CircuitNode::For {
            var, range, body, ..
        } => {
            write!(f, "{pad}for {var} in ")?;
            match range {
                ForRange::Literal { start, end } => writeln!(f, "{start}..{end} {{")?,
                ForRange::WithCapture { start, end_capture } => {
                    writeln!(f, "{start}..{end_capture} {{")?
                }
                ForRange::Array(name) => writeln!(f, "{name} {{")?,
            }
            for n in body {
                write_node(f, n, indent + 1)?;
            }
            writeln!(f, "{pad}}}")
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            writeln!(f, "{pad}if {cond} {{")?;
            for n in then_body {
                write_node(f, n, indent + 1)?;
            }
            if !else_body.is_empty() {
                writeln!(f, "{pad}}} else {{")?;
                for n in else_body {
                    write_node(f, n, indent + 1)?;
                }
            }
            writeln!(f, "{pad}}}")
        }
        CircuitNode::Expr { expr, .. } => {
            writeln!(f, "{pad}{expr}")
        }
        CircuitNode::Decompose {
            name,
            value,
            num_bits,
            ..
        } => {
            writeln!(f, "{pad}let {name} = decompose({value}, {num_bits})")
        }
        CircuitNode::WitnessHint { name, hint, .. } => {
            writeln!(f, "{pad}{name} <-- {hint}")
        }
    }
}

impl fmt::Display for CircuitExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitExpr::Const(fe) => write!(f, "{fe:?}"),
            CircuitExpr::Input(name) => write!(f, "{name}"),
            CircuitExpr::Capture(name) => write!(f, "${name}"),
            CircuitExpr::Var(name) => write!(f, "{name}"),
            CircuitExpr::BinOp { op, lhs, rhs } => {
                write!(f, "({lhs} {op} {rhs})")
            }
            CircuitExpr::UnaryOp { op, operand } => {
                write!(f, "{op}{operand}")
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                write!(f, "({lhs} {op} {rhs})")
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                write!(f, "({lhs} {op} {rhs})")
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => write!(f, "mux({cond}, {if_true}, {if_false})"),
            CircuitExpr::PoseidonHash { left, right } => {
                write!(f, "poseidon({left}, {right})")
            }
            CircuitExpr::PoseidonMany(args) => {
                write!(f, "poseidon(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            CircuitExpr::RangeCheck { value, bits } => {
                write!(f, "range_check({value}, {bits})")
            }
            CircuitExpr::MerkleVerify {
                root,
                leaf,
                path,
                indices,
            } => write!(f, "merkle_verify({root}, {leaf}, {path}, {indices})"),
            CircuitExpr::ArrayIndex { array, index } => write!(f, "{array}[{index}]"),
            CircuitExpr::ArrayLen(name) => write!(f, "{name}.len()"),
            CircuitExpr::Pow { base, exp } => write!(f, "({base} ^ {exp})"),
            CircuitExpr::IntDiv { lhs, rhs, max_bits } => {
                write!(f, "int_div({lhs}, {rhs}, {max_bits})")
            }
            CircuitExpr::IntMod { lhs, rhs, max_bits } => {
                write!(f, "int_mod({lhs}, {rhs}, {max_bits})")
            }
            CircuitExpr::BitAnd { lhs, rhs, .. } => write!(f, "({lhs} & {rhs})"),
            CircuitExpr::BitOr { lhs, rhs, .. } => write!(f, "({lhs} | {rhs})"),
            CircuitExpr::BitXor { lhs, rhs, .. } => write!(f, "({lhs} ^ {rhs})"),
            CircuitExpr::BitNot { operand, .. } => write!(f, "~{operand}"),
            CircuitExpr::ShiftR { operand, shift, .. } => write!(f, "({operand} >> {shift})"),
            CircuitExpr::ShiftL { operand, shift, .. } => write!(f, "({operand} << {shift})"),
        }
    }
}

impl fmt::Display for CircuitBinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBinOp::Add => write!(f, "+"),
            CircuitBinOp::Sub => write!(f, "-"),
            CircuitBinOp::Mul => write!(f, "*"),
            CircuitBinOp::Div => write!(f, "/"),
        }
    }
}

impl fmt::Display for CircuitUnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitUnaryOp::Neg => write!(f, "-"),
            CircuitUnaryOp::Not => write!(f, "!"),
        }
    }
}

impl fmt::Display for CircuitCmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitCmpOp::Eq => write!(f, "=="),
            CircuitCmpOp::Neq => write!(f, "!="),
            CircuitCmpOp::Lt => write!(f, "<"),
            CircuitCmpOp::Le => write!(f, "<="),
            CircuitCmpOp::Gt => write!(f, ">"),
            CircuitCmpOp::Ge => write!(f, ">="),
        }
    }
}

impl fmt::Display for CircuitBoolOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBoolOp::And => write!(f, "&&"),
            CircuitBoolOp::Or => write!(f, "||"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prove_ir::compiler::{OuterScope, OuterScopeEntry, ProveIrCompiler};
    use memory::Bn254Fr;

    /// Round-trip: ProveIR → bytes → ProveIR, verify equality.
    fn assert_round_trip(prove_ir: &ProveIR) {
        let bytes = prove_ir
            .to_bytes(PrimeId::Bn254)
            .expect("serialization failed");
        let (restored, prime) = ProveIR::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(prime, PrimeId::Bn254);

        // Spans are skipped, so we compare field-by-field excluding spans.
        assert_eq!(prove_ir.public_inputs, restored.public_inputs);
        assert_eq!(prove_ir.witness_inputs, restored.witness_inputs);
        assert_eq!(prove_ir.captures, restored.captures);
        // Body comparison: spans will be None after round-trip.
        // Compare the number and structure of nodes.
        assert_eq!(prove_ir.body.len(), restored.body.len());
    }

    #[test]
    fn round_trip_empty() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        };
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_simple_circuit() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public x\npublic out\nwitness s\nassert_eq(x + s, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_assert_eq_with_message() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public x\npublic out\nwitness s\nassert_eq(x + s, out, \"sums must match\")",
        )
        .unwrap();
        let bytes = ir.to_bytes(PrimeId::Bn254).expect("serialization failed");
        let (restored, _) = ProveIR::from_bytes(&bytes).expect("deserialization failed");
        // Verify message survives round-trip
        let msg = restored.body.iter().find_map(|n| {
            if let CircuitNode::AssertEq { message, .. } = n {
                message.clone()
            } else {
                None
            }
        });
        assert_eq!(msg.as_deref(), Some("sums must match"));
    }

    #[test]
    fn round_trip_with_all_expr_types() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public a\npublic b\npublic out\n\
             let sum = a + b\n\
             let diff = a - b\n\
             let prod = a * b\n\
             let neg = -a\n\
             let cmp = a == b\n\
             let lt = a < b\n\
             let both = cmp && lt\n\
             let sel = mux(cmp, a, b)\n\
             let h = poseidon(a, b)\n\
             range_check(a, 8)\n\
             let p = a ^ 3\n\
             assert_eq(sum, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_for_loop() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public out\nmut acc = 0\nfor i in 0..5 { acc = acc + i }\nassert_eq(acc, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_if_else() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_captures() {
        let scope = OuterScope {
            values: ["secret", "hash"]
                .iter()
                .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
                .collect(),
            ..Default::default()
        };
        let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "public hash\nassert_eq(poseidon(secret, 0), hash)",
            &scope,
        )
        .unwrap();
        assert_round_trip(&ir);
        assert_eq!(ir.captures.len(), 1);
    }

    #[test]
    fn round_trip_with_arrays() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public out\nlet arr = [1, 2, 3]\nassert_eq(arr_0, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_functions() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public out\nfn double(x) { x * 2 }\nassert_eq(double(21), out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_preserves_field_elements() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public out\nassert_eq(Field::ZERO + Field::ONE, out)",
        )
        .unwrap();
        let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
        let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();

        // The body should contain Const(ZERO) and Const(ONE) nodes.
        // After round-trip, the FieldElement values must be identical.
        fn collect_consts(body: &[CircuitNode]) -> Vec<&FieldConst> {
            let mut consts = Vec::new();
            for node in body {
                if let CircuitNode::Let { value, .. } = node {
                    collect_expr_consts(value, &mut consts);
                }
                if let CircuitNode::AssertEq { lhs, rhs, .. } = node {
                    collect_expr_consts(lhs, &mut consts);
                    collect_expr_consts(rhs, &mut consts);
                }
            }
            consts
        }
        fn collect_expr_consts<'a>(expr: &'a CircuitExpr, out: &mut Vec<&'a FieldConst>) {
            match expr {
                CircuitExpr::Const(fe) => out.push(fe),
                CircuitExpr::BinOp { lhs, rhs, .. } => {
                    collect_expr_consts(lhs, out);
                    collect_expr_consts(rhs, out);
                }
                _ => {}
            }
        }

        let original_consts = collect_consts(&ir.body);
        let restored_consts = collect_consts(&restored.body);
        assert_eq!(original_consts.len(), restored_consts.len());
        for (a, b) in original_consts.iter().zip(restored_consts.iter()) {
            assert_eq!(a, b, "FieldElement round-trip mismatch");
        }
    }

    #[test]
    fn round_trip_instantiate_produces_same_result() {
        use std::collections::HashMap;

        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public x\npublic out\nassert_eq(x + 1, out)",
        )
        .unwrap();

        // Instantiate original
        let program1 = ir.instantiate::<Bn254Fr>(&HashMap::new()).unwrap();

        // Round-trip and instantiate
        let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
        let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();
        let program2 = restored.instantiate::<Bn254Fr>(&HashMap::new()).unwrap();

        // Both should produce identical instruction counts and types
        assert_eq!(
            program1.instructions.len(),
            program2.instructions.len(),
            "instruction count mismatch after round-trip"
        );
    }

    #[test]
    fn serialized_size_reasonable() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public a\npublic b\npublic out\nassert_eq(poseidon(a, b), out)",
        )
        .unwrap();
        let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
        // A simple circuit should serialize to < 1 KB
        assert!(
            bytes.len() < 1024,
            "serialized size {} bytes seems too large",
            bytes.len()
        );
    }

    // =====================================================================
    // Display tests
    // =====================================================================

    #[test]
    fn display_simple_circuit() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public x\npublic out\nwitness s\nassert_eq(x + s, out)",
        )
        .unwrap();
        let output = format!("{ir}");
        assert!(output.contains("Public inputs:"), "got:\n{output}");
        assert!(output.contains("x: Field"), "got:\n{output}");
        assert!(output.contains("Witness inputs:"), "got:\n{output}");
        assert!(output.contains("s: Field"), "got:\n{output}");
        assert!(output.contains("assert_eq("), "got:\n{output}");
    }

    #[test]
    fn display_with_captures() {
        let scope = OuterScope {
            values: [("secret", OuterScopeEntry::Scalar)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            ..Default::default()
        };
        let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "public hash\nassert_eq(poseidon(secret, 0), hash)",
            &scope,
        )
        .unwrap();
        let output = format!("{ir}");
        assert!(output.contains("Captures:"), "got:\n{output}");
        assert!(output.contains("secret"), "got:\n{output}");
        assert!(output.contains("poseidon("), "got:\n{output}");
    }

    #[test]
    fn display_with_for_loop() {
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public out\nmut acc = 0\nfor i in 0..3 { acc = acc + i }\nassert_eq(acc, out)",
        )
        .unwrap();
        let output = format!("{ir}");
        assert!(output.contains("for i in 0..3"), "got:\n{output}");
    }

    #[test]
    fn display_with_mux_from_if() {
        // if-expressions are desugared to mux by the ProveIR compiler
        let ir = crate::prove_ir::test_utils::compile_circuit(
            "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
        )
        .unwrap();
        let output = format!("{ir}");
        assert!(output.contains("mux("), "got:\n{output}");
        assert!(output.contains("assert_eq("), "got:\n{output}");
    }

    // =====================================================================
    // Adversarial deserialization tests
    // =====================================================================

    #[test]
    fn adversarial_empty_bytes() {
        assert!(ProveIR::from_bytes(&[]).is_err());
    }

    #[test]
    fn adversarial_too_short() {
        assert!(ProveIR::from_bytes(b"ACH").is_err());
    }

    #[test]
    fn adversarial_wrong_magic() {
        assert!(ProveIR::from_bytes(b"EVIL\x01").is_err());
    }

    #[test]
    fn adversarial_wrong_version() {
        let mut bytes = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        }
        .to_bytes(PrimeId::Bn254)
        .unwrap();
        bytes[4] = 99; // corrupt version byte
        let err = ProveIR::from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("version"),
            "error should mention version: {err}"
        );
    }

    #[test]
    fn adversarial_truncated_payload() {
        let bytes = ProveIR {
            name: None,
            public_inputs: vec![ProveInputDecl {
                name: "x".into(),
                array_size: None,
                ir_type: IrType::Field,
            }],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        }
        .to_bytes(PrimeId::Bn254)
        .unwrap();
        // Truncate the payload
        let truncated = &bytes[..bytes.len() / 2];
        assert!(ProveIR::from_bytes(truncated).is_err());
    }

    #[test]
    fn adversarial_random_bytes() {
        // Version 99 is unsupported
        let garbage = b"ACHP\x63\xff\xff\xff\xff\xff\xff\xff\xff";
        assert!(ProveIR::from_bytes(garbage).is_err());
    }

    #[test]
    fn adversarial_invalid_field_const_rejected_at_instantiation() {
        // FieldConst stores raw bytes — any [u8;32] is valid at the
        // serialization layer. But values >= modulus are rejected when
        // instantiation calls to_field::<F>().
        use memory::field::MODULUS;

        // Build bytes >= BN254 modulus
        let mut bad_bytes = [0u8; 32];
        for (i, limb) in MODULUS.iter().enumerate() {
            bad_bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        let bad_const = FieldConst(bad_bytes);

        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Let {
                name: "x".into(),
                value: CircuitExpr::Const(bad_const),
                span: None,
            }],
            capture_arrays: vec![],
        };

        // Serialization + deserialization succeeds (FieldConst is just bytes)
        let bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
        let (restored, _) = ProveIR::from_bytes(&bytes).unwrap();

        // But instantiation fails because the bytes are >= BN254 modulus
        let result = restored.instantiate::<Bn254Fr>(&std::collections::HashMap::new());
        assert!(
            result.is_err(),
            "instantiation should reject FieldConst >= modulus"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("invalid") || err.contains("field"),
            "error should mention invalid field constant: {err}"
        );
    }

    // F4: PoseidonMany with < 2 args rejected after deserialization
    #[test]
    fn adversarial_poseidon_many_empty_rejected() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Expr {
                expr: CircuitExpr::PoseidonMany(vec![]),
                span: None,
            }],
            capture_arrays: vec![],
        };
        // Serialize directly with bincode (bypass to_bytes header)
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACHP");
        bytes.push(PROVE_IR_FORMAT_VERSION);
        bytes.push(PrimeId::Bn254.to_byte());
        bytes.extend_from_slice(&payload);
        let err = ProveIR::from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("poseidon_many"),
            "should reject poseidon_many with 0 args: {err}"
        );
    }

    // F5: RangeCheck with invalid bits rejected
    #[test]
    fn adversarial_range_check_zero_bits_rejected() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Expr {
                expr: CircuitExpr::RangeCheck {
                    value: Box::new(CircuitExpr::Const(FieldConst::from_u64(0))),
                    bits: 0,
                },
                span: None,
            }],
            capture_arrays: vec![],
        };
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACHP");
        bytes.push(PROVE_IR_FORMAT_VERSION);
        bytes.push(PrimeId::Bn254.to_byte());
        bytes.extend_from_slice(&payload);
        let err = ProveIR::from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("range_check"),
            "should reject range_check bits=0: {err}"
        );
    }

    #[test]
    fn adversarial_range_check_oversized_bits_rejected() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Expr {
                expr: CircuitExpr::RangeCheck {
                    value: Box::new(CircuitExpr::Const(FieldConst::from_u64(0))),
                    bits: 300,
                },
                span: None,
            }],
            capture_arrays: vec![],
        };
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACHP");
        bytes.push(PROVE_IR_FORMAT_VERSION);
        bytes.push(PrimeId::Bn254.to_byte());
        bytes.extend_from_slice(&payload);
        let err = ProveIR::from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("range_check"),
            "should reject range_check bits=300: {err}"
        );
    }

    // =====================================================================
    // v4 format / multi-prime tests
    // =====================================================================

    #[test]
    fn v3_and_v4_rejected_with_recompile_message() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        };
        // v3 blob (no prime byte)
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes_v3 = Vec::new();
        bytes_v3.extend_from_slice(b"ACHP");
        bytes_v3.push(3);
        bytes_v3.extend_from_slice(&payload);
        let err = ProveIR::from_bytes(&bytes_v3).unwrap_err();
        assert!(
            err.contains("no longer supported") && err.contains("recompile"),
            "v3 error should mention recompile: {err}"
        );

        // v4 blob (has prime byte, but old serialization format)
        let mut bytes_v4 = Vec::new();
        bytes_v4.extend_from_slice(b"ACHP");
        bytes_v4.push(4);
        bytes_v4.push(PrimeId::Bn254.to_byte());
        bytes_v4.extend_from_slice(&payload);
        let err = ProveIR::from_bytes(&bytes_v4).unwrap_err();
        assert!(
            err.contains("no longer supported") && err.contains("recompile"),
            "v4 error should mention recompile: {err}"
        );
    }

    #[test]
    fn v4_roundtrip_with_each_prime() {
        let ir = ProveIR {
            name: Some("test".into()),
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        };
        for prime in [PrimeId::Bn254, PrimeId::Bls12_381, PrimeId::Goldilocks] {
            let bytes = ir.to_bytes(prime).unwrap();
            let (restored, restored_prime) = ProveIR::from_bytes(&bytes).unwrap();
            assert_eq!(restored_prime, prime, "prime mismatch for {}", prime.name());
            assert_eq!(restored.name, ir.name);
        }
    }

    #[test]
    fn v4_bad_prime_byte_rejected() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
            capture_arrays: vec![],
        };
        let mut bytes = ir.to_bytes(PrimeId::Bn254).unwrap();
        bytes[5] = 0xFF; // invalid prime byte
        let err = ProveIR::from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("PrimeId"),
            "error should mention PrimeId: {err}"
        );
    }

    // D4: ArraySize::Capture referencing unknown capture is rejected
    #[test]
    fn adversarial_array_size_unknown_capture_rejected() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![ProveInputDecl {
                name: "arr".into(),
                array_size: Some(ArraySize::Capture("ghost".into())),
                ir_type: IrType::Field,
            }],
            witness_inputs: vec![],
            captures: vec![], // no capture named "ghost"
            body: vec![],
            capture_arrays: vec![],
        };
        let err = ir.validate().unwrap_err();
        assert!(
            err.contains("ghost"),
            "should mention unknown capture: {err}"
        );
    }

    // D5: ForRange::WithCapture referencing unknown capture is rejected
    #[test]
    fn adversarial_for_range_unknown_capture_rejected() {
        let ir = ProveIR {
            name: None,
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![], // no capture named "missing"
            body: vec![CircuitNode::For {
                var: "i".into(),
                range: ForRange::WithCapture {
                    start: 0,
                    end_capture: "missing".into(),
                },
                body: vec![],
                span: None,
            }],
            capture_arrays: vec![],
        };
        let err = ir.validate().unwrap_err();
        assert!(
            err.contains("missing"),
            "should mention unknown capture: {err}"
        );
    }

    // =====================================================================
    // FieldConst::from_decimal_str / from_hex_str tests
    // =====================================================================

    #[test]
    fn field_const_from_decimal_small() {
        let fc = FieldConst::from_decimal_str("42").unwrap();
        assert_eq!(fc, FieldConst::from_u64(42));
    }

    #[test]
    fn field_const_from_decimal_zero() {
        let fc = FieldConst::from_decimal_str("0").unwrap();
        assert_eq!(fc, FieldConst::zero());
    }

    #[test]
    fn field_const_from_decimal_large() {
        // BN254 field order - 1 (a ~77 digit number)
        let s = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
        let fc = FieldConst::from_decimal_str(s).unwrap();
        // Should not be zero and should not fit in u64
        assert!(!fc.is_zero());
        assert!(fc.to_u64().is_none());
    }

    #[test]
    fn field_const_from_decimal_max_u64() {
        let fc = FieldConst::from_decimal_str("18446744073709551615").unwrap();
        assert_eq!(fc, FieldConst::from_u64(u64::MAX));
    }

    #[test]
    fn field_const_from_decimal_just_above_u64() {
        let fc = FieldConst::from_decimal_str("18446744073709551616").unwrap();
        assert!(fc.to_u64().is_none());
        // Verify byte 8 is 1 (2^64 = 1 in byte[8])
        assert_eq!(fc.bytes()[8], 1);
    }

    #[test]
    fn field_const_from_decimal_invalid() {
        assert!(FieldConst::from_decimal_str("").is_none());
        assert!(FieldConst::from_decimal_str("abc").is_none());
        assert!(FieldConst::from_decimal_str("12x3").is_none());
    }

    #[test]
    fn field_const_from_hex_small() {
        let fc = FieldConst::from_hex_str("0xFF").unwrap();
        assert_eq!(fc, FieldConst::from_u64(255));
    }

    #[test]
    fn field_const_from_hex_no_prefix() {
        let fc = FieldConst::from_hex_str("ff").unwrap();
        assert_eq!(fc, FieldConst::from_u64(255));
    }

    #[test]
    fn field_const_from_hex_large() {
        // 64 hex digits = 32 bytes (max)
        let hex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
        let fc = FieldConst::from_hex_str(hex).unwrap();
        assert!(!fc.is_zero());
        assert!(fc.to_u64().is_none());
    }

    #[test]
    fn field_const_from_hex_with_0x_prefix() {
        let fc = FieldConst::from_hex_str("0x1234").unwrap();
        assert_eq!(fc, FieldConst::from_u64(0x1234));
    }

    #[test]
    fn field_const_from_hex_invalid() {
        assert!(FieldConst::from_hex_str("").is_none());
        assert!(FieldConst::from_hex_str("0x").is_none());
        assert!(FieldConst::from_hex_str("0xGG").is_none());
        // 65 hex digits = too large
        let too_large = "1".to_string() + &"0".repeat(64);
        assert!(FieldConst::from_hex_str(&too_large).is_none());
    }
}
