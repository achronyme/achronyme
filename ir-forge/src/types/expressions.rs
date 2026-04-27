//! Expression tree for ProveIR + the four circuit-level operator enums.
//!
//! `CircuitExpr` is the universal expression node. The operator enums
//! (`CircuitBinOp`, `CircuitUnaryOp`, `CircuitCmpOp`, `CircuitBoolOp`)
//! are kept separate from the AST's parser-level operators so that
//! circuit-only constraints (no modulus/power) are encoded directly in
//! the type.

use serde::{Deserialize, Serialize};

use super::FieldConst;

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

    /// For-loop induction-variable placeholder used by R1″ body
    /// memoization. Token IDs are minted per active loop nesting.
    /// Substituted with `Const(value)` by `substitute_loop_var` when
    /// replaying a memoized iter-0 body for iters 1..end. Must NOT be
    /// const-folded (`try_fold_const` returns None) and must NOT
    /// survive past `lower_for_loop` — instantiate-time encountering
    /// `LoopVar` is a bug.
    LoopVar(u32),

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
