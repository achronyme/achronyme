//! ProveIR data types — a pre-compiled circuit template representation.
//!
//! ProveIR sits between the AST and IR SSA: validated, desugared, functions
//! inlined, but loops and conditionals are preserved (not unrolled/mux'd).
//! It is parametric on "captures" — values from the outer scope that are
//! resolved at instantiation time (Phase B).

use achronyme_parser::diagnostic::SpanRange;
use memory::FieldElement;

use crate::types::IrType;

// ---------------------------------------------------------------------------
// Top-level ProveIR
// ---------------------------------------------------------------------------

/// A pre-compiled circuit template, ready for instantiation.
#[derive(Debug, Clone, PartialEq)]
pub struct ProveIR {
    /// Variables the verifier knows (explicitly declared by user).
    pub public_inputs: Vec<ProveInputDecl>,
    /// Variables only the prover knows (auto-inferred or explicit).
    pub witness_inputs: Vec<ProveInputDecl>,
    /// Template parameters — values from outer scope that affect circuit
    /// structure or constraints.
    pub captures: Vec<CaptureDef>,
    /// The circuit body — validated, desugared, functions inlined.
    pub body: Vec<CircuitNode>,
}

/// An input declaration (public or witness).
#[derive(Debug, Clone, PartialEq)]
pub struct ProveInputDecl {
    pub name: String,
    pub array_size: Option<ArraySize>,
    pub ir_type: IrType,
}

/// Array size: either a compile-time literal or a captured value.
#[derive(Debug, Clone, PartialEq)]
pub enum ArraySize {
    Literal(usize),
    Capture(String),
}

/// A captured variable from the outer scope.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureDef {
    pub name: String,
    pub usage: CaptureUsage,
}

/// How a captured variable is used in the circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitNode {
    /// Immutable scalar binding: `let name = value`
    Let {
        name: String,
        value: CircuitExpr,
        span: Option<SpanRange>,
    },
    /// Array binding: `let name = [e0, e1, ...]`
    LetArray {
        name: String,
        elements: Vec<CircuitExpr>,
        span: Option<SpanRange>,
    },
    /// Equality constraint: `assert_eq(lhs, rhs)`
    AssertEq {
        lhs: CircuitExpr,
        rhs: CircuitExpr,
        span: Option<SpanRange>,
    },
    /// Boolean constraint: `assert(expr)` — expr must be 1
    Assert {
        expr: CircuitExpr,
        span: Option<SpanRange>,
    },
    /// For loop (preserved, unrolled during instantiation)
    For {
        var: String,
        range: ForRange,
        body: Vec<CircuitNode>,
        span: Option<SpanRange>,
    },
    /// Conditional (preserved, converted to Mux during instantiation)
    If {
        cond: CircuitExpr,
        then_body: Vec<CircuitNode>,
        else_body: Vec<CircuitNode>,
        span: Option<SpanRange>,
    },
    /// Bare expression (e.g., a builtin call with side effects)
    Expr {
        expr: CircuitExpr,
        span: Option<SpanRange>,
    },
}

// ---------------------------------------------------------------------------
// For loop range
// ---------------------------------------------------------------------------

/// Range of a for loop in ProveIR.
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitExpr {
    /// Compile-time constant field element.
    Const(FieldElement),
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
}

// ---------------------------------------------------------------------------
// Operator enums (separate from AST's BinOp to exclude Mod/Pow)
// ---------------------------------------------------------------------------

/// Arithmetic binary operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBinOp {
    Add,
    Sub,
    Mul,
    Div,
}

/// Unary operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitUnaryOp {
    Neg,
    Not,
}

/// Comparison operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitCmpOp {
    Eq,
    Neq,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Boolean operators available in circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBoolOp {
    And,
    Or,
}
