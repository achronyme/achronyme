//! Statement-level nodes for a ProveIR circuit body.
//!
//! `CircuitNode` is the top of the statement tree; `ForRange` enumerates
//! the shapes a for-loop bound can take (literal, captured scalar,
//! computed expression, or named array).

use diagnostics::SpanRange;
use serde::{Deserialize, Serialize};

use super::CircuitExpr;

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
    /// Deferred witness-calculator call. The `program_bytes` field
    /// carries an Artik bytecode payload; at prove time the
    /// `input_signals` are resolved, handed to the Artik executor,
    /// and the executor's witness slots are bound to the names in
    /// `output_bindings` (one local per output signal the function
    /// returns).
    ///
    /// Emitted by the circom Fase 2 lifting pass for function bodies
    /// that cannot be circuit-inlined (local variables, loops,
    /// multi-statement computations). The bytecode is opaque to
    /// ProveIR itself — the instantiation pass carries the payload
    /// through untouched, and the runtime hook in Fase 4 dispatches
    /// it via the Artik executor.
    WitnessCall {
        /// Bindings for each output slot the Artik program writes to.
        /// The caller may reference these names in later constraints.
        output_bindings: Vec<String>,
        /// Signal values to hand to Artik as inputs. Order matches
        /// the program's `ReadSignal` order.
        input_signals: Vec<CircuitExpr>,
        /// Serialized Artik program (header + const pool + body).
        /// Opaque at this layer — decoded by the runtime handler.
        program_bytes: Vec<u8>,
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
            | CircuitNode::WitnessHintIndexed { span, .. }
            | CircuitNode::WitnessCall { span, .. } => span.as_ref(),
        }
    }
}

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
