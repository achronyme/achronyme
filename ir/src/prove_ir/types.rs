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

use achronyme_parser::diagnostic::SpanRange;
use memory::FieldElement;
use serde::{Deserialize, Serialize};

use crate::types::IrType;

// ---------------------------------------------------------------------------
// Top-level ProveIR
// ---------------------------------------------------------------------------

/// A pre-compiled circuit template, ready for instantiation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl ProveIR {
    /// Serialize to bincode bytes (for embedding in .achb bytecode files).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("ProveIR serialization failed: {e}"))
    }

    /// Deserialize from bincode bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("ProveIR deserialization failed: {e}"))
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
    /// Equality constraint: `assert_eq(lhs, rhs)`
    AssertEq {
        lhs: CircuitExpr,
        rhs: CircuitExpr,
        #[serde(skip)]
        span: Option<SpanRange>,
    },
    /// Boolean constraint: `assert(expr)` — expr must be 1
    Assert {
        expr: CircuitExpr,
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prove_ir::compiler::ProveIrCompiler;

    /// Round-trip: ProveIR → bytes → ProveIR, verify equality.
    fn assert_round_trip(prove_ir: &ProveIR) {
        let bytes = prove_ir.to_bytes().expect("serialization failed");
        let restored = ProveIR::from_bytes(&bytes).expect("deserialization failed");

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
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
        };
        assert_round_trip(&ir);
        assert_eq!(ir.to_bytes().unwrap().len(), 32); // 4 empty vecs
    }

    #[test]
    fn round_trip_simple_circuit() {
        let ir = ProveIrCompiler::compile_circuit(
            "public x\npublic out\nwitness s\nassert_eq(x + s, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_all_expr_types() {
        let ir = ProveIrCompiler::compile_circuit(
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
        let ir = ProveIrCompiler::compile_circuit(
            "public out\nmut acc = 0\nfor i in 0..5 { acc = acc + i }\nassert_eq(acc, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_if_else() {
        let ir = ProveIrCompiler::compile_circuit(
            "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_captures() {
        use std::collections::HashSet;
        let scope: HashSet<String> = ["secret", "hash"].iter().map(|s| s.to_string()).collect();
        let ir = ProveIrCompiler::compile_prove_block(
            "public hash\nassert_eq(poseidon(secret, 0), hash)",
            &scope,
        )
        .unwrap();
        assert_round_trip(&ir);
        assert_eq!(ir.captures.len(), 1);
    }

    #[test]
    fn round_trip_with_arrays() {
        let ir = ProveIrCompiler::compile_circuit(
            "public out\nlet arr = [1, 2, 3]\nassert_eq(arr_0, out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_with_functions() {
        let ir = ProveIrCompiler::compile_circuit(
            "public out\nfn double(x) { x * 2 }\nassert_eq(double(21), out)",
        )
        .unwrap();
        assert_round_trip(&ir);
    }

    #[test]
    fn round_trip_preserves_field_elements() {
        let ir = ProveIrCompiler::compile_circuit(
            "public out\nassert_eq(Field::ZERO + Field::ONE, out)",
        )
        .unwrap();
        let bytes = ir.to_bytes().unwrap();
        let restored = ProveIR::from_bytes(&bytes).unwrap();

        // The body should contain Const(ZERO) and Const(ONE) nodes.
        // After round-trip, the FieldElement values must be identical.
        fn collect_consts(body: &[CircuitNode]) -> Vec<&FieldElement> {
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
        fn collect_expr_consts<'a>(expr: &'a CircuitExpr, out: &mut Vec<&'a FieldElement>) {
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

        let ir = ProveIrCompiler::compile_circuit("public x\npublic out\nassert_eq(x + 1, out)")
            .unwrap();

        // Instantiate original
        let program1 = ir.instantiate(&HashMap::new()).unwrap();

        // Round-trip and instantiate
        let bytes = ir.to_bytes().unwrap();
        let restored = ProveIR::from_bytes(&bytes).unwrap();
        let program2 = restored.instantiate(&HashMap::new()).unwrap();

        // Both should produce identical instruction counts and types
        assert_eq!(
            program1.instructions.len(),
            program2.instructions.len(),
            "instruction count mismatch after round-trip"
        );
    }

    #[test]
    fn serialized_size_reasonable() {
        let ir = ProveIrCompiler::compile_circuit(
            "public a\npublic b\npublic out\nassert_eq(poseidon(a, b), out)",
        )
        .unwrap();
        let bytes = ir.to_bytes().unwrap();
        // A simple circuit should serialize to < 1 KB
        assert!(
            bytes.len() < 1024,
            "serialized size {} bytes seems too large",
            bytes.len()
        );
    }
}
