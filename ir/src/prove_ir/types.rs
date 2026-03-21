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
use bincode::Options;
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

/// Magic header bytes for serialized ProveIR.
const PROVE_IR_MAGIC: &[u8; 4] = b"ACHP";

/// Format version (increment when enum variants change or fields are added).
const PROVE_IR_FORMAT_VERSION: u8 = 1;

/// Maximum allowed size for deserialized ProveIR data (64 MB).
/// Prevents allocation bombs from crafted length prefixes.
const PROVE_IR_MAX_SIZE: u64 = 64 * 1024 * 1024;

impl ProveIR {
    /// Serialize to bytes with magic header and version (for .achb bytecode files).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let payload =
            bincode::serialize(self).map_err(|e| format!("ProveIR serialization failed: {e}"))?;
        let mut out = Vec::with_capacity(5 + payload.len());
        out.extend_from_slice(PROVE_IR_MAGIC);
        out.push(PROVE_IR_FORMAT_VERSION);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Validate structural invariants that the compiler guarantees but
    /// could be violated by crafted bytes.
    pub fn validate(&self) -> Result<(), String> {
        for node in &self.body {
            validate_node(node)?;
        }
        Ok(())
    }

    /// Deserialize from bytes, validating magic header, version, and invariants.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
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
        if bytes[4] != PROVE_IR_FORMAT_VERSION {
            return Err(format!(
                "unsupported ProveIR format version: expected {}, got {}",
                PROVE_IR_FORMAT_VERSION, bytes[4]
            ));
        }
        let payload = &bytes[5..];
        let prove_ir: Self = bincode::options()
            .with_limit(PROVE_IR_MAX_SIZE)
            .with_fixint_encoding()
            .allow_trailing_bytes() // payload may be embedded in a larger buffer
            .deserialize(payload)
            .map_err(|e| format!("ProveIR deserialization failed: {e}"))?;
        prove_ir.validate()?;
        Ok(prove_ir)
    }
}

/// Maximum allowed bits for RangeCheck (BN254 field is ~254 bits).
const MAX_RANGE_CHECK_BITS: u32 = 253;

fn validate_node(node: &CircuitNode) -> Result<(), String> {
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
        CircuitNode::For { body, .. } => {
            for n in body {
                validate_node(n)?;
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
                validate_node(n)?;
            }
            for n in else_body {
                validate_node(n)?;
            }
            Ok(())
        }
        CircuitNode::Expr { expr, .. } => validate_expr(expr),
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
        // 5 bytes header (ACHP + version) + 32 bytes payload (4 empty vecs)
        assert_eq!(ir.to_bytes().unwrap().len(), 37);
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
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
        }
        .to_bytes()
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
            public_inputs: vec![ProveInputDecl {
                name: "x".into(),
                array_size: None,
                ir_type: IrType::Field,
            }],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![],
        }
        .to_bytes()
        .unwrap();
        // Truncate the payload
        let truncated = &bytes[..bytes.len() / 2];
        assert!(ProveIR::from_bytes(truncated).is_err());
    }

    #[test]
    fn adversarial_random_bytes() {
        let garbage = b"ACHP\x01\xff\xff\xff\xff\xff\xff\xff\xff";
        assert!(ProveIR::from_bytes(garbage).is_err());
    }

    #[test]
    fn adversarial_invalid_field_element() {
        // Craft bytes with FieldElement limbs >= MODULUS
        use memory::field::MODULUS;

        let ir = ProveIR {
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Let {
                name: "x".into(),
                value: CircuitExpr::Const(FieldElement::ONE),
                span: None,
            }],
        };
        let mut bytes = ir.to_bytes().unwrap();

        // Find the FieldElement in the serialized bytes and corrupt it.
        // The ONE constant has specific limbs — replace them with MODULUS.
        // The FieldElement is serialized as [u64;4] = 32 bytes.
        // Search for the ONE limbs and replace with MODULUS.
        let one_bytes = bincode::serialize(&FieldElement::ONE).unwrap();

        let modulus_bytes: Vec<u8> = MODULUS.iter().flat_map(|l| l.to_le_bytes()).collect();
        let one_bytes_len = one_bytes.len();

        // Find the ONE pattern in serialized bytes
        if let Some(pos) = bytes
            .windows(one_bytes_len)
            .position(|w| w == one_bytes.as_slice())
        {
            bytes[pos..pos + one_bytes_len].copy_from_slice(&modulus_bytes);
            let err = ProveIR::from_bytes(&bytes).unwrap_err();
            assert!(
                err.contains("modulus") || err.contains("FieldElement"),
                "error should mention modulus/FieldElement: {err}"
            );
        } else {
            panic!("could not find ONE limbs in serialized bytes");
        }
    }

    // F4: PoseidonMany with < 2 args rejected after deserialization
    #[test]
    fn adversarial_poseidon_many_empty_rejected() {
        let ir = ProveIR {
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Expr {
                expr: CircuitExpr::PoseidonMany(vec![]),
                span: None,
            }],
        };
        // Serialize directly with bincode (bypass to_bytes header)
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACHP");
        bytes.push(1);
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
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Expr {
                expr: CircuitExpr::RangeCheck {
                    value: Box::new(CircuitExpr::Const(FieldElement::ZERO)),
                    bits: 0,
                },
                span: None,
            }],
        };
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACHP");
        bytes.push(1);
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
            public_inputs: vec![],
            witness_inputs: vec![],
            captures: vec![],
            body: vec![CircuitNode::Expr {
                expr: CircuitExpr::RangeCheck {
                    value: Box::new(CircuitExpr::Const(FieldElement::ZERO)),
                    bits: 300,
                },
                span: None,
            }],
        };
        let payload = bincode::serialize(&ir).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ACHP");
        bytes.push(1);
        bytes.extend_from_slice(&payload);
        let err = ProveIR::from_bytes(&bytes).unwrap_err();
        assert!(
            err.contains("range_check"),
            "should reject range_check bits=300: {err}"
        );
    }
}
