//! Top-level `ProveIR` container + serialize / validate / deserialize.
//!
//! `ProveIR` owns the declarative template (inputs, captures, body) and the
//! three entry points for the `.achb` format: [`to_bytes`](ProveIR::to_bytes),
//! [`from_bytes`](ProveIR::from_bytes), and [`validate`](ProveIR::validate).
//! The last two are also used as structural invariants over crafted input.

use bincode::Options;
use memory::field::PrimeId;
use serde::{Deserialize, Serialize};

use super::{
    ArraySize, CaptureArrayDef, CaptureDef, CircuitExpr, CircuitNode, ForRange, ProveInputDecl,
};

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
pub(crate) const PROVE_IR_MAGIC: &[u8; 4] = b"ACHP";

/// Format version (increment when enum variants change or fields are added).
/// v2: added `capture_arrays` field to ProveIR.
/// v3: added `message` field to CircuitNode::AssertEq.
/// v4: added PrimeId byte after version (multi-prime support).
/// v5: CircuitExpr::Const uses FieldConst ([u8;32] canonical LE) instead of FieldElement.
pub const PROVE_IR_FORMAT_VERSION: u8 = 5;

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
        CircuitNode::WitnessArrayDecl { size, .. } => {
            if let crate::types::ArraySize::Capture(name) = size {
                if !capture_names.contains(name.as_str()) {
                    return Err(format!(
                        "invalid ProveIR: WitnessArrayDecl size references unknown capture `{name}`"
                    ));
                }
            }
            Ok(())
        }
        CircuitNode::LetIndexed { index, value, .. } => {
            validate_expr(index)?;
            validate_expr(value)
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            validate_expr(index)?;
            validate_expr(hint)
        }
        CircuitNode::WitnessCall { input_signals, .. } => {
            for sig in input_signals {
                validate_expr(sig)?;
            }
            Ok(())
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
        // R1″ for-loop placeholder must not survive past lowering. If
        // a ProveIR blob containing LoopVar is being validated, the
        // for-loop unroller skipped substitution on a captured body.
        CircuitExpr::LoopVar(token) => Err(format!(
            "invalid ProveIR: CircuitExpr::LoopVar({token}) leaked into validation; \
             R1″ placeholder must be substituted during for-loop unroll"
        )),
    }
}
