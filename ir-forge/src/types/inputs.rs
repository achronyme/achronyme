//! Input declarations and capture descriptors for a ProveIR template.
//!
//! - [`ProveInputDecl`] — a single public or witness variable declaration.
//! - [`ArraySize`] — literal or capture-driven size for array inputs.
//! - [`CaptureDef`] / [`CaptureArrayDef`] / [`CaptureUsage`] — template
//!   parameters drawn from the outer scope, resolved at instantiation.

use ir_core::IrType;
use serde::{Deserialize, Serialize};

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
