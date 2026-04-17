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
//!
//! Submodules:
//! - [`prove_ir`] — top-level `ProveIR` container + serialize/validate.
//! - [`field_const`] — 256-bit field-erased constants.
//! - [`inputs`] — input declarations and capture descriptors.
//! - [`nodes`] — statement-level `CircuitNode` + `ForRange`.
//! - [`expressions`] — `CircuitExpr` tree + operator enums.
//! - [`display`] — human-readable `Display` impls (not re-exported).

pub mod display;
pub mod expressions;
pub mod field_const;
pub mod inputs;
pub mod nodes;
pub mod prove_ir;

pub use expressions::{CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitUnaryOp};
pub use field_const::FieldConst;
pub use inputs::{ArraySize, CaptureArrayDef, CaptureDef, CaptureUsage, ProveInputDecl};
pub use nodes::{CircuitNode, ForRange};
pub use prove_ir::ProveIR;

#[cfg(test)]
mod tests;
