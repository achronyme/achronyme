//! ProveIR — pre-compiled circuit templates.
//!
//! This module provides the `ProveIR` intermediate representation that sits
//! between the AST and the SSA IR. It is the unified compilation target for
//! both `ach circuit` and `prove {}` blocks.
//!
//! Key properties:
//! - **Validated**: only circuit-safe constructs survive compilation
//! - **Desugared**: `mut` → SSA, `return` → last-expr, methods → primitives
//! - **Functions inlined**: no callable references remain
//! - **Loops preserved**: not unrolled (deferred to instantiation with concrete values)
//! - **Parametric**: captures from outer scope are "holes" filled at instantiation

pub mod capture;
pub mod circom_interop;
pub mod compiler;
pub mod error;
pub mod extended;
pub mod extended_program;
pub mod instantiate;
pub mod lysis_bridge;
pub mod lysis_lower;
pub mod lysis_materialize;
pub mod types;

pub use extended::{ExtendedInstruction, TemplateId};
pub use extended_program::ExtendedIrProgram;
pub use lysis_bridge::{instruction_from_kind, ssa_var_from_node_id};
pub use lysis_materialize::{materialize_interner, materialize_interning_sink};

/// Re-export of [`crate::passes::canonicalize_ssa`] kept for source
/// stability across the P5 cleanup move. Prefer the canonical path.
pub use crate::passes::canonicalize_ssa;

pub use circom_interop::{
    CircomCallable, CircomDispatchError, CircomInputLayout, CircomInstantiation,
    CircomLibraryHandle, CircomTemplateOutput, CircomTemplateSignature,
};
pub use compiler::{OuterResolverState, OuterScope, OuterScopeEntry, ProveIrCompiler};
pub use error::ProveIrError;
pub use types::{
    ArraySize, CaptureArrayDef, CaptureDef, CaptureUsage, CircuitBinOp, CircuitBoolOp,
    CircuitCmpOp, CircuitExpr, CircuitNode, CircuitUnaryOp, FieldConst, ForRange, ProveIR,
    ProveInputDecl,
};

#[cfg(test)]
pub(crate) mod test_utils;
