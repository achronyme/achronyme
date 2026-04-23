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

pub mod compiler;
pub mod lysis_lower;

pub use compiler::{OuterResolverState, OuterScope, OuterScopeEntry, ProveIrCompiler};
pub use ir_forge::types;
pub use ir_forge::{
    instruction_from_kind, materialize_interner, materialize_interning_sink, ssa_var_from_node_id,
    ArraySize, CaptureArrayDef, CaptureDef, CaptureUsage, CircomCallable, CircomDispatchError,
    CircomInputLayout, CircomInstantiation, CircomLibraryHandle, CircomTemplateOutput,
    CircomTemplateSignature, CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitNode,
    CircuitUnaryOp, ExtendedInstruction, ExtendedIrProgram, FieldConst, ForRange, ProveIR,
    ProveInputDecl, ProveIrError, TemplateId,
};

#[cfg(test)]
pub(crate) mod test_utils;

#[cfg(test)]
mod instantiate_tests;

#[cfg(test)]
mod types_tests;
