//! # `ir-forge` — Circuit IR front-half
//!
//! This crate holds the ProveIR layer and its lowering / interop
//! infrastructure.
//!
//! ## Layout
//!
//! - `error` — `ProveIrError`
//! - `lysis_bridge` — `InstructionKind<F>` and `Instruction<F>` conversions
//! - `extended` — `ExtendedInstruction<F>`, `ExtendedIrProgram<F>`, `TemplateId`
//! - `lysis_materialize` — `NodeInterner<F>` to `Vec<Instruction<F>>` flattener
//! - `types` — ProveIR AST (`CircuitExpr`, `CircuitNode`, `ProveIR`, ...)
//! - `capture`, `circom_interop` — capture defs and circom dispatch types
//! - `instantiate` — eager instantiation (slated for deletion once
//!   the Lysis pipeline is the only consumer)
//! - `ast_lower` — `ProveIrCompiler` and outer scope (was `ir::prove_ir::compiler`)
//! - `lysis_lift` — Walker, BTA, diff, extract, symbolic (was `ir::prove_ir::lysis_lower`)

pub mod ast_lower;
pub mod capture;
pub mod circom_interop;
pub mod error;
pub mod extended;
pub mod extended_program;
pub mod instantiate;
pub mod lysis_bridge;
pub mod lysis_lift;
pub mod lysis_materialize;
pub mod lysis_roundtrip;
pub mod module_loader;
pub mod resolver_adapter;
pub mod suggest;
pub mod types;

#[cfg(any(test, feature = "test-support"))]
pub mod test_utils;

pub use ast_lower::{OuterResolverState, OuterScope, OuterScopeEntry, ProveIrCompiler};
pub use circom_interop::{
    CircomCallable, CircomDispatchError, CircomInputLayout, CircomInstantiation,
    CircomLibraryHandle, CircomTemplateOutput, CircomTemplateSignature,
};
pub use error::{CircomDispatchErrorKind, ProveIrError};
pub use extended::{ExtendedInstruction, TemplateId};
pub use extended_program::ExtendedIrProgram;
pub use instantiate::LysisInstantiateError;
pub use lysis_bridge::{instruction_from_kind, ssa_var_from_node_id};
pub use lysis_materialize::{materialize_interner, materialize_interning_sink};
pub use lysis_roundtrip::{lysis_roundtrip, RoundTripError};
pub use types::{
    ArraySize, CaptureArrayDef, CaptureDef, CaptureUsage, CircuitBinOp, CircuitBoolOp,
    CircuitCmpOp, CircuitExpr, CircuitNode, CircuitUnaryOp, FieldConst, ForRange, ProveIR,
    ProveInputDecl,
};
