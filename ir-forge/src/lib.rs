//! # `ir-forge` — Circuit IR front-half
//!
//! This crate holds the ProveIR layer and its lowering/interop
//! infrastructure, extracted from `ir/src/prove_ir/` during the
//! structural cleanup phase 7 (see
//! `.claude/plans/structural-cleanup.md` §9.bis).
//!
//! The extraction is performed in 11 incremental sub-stages on the
//! `feat/ir-forge-crate` branch; this scaffold is sub-stage 0. Each
//! subsequent sub-stage moves one leaf of the `ir::prove_ir::**`
//! subtree into this crate, topologically bottom-up, updating external
//! call-sites in the same commit (no shims, because `ir-forge → ir`
//! would form a Cargo cycle with any shim `ir → ir-forge`).
//!
//! ## Target layout (post sub-stage 10)
//!
//! - `error` — `ProveIrError`
//! - `lysis_bridge` — `InstructionKind<F> ↔ Instruction<F>` conversions
//! - `extended` — `ExtendedInstruction<F>`, `ExtendedIrProgram<F>`, `TemplateId`
//! - `lysis_materialize` — `NodeInterner<F> → Vec<Instruction<F>>` flattener
//! - `types` — ProveIR AST (`CircuitExpr`, `CircuitNode`, `ProveIR`, …)
//! - `capture`, `circom_interop` — capture defs + circom dispatch types
//! - `instantiate` — eager instantiation (slated for deletion in Lysis Phase 5)
//! - `ast_lower` — `ProveIrCompiler` + outer scope (was `ir::prove_ir::compiler`)
//! - `lysis_lift` — Walker + BTA + diff + extract + symbolic (was `ir::prove_ir::lysis_lower`)

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
pub use lysis_bridge::{instruction_from_kind, ssa_var_from_node_id};
pub use lysis_materialize::{materialize_interner, materialize_interning_sink};
pub use types::{
    ArraySize, CaptureArrayDef, CaptureDef, CaptureUsage, CircuitBinOp, CircuitBoolOp,
    CircuitCmpOp, CircuitExpr, CircuitNode, CircuitUnaryOp, FieldConst, ForRange, ProveIR,
    ProveInputDecl,
};
