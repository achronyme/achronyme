//! Lowering: `ExtendedInstruction<F>` → Lysis bytecode.
//!
//! Phase 3 deliverable. See RFC §3.3 for the pipeline and §6 for the
//! lowering algorithm (BTA + template extraction + bytecode emission).

pub mod bta;
pub mod env;
pub mod extract;
