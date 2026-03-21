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

pub mod error;
pub mod types;

pub use error::ProveIrError;
pub use types::*;
