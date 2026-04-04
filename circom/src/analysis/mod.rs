//! Semantic analysis passes for Circom AST.
//!
//! - Constraint pairing: ensures every `<--` has a corresponding `===`.
//! - Include resolution: resolves `include` directives.

pub mod constraint_check;
pub mod include_resolver;
