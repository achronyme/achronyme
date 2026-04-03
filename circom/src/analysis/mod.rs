//! Semantic analysis passes for Circom AST.
//!
//! - Constraint pairing: ensures every `<--` has a corresponding `===`.
//! - Include resolution: resolves `include` directives.
