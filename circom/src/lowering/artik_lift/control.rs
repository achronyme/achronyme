//! Lowering for structured control-flow constructs.
//!
//! This module handles `for`, `while`, and `if` statements in Circom by
//! selecting between three lowering strategies:
//!
//! * compile-time loop unrolling when bounds are constants,
//! * runtime branching when the target builder supports it,
//! * arithmetic multiplexing for mux-compatible assignments.
//!
//! The lowering code lives on [`LiftState`] because it needs access to both the
//! source AST context and the Artik builder state.

#[allow(unused_imports)]
use super::LiftState;

mod branching;
mod folded_mux;
mod loops;
mod predicates;
