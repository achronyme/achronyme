//! Witness computation for Circom `<--` hint expressions.
//!
//! Evaluates hint expressions off-circuit using concrete field values
//! to produce witness assignments. This is the Circom equivalent of
//! a witness calculator — it runs the prover-side computation that
//! determines signal values without generating any constraints.
//!
//! Bitwise operations (`>>`, `<<`, `&`, `|`, `^`, `~`) are evaluated
//! using integer arithmetic on the canonical field representation.
//!
//! # Two implementations, one semantics
//!
//! The production entry points run the slot-addressed template replay
//! (`replay` module); the recursive interpreter behind
//! [`compute_witness_hints_reference`] is the SPEC, and the
//! differential tests in `tests_replay` assert map equality. That
//! guarantee is only as strong as the corpus: **any change to hint
//! semantics — a new `CircuitNode` or `CircuitExpr` form, a new range
//! shape, a change to skip/overwrite/scoping rules — must land in BOTH
//! interpreters and add a differential case that exercises it.** A
//! semantics change made only in the reference (or only in the replay)
//! that the corpus does not exercise will keep the gate green while
//! production diverges.

mod compute;
mod error;
mod eval;
mod limbs;
pub mod profile;
mod replay;
mod replay_eval;
mod slot_env;
mod template;

pub use compute::{
    compute_witness_hints, compute_witness_hints_reference, compute_witness_hints_with_captures,
    compute_witness_hints_with_captures_memo,
};
pub use error::WitnessError;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_replay;
