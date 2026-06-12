//! Witness computation for Circom `<--` hint expressions.
//!
//! Evaluates hint expressions off-circuit using concrete field values
//! to produce witness assignments. This is the Circom equivalent of
//! a witness calculator — it runs the prover-side computation that
//! determines signal values without generating any constraints.
//!
//! Bitwise operations (`>>`, `<<`, `&`, `|`, `^`, `~`) are evaluated
//! using integer arithmetic on the canonical field representation.

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
