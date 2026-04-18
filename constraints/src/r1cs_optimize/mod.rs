//! R1CS constraint optimization — two-pass pipeline that mirrors
//! circom's `--O1` and `--O2` simplification stages.
//!
//! ## Public API
//!
//! - [`optimize_linear`] — O1: linear constraint elimination to
//!   fixpoint + dedup + trivial sweep.
//! - [`optimize_o2`] — O2: O1 followed by decompose + DEDUCE
//!   (Gaussian elimination on a quadratic-monomial matrix) +
//!   protected O1 + cleanup O1, repeated until convergence.
//! - [`R1CSOptimizeResult`] + [`SubstitutionMap`] — shared result
//!   type + substitution map consumed by the compiler's R1CS
//!   backend + witness generator.
//!
//! ## File layout
//!
//! - [`types`] — `R1CSOptimizeResult` struct + `SubstitutionMap`
//!   alias.
//! - [`predicates`] — side-effect-free shape queries: `is_linear`,
//!   `is_trivially_satisfied`, `compute_variable_frequency`,
//!   `lc_fingerprint`.
//! - [`substitution`] — substitution primitives: `apply_substitution`,
//!   `apply_substitution_to_constraint`, `solve_for_variable`.
//! - [`linear`] — O1 pass (`optimize_linear`,
//!   `optimize_linear_with_protected`, `deduplicate_constraints`).
//! - [`deduce`] — O2 pass (`expand_constraint_product`,
//!   `deduce_linear_from_quadratic`, `decompose_for_deduce_tracked`,
//!   `optimize_o2`).
//! - [`tests`] — integration tests that round-trip constraints
//!   through each pass and verify witness satisfaction.

mod deduce;
mod linear;
mod predicates;
mod substitution;
mod types;

pub use deduce::optimize_o2;
pub use linear::optimize_linear;
pub use types::{R1CSOptimizeResult, SubstitutionMap};

#[cfg(test)]
mod tests;
