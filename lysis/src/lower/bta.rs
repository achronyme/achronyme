//! Binding-time analysis — classifies each `For` as
//! static / uniform / parametric / data-dependent.
//!
//! Phase 3 deliverable. The 3-point evaluation algorithm lives here
//! (RFC §6.1 + §6.1.1 edge cases for periodicity and single-iteration
//! loops).
