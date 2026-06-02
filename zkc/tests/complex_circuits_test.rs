//! Complex integration tests for Achronyme circuits.
//!
//! Covers large Merkle trees, nullifier/commitment patterns, hash chains,
//! function chaining, boolean logic chains, nested loops, and negative tests.

#[path = "complex_circuits_test/booleans.rs"]
mod booleans;
#[path = "complex_circuits_test/functions.rs"]
mod functions;
#[path = "complex_circuits_test/helpers.rs"]
mod helpers;
#[path = "complex_circuits_test/loops_large.rs"]
mod loops_large;
#[path = "complex_circuits_test/merkle.rs"]
mod merkle;
#[path = "complex_circuits_test/negative.rs"]
mod negative;
#[path = "complex_circuits_test/patterns.rs"]
mod patterns;
