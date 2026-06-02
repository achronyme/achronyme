//! Expression-level emission on [`Instantiator`].
//!
//! [`emit::emit_expr`] dispatches each [`CircuitExpr`] variant into its SSA
//! program form. The branch bodies live in focused sibling modules:
//!
//! - [`helpers`] — env lookup and exponentiation helpers.
//! - [`ops`] — scalar arithmetic, boolean, comparison, mux, and integer ops.
//! - [`crypto`] — Poseidon, range-check, and Merkle helpers.
//! - [`arrays`] — const and symbolic array indexing.
//! - [`bitwise`] — bitwise and shift dispatch into [`super::bits`].

mod arrays;
mod bitwise;
mod crypto;
mod emit;
mod helpers;
mod ops;
