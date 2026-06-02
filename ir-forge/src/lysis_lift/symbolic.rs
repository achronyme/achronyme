//! Symbolic emission for BTA.
//!
//! Walks a body once with a specific `loop_var → concrete_value`
//! binding and produces a flat linear-tree ([`SymbolicTree`]) whose
//! `Const` nodes carry a `from_slot` flag when the constant was
//! injected through the binding rather than appearing literally in
//! the source. The BTA classifier calls this twice (actually three
//! times under the v1.1 algorithm) with different probe values and
//! then runs [`super::diff::structural_diff`] to check whether the
//! bodies differ only in slot positions.
//!
//! ## What "symbolic" means here
//!
//! Not a CAS. The tree is straight-line — it mirrors the emission
//! order of the input body, with SsaVar references resolved to
//! earlier tree nodes. No interning, no constant folding, no algebraic
//! rewriting. The only "symbolic" aspect is that constants derived
//! from the loop binding are tagged so that structural_diff can
//! distinguish them from authentic literals.
//!
//! ## Outer refs vs captures
//!
//! SsaVars referenced in the body but defined outside it (and not in
//! `bindings`) land as [`SymbolicNode::OuterRef`]. These stay stable
//! across the probe walks because the caller's scope is fixed. The
//! lifter later converts them to capture slots once BTA has
//! classified the loop as `Uniform`; that step is in `extract.rs`,
//! not here.

mod emit;
mod plain;
#[cfg(test)]
mod tests;
mod types;

pub use emit::symbolic_emit;
pub use types::{NodeIdx, OpTag, SlotId, SymbolicNode, SymbolicTree};
