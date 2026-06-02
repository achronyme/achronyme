//! Statement-level emission on [`Instantiator`].
//!
//! These walk a [`CircuitNode`] tree and emit the corresponding flat IR
//! [`Instruction`]s. The big surface here is `emit_node` (the dispatch),
//! `emit_for` (loop unrolling against concrete capture-bound ranges),
//! and the two compile-time evaluators that resolve loop bounds and
//! array sizes. `with_saved_var` is the per-iteration env helper used
//! by both for-range and for-array unrolling.
//!
//! Expression emission lives in [`super::exprs`]; bit-level helpers
//! live in [`super::bits`].

mod const_eval;
mod dispatch;
mod indexed;
mod loops;
