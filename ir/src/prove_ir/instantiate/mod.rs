//! ProveIR instantiation: ProveIR template + capture values → IrProgram (flat IR SSA).
//!
//! This is Phase B of the ProveIR pipeline. Given a pre-compiled circuit template
//! and concrete values for all captured variables, it produces an `IrProgram`
//! compatible with the existing optimize → R1CS/Plonkish pipeline.
//!
//! Key operations:
//! - Resolve captures to constants or witness inputs
//! - Unroll for loops (bounds are now concrete)
//! - Expand array declarations (sizes are now concrete)
//! - Flatten the CircuitNode/CircuitExpr tree into a flat `Vec<Instruction>`
//!
//! ## Submodules
//!
//! - [`api`] — public entry points `ProveIR::instantiate` /
//!   `ProveIR::instantiate_with_outputs` (Circom-frontend variant).
//! - [`scaffold`] — setup methods (capture validation, input/capture
//!   declaration, array-size resolution, span-aware emission).
//! - [`stmts`] — `CircuitNode` walker (`emit_node` / `emit_for` / range
//!   loops) plus the compile-time const evaluator (`eval_const_expr`).
//! - [`exprs`] — `CircuitExpr` walker (`emit_expr` — the big match) +
//!   `resolve_scalar` + `emit_pow`.
//! - [`bits`] — bitwise expansion (decompose / recompose / shifts /
//!   bitwise binops) and the indexing utilities `extract_const_index`
//!   / `ensure_array_slot` / `extract_const_u32` / `resolve_const_u32`.
//! - [`utils`] — free helpers: `fe_to_u64` / `fe_to_usize`.
//! - [`tests`] — test suite (only compiled under `#[cfg(test)]`).

mod api;
mod bits;
mod exprs;
mod scaffold;
mod stmts;
mod utils;

use std::collections::HashMap;

use diagnostics::SpanRange;
use memory::{FieldBackend, FieldElement};

use crate::types::{IrProgram, SsaVar};

/// Maximum iterations allowed during instantiation (loop unrolling).
/// This mirrors `MAX_UNROLL_ITERATIONS` in IrLowering but applies to capture-bound
/// loops that are only resolved at instantiation time.
pub(super) const MAX_INSTANTIATE_ITERATIONS: u64 = 1_000_000;

/// Bitwise binary operation type (used internally by emit_bitwise_binop).
pub(super) enum BitwiseOp {
    And,
    Or,
    Xor,
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// A resolved value in the instantiation environment.
#[derive(Clone, Debug)]
pub(super) enum InstEnvValue {
    /// A scalar SSA variable.
    Scalar(SsaVar),
    /// An array of SSA variables (one per element).
    Array(Vec<SsaVar>),
}

// ---------------------------------------------------------------------------
// Instantiator
// ---------------------------------------------------------------------------

/// Converts a ProveIR template into a flat IrProgram given concrete capture values.
pub(super) struct Instantiator<F: FieldBackend> {
    pub(super) program: IrProgram<F>,
    pub(super) env: HashMap<String, InstEnvValue>,
    /// Concrete capture values (provided by caller).
    pub(super) captures: HashMap<String, FieldElement<F>>,
    /// Current source span context — set when entering a CircuitNode,
    /// propagated to all IR instructions emitted within that node.
    pub(super) current_span: Option<SpanRange>,
    /// Maps output signal element names → their public wire SSA vars.
    /// Non-empty only when instantiating Circom circuits with `signal output`.
    /// Used to intercept body nodes (WitnessHint, Let) that would create
    /// duplicate wires for output signals.
    pub(super) output_pub_vars: HashMap<String, SsaVar>,
}

#[cfg(test)]
mod tests;
