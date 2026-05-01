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
mod sink;
mod stmts;
mod utils;

use std::collections::HashMap;

use diagnostics::SpanRange;
use memory::{FieldBackend, FieldElement};

use ir_core::{IrType, SsaVar};

pub use api::LysisInstantiateError;
pub(super) use sink::{ExtendedSink, InstrSink};

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
///
/// Holds an `&'a mut`-borrowed [`InstrSink`] (boxed `dyn` to keep the
/// struct non-generic over sink type) so the same emission walk can
/// produce either flat `Vec<Instruction<F>>` (LegacySink) or
/// `Vec<ExtendedInstruction<F>>` (ExtendedSink) — see Phase 3.C.6
/// commit 2.1 for the trait definition and 2.2 for this wiring.
pub(super) struct Instantiator<'a, F: FieldBackend> {
    /// The emission target. Constructed by [`super::api`] and
    /// borrowed for the whole instantiation. Sink-internal state
    /// lives behind the `&mut`.
    pub(super) sink: Box<dyn InstrSink<F> + 'a>,
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
    /// Dedup cache for `Instruction::Const`. Maps the field value's
    /// canonical 32-byte representation to the SSA var of a previously
    /// emitted Const with that value. Repeated emissions of the same
    /// constant reuse the existing var, saving both a push and a
    /// `set_type` call per reuse. Populated exclusively via [`emit_const`].
    ///
    /// Stays on `Instantiator` (not the sink) because the peephole
    /// const-fold in `emit_expr` reads it synchronously between
    /// operand resolution and the next push — moving it onto the
    /// sink would force re-entrant `&mut self` borrow patterns.
    pub(super) const_cache: HashMap<[u8; 32], SsaVar>,
    /// Reverse lookup: SSA var → field value, for every var known to
    /// be a compile-time constant. Enables peephole const-fold in
    /// `emit_expr` for `BinOp`/`UnaryOp` (e.g., `Add(x, Const(0)) → x`,
    /// `Mul(Const, Const) → Const(fold)`). Populated alongside
    /// [`const_cache`] in [`emit_const`].
    pub(super) const_values: HashMap<SsaVar, FieldElement<F>>,
}

// ---------------------------------------------------------------------------
// Instantiator delegation helpers — thin pass-through to the sink so
// emission sites in {scaffold, exprs, stmts, bits}.rs read as
// `self.fresh_var()` etc. instead of `self.sink.fresh_var()`.
// ---------------------------------------------------------------------------

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn fresh_var(&mut self) -> SsaVar {
        self.sink.fresh_var()
    }

    pub(super) fn set_type(&mut self, var: SsaVar, ty: IrType) {
        self.sink.set_type(var, ty);
    }

    pub(super) fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.sink.get_type(var)
    }

    pub(super) fn set_name(&mut self, var: SsaVar, name: String) {
        self.sink.set_name(var, name);
    }

    // `set_input_span` and `next_var` are exposed on `InstrSink` for
    // future call sites (input registration in 2.4, canonicaliser in
    // 2.6) but not used by the current instantiation walk.
    #[allow(dead_code)]
    pub(super) fn set_input_span(&mut self, name: String, span: SpanRange) {
        self.sink.set_input_span(name, span);
    }

    #[allow(dead_code)]
    pub(super) fn next_var(&self) -> u32 {
        self.sink.next_var()
    }
}
