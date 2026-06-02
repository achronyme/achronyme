//! Binding-time analysis — the 3-point classifier (v1.1).
//!
//! Given a [`ExtendedInstruction::LoopUnroll`], decide whether its
//! body is safe to lift into a `TemplateBody` + `LoopRolled`
//! bytecode pair or whether it must stay inline as `LoopUnroll`.
//!
//! ## Why three probes instead of two
//!
//! The original two-probe test (evaluate at `start` and `start+1`,
//! compare) misses two patterns:
//!
//! 1. **Period-2 bodies** — `if i % 2 == 0 { a } else { b }` produces
//!    structurally different subtrees between `p0` and `p1`, so the
//!    two-probe test classifies them as `DataDependent`. Adding a
//!    third probe at `p0+2` catches this: `p0 ≡ p2 ∧ p0 ≢ p1` reveals
//!    periodicity. v1 still classifies these as `DataDependent`
//!    (safety-first); v2 could split into two templates.
//! 2. **Single-iteration loops** — `0..1` has exactly one iteration.
//!    The two-probe test evaluates at `start+1` (one past the end),
//!    reading garbage. The 3-point classifier short-circuits: any
//!    loop with ≤ 1 iteration returns `DataDependent` without
//!    probing.
//!
//! ## What the classifier does NOT do
//!
//! - It does not inline the body or mutate it.
//! - It does not intern any template; that's `extract.rs` (3.B.6).
//! - It does not handle `Parametric` bounds (loops whose end is a
//!   runtime capture). `ExtendedInstruction::LoopUnroll` carries
//!   `i64` bounds so every classifiable loop is already compile-
//!   time-bounded; `Parametric` is reserved for a future shape that
//!   carries `SsaVar` bounds.

use std::collections::BTreeSet;

use memory::{FieldBackend, FieldElement};

use super::diff::{structural_diff, Diff};
use super::symbolic::{symbolic_emit, SlotId, SymbolicTree};
use crate::ExtendedInstruction;
use ir_core::SsaVar;

/// Classification of a loop body. Consumed by the lifter (walker,
/// 3.B.7) to decide which Lysis opcode to emit.
#[derive(Debug, Clone)]
pub enum BindingTime<F: FieldBackend> {
    /// All probed iterations produce structurally identical bodies
    /// modulo the slot values at `captures`. Safe to lift into a
    /// `TemplateBody` whose `captures` become `LoadCapture` slots at
    /// call time.
    ///
    /// `skeleton` is the symbolic tree produced at probe 0 — the
    /// extractor reads it as the body shape and the slot positions
    /// as capture positions.
    Uniform {
        skeleton: SymbolicTree<F>,
        captures: BTreeSet<SlotId>,
    },
    /// The body varies structurally between iterations in a way the
    /// classifier will not attempt to lift. The walker emits a
    /// `LoopUnroll` bytecode opcode and inlines the body verbatim.
    DataDependent,
}

impl<F: FieldBackend> BindingTime<F> {
    /// `true` when the body is safe to lift into a template.
    pub fn is_uniform(&self) -> bool {
        matches!(self, BindingTime::Uniform { .. })
    }
}

/// Outcome reported by [`classify`] including the three probe-pair
/// diff results. Kept separate from [`BindingTime`] because future
/// callers may want to react to specific patterns (e.g. period-2)
/// that the current pass lumps as `DataDependent`.
#[derive(Debug, Clone)]
pub struct ClassificationDetails<F: FieldBackend> {
    pub binding_time: BindingTime<F>,
    pub diff_01: Diff,
    pub diff_02: Diff,
    pub diff_12: Diff,
}

/// Classify a loop by probing its body at three points and computing
/// pairwise structural diffs.
///
/// Provide `as_field(i)` to convert `i64` probe values into the
/// caller's field. The classifier never imposes a specific field
/// layout; it takes whatever concrete `FieldElement<F>` the caller
/// hands it.
pub fn classify<F: FieldBackend>(
    iter_var: SsaVar,
    body: &[ExtendedInstruction<F>],
    start: i64,
    end: i64,
    as_field: impl Fn(i64) -> FieldElement<F>,
) -> ClassificationDetails<F> {
    let iterations = end.saturating_sub(start);

    // Degenerate — fewer than two probes possible, or negative
    // range. Classify conservatively.
    if iterations <= 1 {
        return ClassificationDetails {
            binding_time: BindingTime::DataDependent,
            // Synthesize placeholder diffs; callers usually only
            // read `binding_time` in the early-exit path.
            diff_01: Diff::Structural,
            diff_02: Diff::Structural,
            diff_12: Diff::Structural,
        };
    }

    // Three probe points. `p2` clamps to `p1` when the loop has
    // exactly two iterations (so `iterations - 1 = 1` pins it to
    // `start + 1`). In that case `diff_12` is trivially
    // `OnlyConstants({})` and the match below still reaches the
    // Uniform branch when `p0 ≡ p1`.
    //
    //   iterations = 2 → p2 = start + 1  (= p1)
    //   iterations ≥ 3 → p2 = start + 2
    let p0 = start;
    let p1 = start + 1;
    let p2 = start + i64::min(2, iterations - 1);

    let tree_p0 = symbolic_emit(body, &[(iter_var, as_field(p0))]);
    let tree_p1 = symbolic_emit(body, &[(iter_var, as_field(p1))]);
    let tree_p2 = symbolic_emit(body, &[(iter_var, as_field(p2))]);

    let diff_01 = structural_diff(&tree_p0, &tree_p1);
    let diff_02 = structural_diff(&tree_p0, &tree_p2);
    let diff_12 = structural_diff(&tree_p1, &tree_p2);

    let binding_time = match (&diff_01, &diff_02, &diff_12) {
        // All three agree on shape and on the slot set → Uniform.
        // We require `s01 == s02` because a slot that's present in
        // 0↔1 but not in 0↔2 would indicate a non-monotonic
        // dependency on i (e.g., `if i == 0 {... }`) — safer to
        // treat as DataDependent than to promote.
        (Diff::OnlyConstants(s01), Diff::OnlyConstants(s02), Diff::OnlyConstants(_))
            if s01 == s02 =>
        {
            BindingTime::Uniform {
                skeleton: tree_p0.clone(),
                captures: s01.clone(),
            }
        }
        // Anything else → conservative fallback. Period-2 detection
        // (`Structural, OnlyConstants, Structural`) is subsumed by
        // this branch for v1.
        _ => BindingTime::DataDependent,
    };

    ClassificationDetails {
        binding_time,
        diff_01,
        diff_02,
        diff_12,
    }
}

/// Convenience wrapper that classifies an
/// [`ExtendedInstruction::LoopUnroll`] directly. Returns
/// [`BindingTime::DataDependent`] if passed anything else.
pub fn classify_loop_unroll<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    as_field: impl Fn(i64) -> FieldElement<F>,
) -> ClassificationDetails<F> {
    match inst {
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body,
        } => classify(*iter_var, body, *start, *end, as_field),
        _ => ClassificationDetails {
            binding_time: BindingTime::DataDependent,
            diff_01: Diff::Structural,
            diff_02: Diff::Structural,
            diff_12: Diff::Structural,
        },
    }
}

#[cfg(test)]
mod tests;
