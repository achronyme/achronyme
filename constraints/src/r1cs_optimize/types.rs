//! Public result + substitution-map types shared by both optimizer
//! passes (O1 linear elimination and O2 DEDUCE).
//!
//! These are the only names re-exported from `r1cs_optimize` — the
//! rest of the submodules expose their helpers as `pub(super)` to
//! keep the surface area small. Consumers (the compiler's R1CS
//! backend, the witness generator) only ever see
//! `R1CSOptimizeResult` and `SubstitutionMap<F>`.

use rustc_hash::FxHashMap;

use crate::r1cs::LinearCombination;

/// Statistics from linear constraint elimination.
#[derive(Debug, Clone)]
pub struct R1CSOptimizeResult {
    /// Number of constraints before optimization.
    pub constraints_before: usize,
    /// Number of constraints after optimization.
    pub constraints_after: usize,
    /// Number of variables substituted away.
    pub variables_eliminated: usize,
    /// Number of duplicate non-linear constraints removed.
    pub duplicates_removed: usize,
    /// Number of trivially-satisfied constraints removed (0*B=0, k1*k2=k3).
    pub trivial_removed: usize,
    /// Number of fixpoint rounds executed.
    pub rounds: usize,
    /// Per-round breakdown: (linear_eliminated, newly_linear_from_nonlinear).
    pub round_details: Vec<(usize, usize)>,
}

/// Maps a variable index to the LC that replaces it.
///
/// Keyed by `var.index()` (a small dense `usize`). Uses
/// `rustc_hash::FxHashMap` because:
///   - the keys are compiler-internal indices, not user-facing
///     strings, so HashDoS resistance from the default SipHash-13
///     is unneeded;
///   - `apply_substitution_in_place` probes this map per-term per-LC
///     per-round; for SMTVerifier(10) the SipHash leaf samples
///     summed to ~23 % of total pipeline wall time before this
///     change.
pub type SubstitutionMap<F> = FxHashMap<usize, LinearCombination<F>>;
