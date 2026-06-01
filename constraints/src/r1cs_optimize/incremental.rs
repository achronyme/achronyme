//! Incremental linear collapse: fold linear-constraint elimination into
//! constraint emission so the constraint system never materializes the
//! unoptimized set, only the post-elimination survivors plus a running
//! substitution map.
//!
//! This is the streaming analogue of [`super::optimize_linear`]. Where the
//! batch optimizer builds the full constraint set and then runs a clustered
//! Gaussian fixpoint, the incremental collapser folds each emitted
//! constraint as it arrives: it applies the running substitution map, then
//! either records a new substitution (the constraint is linear and solvable
//! — it is absorbed, not stored) or keeps the constraint as a survivor.
//!
//! Soundness rests on one invariant: **no surviving constraint, and no
//! substitution-map replacement, may reference an eliminated variable.** A
//! survivor that referenced an eliminated wire would leave that wire free
//! (the verifier does not enforce the substitution map), which is forgeable.
//! Because this is a single forward pass with no retro-substitution into
//! already-emitted survivors, a variable is eligible for elimination only
//! while it is still "fresh" — not yet referenced by any survivor, any
//! prior replacement, or the public interface. The `barred` set tracks
//! exactly those committed variables; a linear constraint is absorbed only
//! when it has an unbarred pivot, otherwise it is kept as a survivor.
//!
//! This safely absorbs the dominant eliminate-before-use class (the
//! `materialize_lc` / fresh-wire constraints: the wire is defined by
//! `lc = fresh`, eliminated immediately, and only consumed afterwards — its
//! later uses are substituted at arrival). It declines the use-then-
//! eliminate minority (`out <== a*b; out === c`, range-decomposition sums
//! over already-referenced bits), keeping those as survivors — a small,
//! sound count inflation versus the batch optimizer, which handles them via
//! retro-substitution. Barring replacement variables keeps the map fully
//! canonical, so applying it to an arriving constraint is a single pass that
//! never leaves a dangling eliminated variable (no composition pass needed).

use std::collections::HashSet;

use rustc_hash::FxHashMap;

use memory::FieldBackend;

use super::predicates::{is_linear, is_trivially_satisfied};
use super::substitution::{
    apply_substitution_to_constraint_in_place, solve_for_variable, InvCache,
};
use super::types::SubstitutionMap;
use crate::r1cs::Constraint;

/// Streaming linear-elimination state. One per constraint system with
/// collapse enabled. Holds the accumulated substitution map (eliminated
/// `Variable.index()` → replacement `LinearCombination`), the inversion
/// memo, and `barred`: the set of variables ineligible for elimination —
/// `ONE` + public inputs + every variable already eliminated, referenced by
/// a survivor, or referenced by a replacement. A wire is eliminable only
/// while it is still fresh (absent from `barred`), which is what makes a
/// single forward pass sound without retro-substitution.
#[derive(Clone)]
pub struct IncrementalCollapse<F: FieldBackend> {
    subs: SubstitutionMap<F>,
    barred: HashSet<usize>,
    track_barred: bool,
    retain_substitutions: bool,
    /// Always empty: passed to `solve_for_variable` so its max-frequency
    /// pick degenerates to "highest index" (the forward / freshest-wire
    /// pivot). Kept as a field to avoid reallocating per constraint.
    empty_freq: FxHashMap<usize, usize>,
    inv_cache: InvCache<F>,
}

impl<F: FieldBackend> IncrementalCollapse<F> {
    /// Create a collapser whose barred set starts as `ONE` (index 0) plus
    /// the public inputs (indices `1..=num_pub_inputs`).
    pub fn new(num_pub_inputs: usize) -> Self {
        Self {
            subs: FxHashMap::default(),
            barred: (0..=num_pub_inputs).collect(),
            track_barred: true,
            retain_substitutions: true,
            empty_freq: FxHashMap::default(),
            inv_cache: FxHashMap::default(),
        }
    }

    /// Create a collapser that absorbs eligible linear constraints but does
    /// not retain the substitution map. This is only valid for compile-only
    /// count/sizing paths that do not store rows and cannot reconstruct
    /// eliminated witness wires.
    pub fn new_count_only(num_pub_inputs: usize) -> Self {
        let mut collapse = Self::new(num_pub_inputs);
        collapse.track_barred = false;
        collapse.retain_substitutions = false;
        collapse
    }

    /// Fold one emitted constraint. Applies the running substitution map,
    /// then returns `Some(survivor)` for the caller to store, or `None` when
    /// the constraint is absorbed — either trivially satisfied after
    /// substitution, or linear with an unbarred pivot (a new substitution is
    /// recorded). A linear constraint whose only candidate pivots are barred
    /// (use-then-eliminate) is kept as a survivor.
    pub fn fold(&mut self, mut constraint: Constraint<F>) -> Option<Constraint<F>> {
        apply_substitution_to_constraint_in_place(&mut constraint, &self.subs);

        if is_trivially_satisfied(&constraint) {
            return None;
        }

        if let Some((k, other_lc, c_lc)) = is_linear(&constraint) {
            // The linear constraint is `k * other_lc = c_lc`; solve the
            // homogeneous form `k * other_lc - c_lc = 0` for a fresh wire.
            // `barred` is passed as the protected set, so the pivot is the
            // highest-index variable not yet committed anywhere.
            let zero_lc = other_lc * k - c_lc;
            if let Some((var, replacement)) =
                solve_for_variable(zero_lc, &self.barred, &self.empty_freq, &mut self.inv_cache)
            {
                // Bar the eliminated wire and every variable its replacement
                // references. Barring replacement variables keeps the map
                // canonical (replacements never reference an eliminated
                // wire), so a single-pass apply never leaves a dangling
                // reference and no composition pass is needed.
                if self.track_barred {
                    self.barred.insert(var.index());
                    for (v, _) in replacement.terms() {
                        self.barred.insert(v.index());
                    }
                }
                if self.retain_substitutions {
                    self.subs.insert(var.index(), replacement);
                }
                return None;
            }
        }

        // Survivor: bar every variable it references so none is eliminated
        // out from under it by a later constraint.
        if self.track_barred {
            self.bar_constraint(&constraint);
        }
        Some(constraint)
    }

    fn bar_constraint(&mut self, constraint: &Constraint<F>) {
        for lc in [&constraint.a, &constraint.b, &constraint.c] {
            for (v, _) in lc.terms() {
                self.barred.insert(v.index());
            }
        }
    }

    /// Bar a variable index from elimination. Called as public inputs are
    /// allocated (they may be allocated AFTER collapse is enabled, during a
    /// streaming `compile_ir` walk), so the public range is always barred.
    pub fn protect(&mut self, var_index: usize) {
        self.barred.insert(var_index);
    }

    #[cfg(test)]
    pub(crate) fn barred_len(&self) -> usize {
        self.barred.len()
    }

    /// Borrow the accumulated substitution map (for witness reconstruction
    /// of eliminated wires).
    pub fn substitution_map(&self) -> &SubstitutionMap<F> {
        &self.subs
    }

    /// Consume the collapser, returning the substitution map.
    pub fn into_substitution_map(self) -> SubstitutionMap<F> {
        self.subs
    }
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::r1cs::{LinearCombination, Variable};

    fn lc_var(var: Variable) -> LinearCombination<Bn254Fr> {
        LinearCombination::from_variable(var)
    }

    #[test]
    fn count_only_collapse_does_not_grow_barred_set() {
        let mut collapse = IncrementalCollapse::<Bn254Fr>::new_count_only(0);
        let initial_barred = collapse.barred_len();

        let x = Variable(1);
        let y = Variable(2);
        let z = Variable(3);
        let materialize = Constraint {
            a: lc_var(x) + lc_var(y),
            b: LinearCombination::from_constant(FieldElement::one()),
            c: lc_var(z),
        };
        assert!(collapse.fold(materialize).is_none());

        let survivor = Constraint {
            a: lc_var(z),
            b: lc_var(y),
            c: lc_var(x),
        };
        assert!(collapse.fold(survivor).is_some());
        assert_eq!(
            collapse.barred_len(),
            initial_barred,
            "count-only collapse must not retain per-variable barred state"
        );
        assert!(collapse.into_substitution_map().is_empty());
    }
}
