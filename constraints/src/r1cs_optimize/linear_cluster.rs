//! Cluster-based Gaussian elimination on linear R1CS constraints.
//!
//! Mirrors circom 2.2.x's `linear_simplification` pipeline
//! (`constraint_list/src/constraint_simplification.rs:275` in
//! `iden3/circom`):
//!
//! 1. Partition the linear constraints into connected components via
//!    Union-Find on shared variable indices (one signal -> all
//!    constraints referencing it merge).
//! 2. Run reduced row-echelon Gaussian elimination over each cluster
//!    independently. Cluster sizes >= 350 use a min-occurrence
//!    picker; smaller clusters use the existing max-frequency
//!    picker. (Phase 5: picker swap. Phase 2 + 3 use only
//!    max-frequency.)
//!
//! `optimize_linear_clustered` is the public entry; an
//! `_with_protected` variant exists for the same reason as in
//! `linear.rs:52` -- O2's outer loop calls it after
//! `decompose_for_deduce_tracked` to shield aux wires.
//!
//! This module currently exposes only `build_clusters_by_signal`
//! (Phase 2). The Gaussian solver and public API land in subsequent
//! phases.

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use super::predicates::is_linear;
use super::substitution::{apply_substitution, solve_for_variable};
use super::types::SubstitutionMap;
use super::union_find::UnionFind;
use crate::r1cs::{Constraint, LinearCombination, Variable};

/// Cluster the linear constraints in `linear_constraints` by shared
/// variable index. Two constraints land in the same cluster iff they
/// reference at least one common non-protected, non-`Variable::ONE`
/// signal.
///
/// Returns clusters as a `Vec<Vec<usize>>` of indices into
/// `linear_constraints`. Each cluster vec is sorted ascending; clusters
/// as a whole are sorted by their smallest member, so the output is
/// deterministic across runs.
///
/// **Skip rules:**
/// - `Variable::ONE` (index 0) is always skipped. Sharing the
///   constant wire would merge every constraint into one giant
///   cluster regardless of structure.
/// - Indices in `protected` (public inputs, decompose aux wires) are
///   also skipped. Clustering on a protected signal cannot enable a
///   substitution -- the picker will refuse to substitute it -- so
///   merging through it only inflates clusters without enabling work.
///
/// Constraints not classified as linear by `is_linear` produce
/// singleton clusters (they cannot contribute to or be reduced by
/// the Gauss step).
#[allow(dead_code)] // wired in Phase 4
pub(super) fn build_clusters_by_signal<F: FieldBackend>(
    linear_constraints: &[Constraint<F>],
    protected: &HashSet<usize>,
) -> Vec<Vec<usize>> {
    let n = linear_constraints.len();
    let mut uf = UnionFind::new(n);

    // For each signal index, remember the first constraint that owns
    // it; subsequent owners union with that first. The first-owner
    // table is keyed on signal index up to the maximum referenced
    // (sized lazily via HashMap, since the wire-index space is sparse
    // here -- we only see indices appearing in the linear subset).
    let mut first_owner: std::collections::HashMap<usize, usize> =
        std::collections::HashMap::new();

    for (idx, constraint) in linear_constraints.iter().enumerate() {
        // Walk only constraints that ARE linear. Non-linear ones
        // contribute no signals to the Union-Find -- they end up as
        // their own singleton cluster, which the caller can ignore
        // (the Gauss step has nothing to do with them).
        let Some((_k, other_lc, c_lc)) = is_linear(constraint) else {
            continue;
        };

        for (var, _coeff) in other_lc.terms().iter().chain(c_lc.terms().iter()) {
            let sig = var.index();
            if sig == Variable::ONE.index() || protected.contains(&sig) {
                continue;
            }
            match first_owner.get(&sig) {
                Some(&owner) => uf.union(idx, owner),
                None => {
                    first_owner.insert(sig, idx);
                }
            }
        }
    }

    // Bucket by root. Pushing in 0..n order keeps each cluster vec
    // sorted ascending.
    let mut by_root: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for idx in 0..n {
        let root = uf.find(idx);
        by_root.entry(root).or_default().push(idx);
    }
    let mut clusters: Vec<Vec<usize>> = by_root.into_values().collect();
    clusters.sort_by_key(|c| c[0]);
    clusters
}

/// Run reduced row-echelon Gaussian elimination on a single cluster of
/// linear constraints.
///
/// Each linear constraint `k * other = c_lc` is rewritten as the LC
/// `c_lc - k*other` that must equal zero. We pick a pivot row + a
/// pivot variable via `solve_for_variable` (max-frequency picker;
/// the size-conditional swap to min-occurrence lands in Phase 5),
/// record the substitution `var -> expr`, apply it to the remaining
/// rows + previously-recorded substitutions (composition), and
/// repeat until no row admits a substitution.
///
/// Inputs:
/// - `cluster_constraints`: linear constraints in this cluster.
///   Non-linear constraints (those for which `is_linear` returns
///   `None`) flow straight to the residual list -- they cannot
///   contribute to or be reduced by the linear Gauss step.
/// - `protected`: variables the picker must never substitute (public
///   inputs, `Variable::ONE`, decompose aux wires).
/// - `var_freq`: per-variable frequency over the full constraint
///   set, used by the max-frequency picker. The frequency map is
///   passed in (rather than computed locally over the cluster) to
///   match the existing greedy path's heuristic exactly during
///   Phase 3.
///
/// Output:
/// - `(SubstitutionMap, residual)`: the discovered substitutions
///   (composed acyclically -- each value LC references only
///   variables not in the substitution map's keys), plus any
///   constraints that could not be reduced (all-protected variables,
///   or non-linear constraints in the cluster). Residual constraints
///   are emitted in `1 * lc = 0` form mirroring the dense path.
#[allow(dead_code)] // wired in Phase 4
pub(super) fn solve_cluster_linear<F: FieldBackend>(
    cluster_constraints: Vec<Constraint<F>>,
    protected: &HashSet<usize>,
    var_freq: &HashMap<usize, usize>,
) -> (SubstitutionMap<F>, Vec<Constraint<F>>) {
    // Linearize: build the per-constraint "must equal zero" LC.
    let mut zero_lcs: Vec<LinearCombination<F>> = Vec::new();
    let mut residual: Vec<Constraint<F>> = Vec::new();

    for c in cluster_constraints {
        match is_linear(&c) {
            Some((k, other, c_lc)) => {
                // Constraint encodes k * other = c_lc, i.e.
                // c_lc - k*other = 0.
                let combined = (c_lc - (other * k)).simplify();
                zero_lcs.push(combined);
            }
            None => residual.push(c),
        }
    }

    let mut subs: SubstitutionMap<F> = HashMap::new();

    loop {
        // Build the "effective protected" set: original protected
        // variables plus everything we have already substituted. Once
        // a variable is substituted it must never be picked again --
        // doing so would create a chain in the substitution map and
        // break the acyclic invariant the witness fixup relies on.
        let mut effective_protected = protected.clone();
        for var_idx in subs.keys() {
            effective_protected.insert(*var_idx);
        }

        // Find the first row that admits a substitution.
        let mut found: Option<(usize, Variable, LinearCombination<F>)> = None;
        for (i, lc) in zero_lcs.iter().enumerate() {
            if let Some((var, expr)) =
                solve_for_variable(lc.clone(), &effective_protected, var_freq)
            {
                found = Some((i, var, expr));
                break;
            }
        }

        let Some((row_idx, var, expr)) = found else {
            break;
        };
        zero_lcs.swap_remove(row_idx);

        // Apply the new substitution to all remaining rows + compose
        // it into previously-recorded substitutions so the final map
        // is acyclic.
        let mut single_sub: SubstitutionMap<F> = HashMap::new();
        single_sub.insert(var.index(), expr.clone());

        for lc in zero_lcs.iter_mut() {
            *lc = apply_substitution(lc, &single_sub);
        }
        for prev_expr in subs.values_mut() {
            *prev_expr = apply_substitution(prev_expr, &single_sub);
        }
        subs.insert(var.index(), expr);
    }

    // Convert any remaining non-empty rows back to constraint form
    // (`1 * lc = 0`) so the caller can keep them in the system.
    // Empty rows are tautologies after substitution; skip them.
    for lc in zero_lcs {
        let lc_simp = lc.simplify();
        if !lc_simp.terms().is_empty() {
            residual.push(Constraint {
                a: LinearCombination::from_constant(FieldElement::one()),
                b: lc_simp,
                c: LinearCombination::zero(),
            });
        }
    }

    (subs, residual)
}
