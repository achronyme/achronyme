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

use std::collections::HashSet;

use memory::FieldBackend;

use super::predicates::is_linear;
use super::union_find::UnionFind;
use crate::r1cs::{Constraint, Variable};

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
