//! R1CS constraint optimization — two-pass pipeline that mirrors
//! circom's `--O1` and `--O2` simplification stages.
//!
//! ## Public API
//!
//! - [`optimize_linear`] -- O1: linear constraint elimination to
//!   fixpoint + dedup + trivial sweep. Re-exported from
//!   `linear_cluster::optimize_linear_clustered`, the cluster-based
//!   driver that partitions linear constraints into connected
//!   components by shared signal (Union-Find) and runs Gaussian
//!   elimination per cluster with a size-conditional picker
//!   (max-frequency below 350, min-occurrence in [350, 1M)). Clusters
//!   above `CLUSTER_FALLBACK_THRESHOLD` fall back to the greedy
//!   iterative eliminator (`linear::optimize_linear_with_protected`),
//!   preserved as a private helper for that purpose.
//! - [`optimize_o2`] -- O2: O1 followed by decompose + DEDUCE
//!   (Gaussian elimination on a quadratic-monomial matrix) +
//!   protected O1 + cleanup O1, repeated until convergence.
//! - [`optimize_o2_sparse`] -- variant of O2 that runs DEDUCE on
//!   `BTreeMap`-row clusters (Union-Find by shared monomial). Same
//!   outer loop, designed for circuits where the dense matrix would
//!   not fit in RAM.
//! - [`R1CSOptimizeResult`] + [`SubstitutionMap`] -- shared result
//!   type + substitution map consumed by the compiler's R1CS
//!   backend + witness generator.
//!
//! ## File layout
//!
//! - [`types`] -- `R1CSOptimizeResult` struct + `SubstitutionMap`
//!   alias.
//! - [`predicates`] -- side-effect-free shape queries: `is_linear`,
//!   `is_trivially_satisfied`, `compute_variable_frequency`,
//!   `lc_fingerprint`.
//! - [`substitution`] -- substitution primitives: `apply_substitution`,
//!   `apply_substitution_to_constraint`, `solve_for_variable`.
//! - [`linear`] -- greedy iterative O1 fixpoint, retained as a
//!   `pub(super)` helper (`optimize_linear_with_protected`) for use
//!   as the per-cluster fallback in `linear_cluster`. No longer the
//!   public O1 entry — see the re-export at the bottom of this file.
//! - [`linear_cluster`] -- cluster-based O1 (default driver):
//!   `optimize_linear_clustered`, `build_clusters_by_signal`,
//!   `solve_cluster_linear`, `Picker` enum.
//! - [`deduce`] -- dense O2 pass (`expand_constraint_product`,
//!   `deduce_linear_from_quadratic`, `decompose_for_deduce_tracked`,
//!   `optimize_o2`, `optimize_o2_with_deducer`).
//! - [`deduce_sparse`] -- sparse-row clustered O2 variant
//!   (`deduce_linear_from_quadratic_sparse`, `optimize_o2_sparse`).
//! - [`union_find`] -- shared Vec-backed disjoint-set union with
//!   path compression + union by rank. Used by `deduce_sparse` (key
//!   = quadratic monomial) and `linear_cluster` (key = variable
//!   index); the primitive is identical.
//! - [`tests`] -- integration tests that round-trip constraints
//!   through each pass and verify witness satisfaction.

mod deduce;
mod deduce_sparse;
mod linear;
mod linear_cluster;
mod predicates;
mod substitution;
mod types;
mod union_find;

pub use deduce::optimize_o2;
pub use deduce_sparse::optimize_o2_sparse;
// `optimize_linear` is the cluster-based driver. The greedy
// implementation is preserved as a private helper
// (`linear::optimize_linear_with_protected`) and called as the
// per-cluster fallback for clusters above CLUSTER_FALLBACK_THRESHOLD.
pub use linear_cluster::optimize_linear_clustered as optimize_linear;
pub use types::{R1CSOptimizeResult, SubstitutionMap};

#[cfg(test)]
mod tests;
