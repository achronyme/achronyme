use super::make_lc_var;
use crate::r1cs::ConstraintSystem;

// ========================================================================
// linear_cluster::build_clusters_by_signal -- partition tests
// ========================================================================

/// Two disjoint linear sub-systems must produce two clusters: their
/// variable-index sets do not overlap, so Union-Find never merges them.
#[test]
fn cluster_isolation_disjoint_subsystems() {
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    // Cluster A: 1 * a = b -- shares no variables with B.
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    cs.enforce_equal(make_lc_var(a), make_lc_var(b));

    // Cluster B: 1 * c = d -- disjoint variable indices vs A.
    let c = cs.alloc_witness();
    let d = cs.alloc_witness();
    cs.enforce_equal(make_lc_var(c), make_lc_var(d));

    let constraints = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let clusters = build_clusters_by_signal(&constraints, &protected);

    assert_eq!(clusters.len(), 2, "expected 2 disjoint clusters");
    assert!(clusters.iter().all(|c| c.len() == 1));
}

/// Three constraints `a-b`, `b-c`, `c-d` share signals transitively.
/// Union-Find must merge them into a single cluster of size 3.
#[test]
fn cluster_transitive_merge() {
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let c = cs.alloc_witness();
    let d = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(a), make_lc_var(b)); // shares b with next
    cs.enforce_equal(make_lc_var(b), make_lc_var(c)); // shares c with next
    cs.enforce_equal(make_lc_var(c), make_lc_var(d));

    let constraints = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let clusters = build_clusters_by_signal(&constraints, &protected);

    assert_eq!(clusters.len(), 1, "transitive merge -> 1 cluster");
    assert_eq!(clusters[0].len(), 3);
    assert_eq!(clusters[0], vec![0, 1, 2]);
}

/// When every signal a constraint touches is in the protected set,
/// the constraint contributes no merging signal and ends up as a
/// singleton. This guards against Union-Find leaking through public
/// inputs / aux wires (which would inflate clusters without enabling
/// any substitution).
#[test]
fn cluster_all_protected_returns_singletons() {
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_a = cs.alloc_input();
    let pub_b = cs.alloc_input();
    cs.enforce_equal(make_lc_var(pub_a), make_lc_var(pub_b));
    cs.enforce_equal(make_lc_var(pub_a), make_lc_var(pub_b)); // duplicate

    let constraints = cs.constraints().to_vec();
    // Public inputs are protected: indices 0..=2 (ONE + 2 pub inputs).
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let clusters = build_clusters_by_signal(&constraints, &protected);

    // No mergeable signal -> 2 singletons.
    assert_eq!(clusters.len(), 2);
    assert!(clusters.iter().all(|c| c.len() == 1));
}

// ========================================================================
// linear_cluster::solve_cluster_linear -- per-cluster Gauss tests
// ========================================================================
