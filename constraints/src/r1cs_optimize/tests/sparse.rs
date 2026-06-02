use super::make_lc_var;
use crate::r1cs::{ConstraintSystem, LinearCombination, Variable};
use memory::FieldElement;

// ========================================================================
// Sparse DEDUCE tests
// ========================================================================

/// Two unrelated constraint sets (disjoint variable indices, disjoint
/// monomials) should be processed as two independent clusters by
/// `optimize_o2_sparse`. The resulting constraint count + variable
/// eliminations must equal the dense `optimize_o2` baseline -- the
/// outer-loop scaffolding is shared, so the only path-dependent
/// difference is whether DEDUCE runs at cluster granularity.
#[test]
fn sparse_cluster_isolation_matches_dense() {
    use crate::r1cs_optimize::{optimize_o2, optimize_o2_sparse};

    fn build_two_disjoint_systems() -> ConstraintSystem<memory::Bn254Fr> {
        let mut cs = ConstraintSystem::new();
        // Cluster A: x*y=z; 1*w=z (linear) -- shares variable z so they
        // do interact in O1, but the quadratic monomial set is {(x,y)}
        // alone.
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        let z = cs.alloc_witness();
        let w = cs.alloc_witness();
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
        cs.enforce_equal(make_lc_var(w), make_lc_var(z));

        // Cluster B: a*b=c; 1*d=c -- separate variable indices, separate
        // monomials. Should not interact with cluster A.
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();
        let c = cs.alloc_witness();
        let d = cs.alloc_witness();
        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(c));
        cs.enforce_equal(make_lc_var(d), make_lc_var(c));

        cs
    }

    let mut dense = build_two_disjoint_systems().constraints().to_vec();
    let mut sparse = build_two_disjoint_systems().constraints().to_vec();

    let (_, dense_stats) = optimize_o2(&mut dense, 0);
    let (_, sparse_stats) = optimize_o2_sparse(&mut sparse, 0);

    assert_eq!(
        dense_stats.constraints_after, sparse_stats.constraints_after,
        "sparse and dense O2 must agree on final constraint count for disjoint systems"
    );
    assert_eq!(
        dense_stats.variables_eliminated, sparse_stats.variables_eliminated,
        "sparse and dense O2 must agree on eliminations for disjoint systems"
    );
}

/// On a tiny boolean-decomposition system (one constraint per bit, all
/// sharing variable `ONE`), sparse and dense O2 must converge to the
/// same constraint count. Boolean checks are the dominant pattern in
/// Num2Bits-style circuits where the sparse path is expected to behave
/// identically to dense at small scale.
#[test]
fn sparse_matches_dense_on_boolean_decomposition() {
    use crate::r1cs_optimize::{optimize_o2, optimize_o2_sparse};

    fn build_bool_decomp(n_bits: usize) -> ConstraintSystem<memory::Bn254Fr> {
        let mut cs = ConstraintSystem::new();
        let mut bits = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            bits.push(cs.alloc_witness());
        }
        // Each bit b: b * (1 - b) = 0
        for &b in &bits {
            let one_minus_b = LinearCombination::from_variable(Variable::ONE)
                - LinearCombination::from_variable(b);
            cs.enforce(make_lc_var(b), one_minus_b, LinearCombination::zero());
        }
        cs
    }

    for n_bits in [4usize, 8, 12] {
        let mut dense = build_bool_decomp(n_bits).constraints().to_vec();
        let mut sparse = build_bool_decomp(n_bits).constraints().to_vec();

        let (_, dense_stats) = optimize_o2(&mut dense, 0);
        let (_, sparse_stats) = optimize_o2_sparse(&mut sparse, 0);

        assert_eq!(
            dense_stats.constraints_after, sparse_stats.constraints_after,
            "sparse vs dense disagree on bool decomp(n_bits={n_bits})"
        );
    }
}

/// `optimize_o2_sparse` must be a no-op on a fully linear system (no
/// quadratic constraints). The dense path is already a no-op for
/// DEDUCE in this case; sparse must mirror that exactly so we never
/// fabricate constraints out of thin air on degenerate input.
#[test]
fn sparse_o2_no_op_on_linear_system() {
    use crate::r1cs_optimize::optimize_o2_sparse;

    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let c = cs.alloc_witness();
    cs.enforce_equal(
        make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
        make_lc_var(c),
    );

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_o2_sparse(&mut constraints, cs.num_pub_inputs());

    // O1 alone substitutes c (or one of a,b) and removes the constraint.
    assert_eq!(stats.constraints_after, 0);
    assert_eq!(stats.variables_eliminated, 1);
    assert_eq!(subs.len(), 1);
}

/// A large cluster (above `MAX_CLUSTER_SIZE`) must be skipped without
/// panicking and without losing soundness. The constraints stay in the
/// system unchanged; O1 + decompose around them still runs.
///
/// We construct a synthetic cluster of 400 quadratic constraints that
/// all share one common monomial `x*y` so they end up in the same
/// connected component. After `optimize_o2_sparse`, the constraint
/// count must still bound the system (no spurious deductions), and
/// the original witness must still satisfy what remains.
#[test]
fn sparse_skips_oversized_cluster() {
    use crate::r1cs_optimize::optimize_o2_sparse;

    let mut cs = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();

    // 400 wires z_i, each with x*y = z_i. All 400 constraints share the
    // monomial (x,y), so Union-Find puts them in one cluster of size 400 > 350.
    let mut zs: Vec<Variable> = Vec::with_capacity(400);
    for _ in 0..400 {
        let z = cs.alloc_witness();
        zs.push(z);
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
    }

    let constraints_before = cs.constraints().len();
    let mut constraints = cs.constraints().to_vec();
    let (_subs, stats) = optimize_o2_sparse(&mut constraints, cs.num_pub_inputs());

    // Sanity: optimize_o2_sparse did not crash and did not blow up the
    // constraint count (skip is supposed to be a no-op for the cluster
    // beyond aux-wire bookkeeping that O1 will sweep).
    assert!(
        stats.constraints_after <= constraints_before,
        "skipped cluster must not grow the system"
    );

    // The 400 constraints share monomial (x,y) and only differ in C.
    // O1 sees them all as 1 * <multi-term LC> = 0 after any deduction
    // would be applied; even without deductions, the system stays
    // satisfiable with x=2, y=3, z_i=6.
    let mut witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(2),
        FieldElement::from_u64(3),
    ];
    witness.extend(std::iter::repeat_n(FieldElement::from_u64(6), 400));
    for c in &constraints {
        let av = c.a.evaluate(&witness).unwrap();
        let bv = c.b.evaluate(&witness).unwrap();
        let cv = c.c.evaluate(&witness).unwrap();
        assert_eq!(
            av.mul(&bv),
            cv,
            "skipped cluster: witness must still satisfy"
        );
    }
}
