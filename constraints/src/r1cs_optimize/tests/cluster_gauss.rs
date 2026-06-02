use super::make_lc_var;
use crate::r1cs::{Constraint, ConstraintSystem, Variable};
use memory::FieldElement;

/// A cluster containing a single non-linear (quadratic) constraint must
/// produce no substitutions and emit the constraint as residual. The
/// solver linearises only what `is_linear` accepts.
#[test]
fn cluster_gauss_singleton_no_substitution() {
    use crate::r1cs_optimize::linear_cluster::solve_cluster_linear;
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();
    let z = cs.alloc_witness();
    // x * y = z -- genuinely quadratic, NOT linear.
    cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));

    let constraints = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let var_freq = compute_variable_frequency(&constraints);

    let mut inv_cache = rustc_hash::FxHashMap::default();
    let (subs, residual) = solve_cluster_linear::<memory::Bn254Fr>(
        constraints.clone(),
        &protected,
        &var_freq,
        &mut inv_cache,
    );

    assert!(subs.is_empty());
    assert_eq!(residual.len(), 1);
}

/// Cluster-Gauss applied to the same chain system as
/// `test_chain_substitution` (1*a=b, 1*b=c, c*c=d) must produce the
/// same final constraint count and a witness-satisfying residual as
/// the greedy path. Specific substitution keys may differ -- we
/// assert structural equivalence, not byte equality.
#[test]
fn cluster_gauss_chain_match_greedy() {
    use crate::r1cs_optimize::linear_cluster::{build_clusters_by_signal, solve_cluster_linear};
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use std::collections::HashSet;

    let mut cs = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let c = cs.alloc_witness();
    let d = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(a), make_lc_var(b));
    cs.enforce_equal(make_lc_var(b), make_lc_var(c));
    cs.enforce(make_lc_var(c), make_lc_var(c), make_lc_var(d));

    let constraints: Vec<_> = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let var_freq = compute_variable_frequency(&constraints);
    let clusters = build_clusters_by_signal(&constraints, &protected);

    // Linear constraints (idx 0,1) cluster together via shared variable b.
    // Quadratic constraint (idx 2) is its own singleton (is_linear -> None).
    // Solve only the linear cluster.
    let mut total_subs = std::collections::HashMap::new();
    let mut total_residual: Vec<Constraint<memory::Bn254Fr>> = Vec::new();
    let mut inv_cache = rustc_hash::FxHashMap::default();
    for cluster in &clusters {
        let cluster_cons: Vec<_> = cluster.iter().map(|i| constraints[*i].clone()).collect();
        let (subs, residual) = solve_cluster_linear::<memory::Bn254Fr>(
            cluster_cons,
            &protected,
            &var_freq,
            &mut inv_cache,
        );
        total_subs.extend(subs);
        total_residual.extend(residual);
    }

    // Greedy variant eliminated 2 vars and left 1 quadratic; cluster-Gauss
    // must match those counts.
    assert_eq!(
        total_subs.len(),
        2,
        "expected 2 vars eliminated (a and b OR b and c)"
    );
    assert_eq!(total_residual.len(), 1, "1 quadratic residual constraint");

    // Witness check: a=b=c=5, d=25 satisfies the residual quadratic.
    let witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(5),  // a
        FieldElement::from_u64(5),  // b
        FieldElement::from_u64(5),  // c
        FieldElement::from_u64(25), // d
    ];
    let con = &total_residual[0];
    let av = con.a.evaluate(&witness).unwrap();
    let bv = con.b.evaluate(&witness).unwrap();
    let cv = con.c.evaluate(&witness).unwrap();
    assert_eq!(av.mul(&bv), cv);
}

// ========================================================================
// optimize_linear_clustered driver tests
// ========================================================================

/// Mirror of `test_single_linear_elimination` (the very first sanity
/// test for greedy O1) under the clustered driver. Same input, same
/// expected outcome: one substitution, one quadratic constraint left,
/// witness still satisfied.
#[test]
fn cluster_gauss_multi_cluster_correctness() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let x = cs.alloc_witness();
    let y = cs.alloc_witness();
    let z = cs.alloc_witness();
    let w = cs.alloc_witness();

    // x * y = z (quadratic, kept)
    cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
    // 1 * w = z  (linear: w = z)
    cs.enforce_equal(make_lc_var(w), make_lc_var(z));

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.constraints_before, 2);
    assert_eq!(stats.constraints_after, 1);
    assert_eq!(stats.variables_eliminated, 1);
    assert_eq!(subs.len(), 1);

    // Witness check: x=6, y=7, z=42, w=42
    let mut witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(6),  // x
        FieldElement::from_u64(7),  // y
        FieldElement::from_u64(42), // z
        FieldElement::from_u64(42), // w
    ];
    for (var_idx, lc) in &subs {
        witness[*var_idx] = lc.evaluate(&witness).unwrap();
    }
    for c in &constraints {
        let av = c.a.evaluate(&witness).unwrap();
        let bv = c.b.evaluate(&witness).unwrap();
        let cv = c.c.evaluate(&witness).unwrap();
        assert_eq!(av.mul(&bv), cv);
    }
}

/// `extra_protected` plumbing: a synthetic "aux wire" shared with a
/// non-protected variable across a cluster must never be picked as
/// the substitution target -- the picker (max-frequency or min-occ)
/// must always pick the non-protected wire.
#[test]
fn cluster_gauss_aux_wire_protection() {
    use crate::r1cs_optimize::linear_cluster::optimize_linear_clustered_with_protected;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let aux = cs.alloc_witness(); // pretend this is a decompose aux wire (idx 1)
    let other = cs.alloc_witness(); // idx 2

    // 1 * aux = other -- linear, picker chooses one of {aux, other}.
    cs.enforce_equal(make_lc_var(aux), make_lc_var(other));

    let mut constraints = cs.constraints().to_vec();
    let mut extra: HashSet<usize> = HashSet::new();
    extra.insert(aux.index());
    let (subs, _stats) =
        optimize_linear_clustered_with_protected(&mut constraints, cs.num_pub_inputs(), &extra);

    assert!(
        !subs.contains_key(&aux.index()),
        "aux wire must NOT be substituted"
    );
    assert!(
        subs.contains_key(&other.index()),
        "other wire SHOULD be substituted"
    );
}

/// Public input variables must never be substituted. Mirrors
/// `test_public_variable_not_substituted` for the clustered driver.
#[test]
fn cluster_gauss_does_not_substitute_protected() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input(); // idx 1, public
    let w = cs.alloc_witness(); // idx 2
    let z = cs.alloc_witness(); // idx 3

    cs.enforce_equal(make_lc_var(pub_out), make_lc_var(w));
    cs.enforce(make_lc_var(w), make_lc_var(w), make_lc_var(z));

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.variables_eliminated, 1);
    assert!(subs.contains_key(&w.index()), "w should be substituted");
    assert!(!subs.contains_key(&pub_out.index()), "pub_out is protected");
    assert_eq!(constraints.len(), 1, "only the quadratic should remain");
}

/// Larger end-to-end soundness check on the `test_optimization_preserves_satisfaction`
/// system, run through the clustered driver. After fixup, every
/// remaining constraint must still satisfy the witness.
#[test]
fn cluster_gauss_soundness_witness_roundtrip() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input();
    let a = cs.alloc_witness();
    let b = cs.alloc_witness();
    let m1 = cs.alloc_witness();
    let m2 = cs.alloc_witness();
    let c = cs.alloc_witness();

    cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(pub_out));
    cs.enforce_equal(
        make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
        make_lc_var(m1),
    );
    cs.enforce(make_lc_var(m1), make_lc_var(a), make_lc_var(m2));
    cs.enforce_equal(make_lc_var(m2), make_lc_var(c));

    let mut witness = vec![
        FieldElement::ONE,
        FieldElement::from_u64(12), // pub_out
        FieldElement::from_u64(3),  // a
        FieldElement::from_u64(4),  // b
        FieldElement::from_u64(7),  // m1 = a+b
        FieldElement::from_u64(21), // m2 = m1*a
        FieldElement::from_u64(21), // c = m2
    ];

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());
    assert_eq!(stats.constraints_before, 4);
    assert_eq!(stats.constraints_after, 2);

    // Apply subs to witness.
    for (var_idx, lc) in &subs {
        witness[*var_idx] = lc.evaluate(&witness).unwrap();
    }

    for (i, c) in constraints.iter().enumerate() {
        let av = c.a.evaluate(&witness).unwrap();
        let bv = c.b.evaluate(&witness).unwrap();
        let cv = c.c.evaluate(&witness).unwrap();
        assert_eq!(
            av.mul(&bv),
            cv,
            "constraint {i} unsatisfied after clustered optimization"
        );
    }
}

/// Substituting one side of a constraint can collapse it into a
/// tautology (e.g. `1 * pub = pub` after `x = pub`). The clustered
/// driver must remove those via the trivial sweep.
#[test]
fn cluster_gauss_tautology_after_pivot() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let pub_out = cs.alloc_input(); // idx 1
    let x = cs.alloc_witness(); // idx 2
    let z = cs.alloc_witness(); // idx 3

    cs.enforce_equal(make_lc_var(pub_out), make_lc_var(x));
    cs.enforce_equal(make_lc_var(x), make_lc_var(pub_out));
    cs.enforce(make_lc_var(x), make_lc_var(x), make_lc_var(z));

    let mut constraints = cs.constraints().to_vec();
    let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    // Cluster-Gauss absorbs the tautology inside solve_cluster_linear
    // (the second linear constraint reduces to an empty row after the
    // first substitution and is dropped before being re-emitted as
    // residual), whereas the greedy path discovers it via
    // is_trivially_satisfied AFTER applying substitutions. Both
    // arrive at the same end state (1 constraint left, 1 var
    // eliminated) by different bookkeeping; we assert the end state.
    assert_eq!(stats.constraints_before, 3);
    assert_eq!(
        stats.constraints_after, 1,
        "only pub*pub=z should remain after tautology absorption"
    );
    assert_eq!(stats.variables_eliminated, 1);
}

// ========================================================================
// Picker selection tests
// ========================================================================

/// Above the MIN_OCCURRENCE_LOWER threshold (350), the picker switches
/// to min-occurrence: the variable with the FEWEST occurrences in the
/// global frequency map wins, tie-broken by largest signal index.
///
/// Construction: 360 linear constraints `1 * hot = bot_i` for
/// i in 0..360. `hot` (idx 1) appears in 360 rows; each `bot_i`
/// (indices 2..362) appears in exactly 1 row. They form one cluster
/// of 360 (above the threshold).
///
/// Under min-occurrence: every row picks its own `bot_i` (freq 1)
/// over `hot` (freq 360). Result: subs = {bot_0..bot_359}, hot is
/// NEVER substituted.
#[test]
fn cluster_gauss_min_occurrence_picker_above_threshold() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let hot = cs.alloc_witness();
    let mut bots: Vec<Variable> = Vec::with_capacity(360);
    for _ in 0..360 {
        bots.push(cs.alloc_witness());
    }
    for &b in &bots {
        cs.enforce_equal(make_lc_var(hot), make_lc_var(b));
    }

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.variables_eliminated, 360);
    assert!(
        !subs.contains_key(&hot.index()),
        "hot variable (idx {}) must NOT be substituted under min-occurrence picker; \
         subs has {} keys, hot present={}",
        hot.index(),
        subs.len(),
        subs.contains_key(&hot.index()),
    );
    // Every bot_i should be substituted instead.
    for &b in &bots {
        assert!(
            subs.contains_key(&b.index()),
            "bot variable (idx {}) should be substituted",
            b.index()
        );
    }
}

/// Below the threshold (340 < 350), the picker stays max-frequency:
/// `hot` (freq 340) wins over each `bot_i` (freq 1). Hot IS
/// substituted in the first round.
#[test]
fn cluster_gauss_max_frequency_picker_below_threshold() {
    use crate::r1cs_optimize::optimize_linear;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let hot = cs.alloc_witness();
    let mut bots: Vec<Variable> = Vec::with_capacity(340);
    for _ in 0..340 {
        bots.push(cs.alloc_witness());
    }
    for &b in &bots {
        cs.enforce_equal(make_lc_var(hot), make_lc_var(b));
    }

    let mut constraints = cs.constraints().to_vec();
    let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

    assert_eq!(stats.variables_eliminated, 340);
    // Under max-frequency, the FIRST row's pick is `hot` -> hot is
    // in subs. (Other bot_i's get substituted in subsequent rows.)
    assert!(
        subs.contains_key(&hot.index()),
        "hot variable (idx {}) MUST be substituted under max-frequency picker",
        hot.index(),
    );
}

/// Threshold boundary: exactly 350 triggers min-occurrence; 349 stays
/// max-frequency. Documents the picker's branch condition.
#[test]
fn cluster_gauss_picker_threshold_exact() {
    use crate::r1cs_optimize::optimize_linear;

    fn build_and_optimize(n: usize) -> bool {
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let hot = cs.alloc_witness();
        let mut bots: Vec<Variable> = Vec::with_capacity(n);
        for _ in 0..n {
            bots.push(cs.alloc_witness());
        }
        for &b in &bots {
            cs.enforce_equal(make_lc_var(hot), make_lc_var(b));
        }
        let mut constraints = cs.constraints().to_vec();
        let (subs, _stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());
        // Returns true iff hot was substituted (max-frequency picker).
        subs.contains_key(&hot.index())
    }

    // 349 -> max-frequency -> hot substituted -> returns true
    assert!(
        build_and_optimize(349),
        "n=349 should use max-frequency (hot substituted)"
    );
    // 350 -> min-occurrence -> hot NOT substituted -> returns false
    assert!(
        !build_and_optimize(350),
        "n=350 should use min-occurrence (hot NOT substituted)"
    );
}

/// 20 linear constraints all sharing one anchor variable (a) collapse
/// completely under cluster-Gauss: 20 substitutions produced, no
/// duplicates in the substitution map, residual empty.
#[test]
fn cluster_gauss_high_degree_variable() {
    use crate::r1cs_optimize::linear_cluster::{build_clusters_by_signal, solve_cluster_linear};
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use std::collections::HashSet;

    let mut cs: ConstraintSystem = ConstraintSystem::new();
    let a = cs.alloc_witness();
    let mut bs: Vec<Variable> = Vec::with_capacity(20);
    for _ in 0..20 {
        bs.push(cs.alloc_witness());
    }
    // 20 constraints: a == b_i for i in 0..20.
    for &b in &bs {
        cs.enforce_equal(make_lc_var(a), make_lc_var(b));
    }

    let constraints: Vec<_> = cs.constraints().to_vec();
    let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
    let var_freq = compute_variable_frequency(&constraints);
    let clusters = build_clusters_by_signal(&constraints, &protected);

    // All 20 constraints share variable `a` -- one cluster of 20.
    assert_eq!(clusters.len(), 1);
    assert_eq!(clusters[0].len(), 20);

    let cluster_cons: Vec<_> = clusters[0]
        .iter()
        .map(|i| constraints[*i].clone())
        .collect();
    let mut inv_cache = rustc_hash::FxHashMap::default();
    let (subs, residual) = solve_cluster_linear::<memory::Bn254Fr>(
        cluster_cons,
        &protected,
        &var_freq,
        &mut inv_cache,
    );

    // 20 linear constraints over 21 variables (a + b0..b19) collapse
    // to 20 substitutions; the surviving variable is the one each
    // substitution chains to.
    assert_eq!(subs.len(), 20);
    assert!(
        residual.is_empty(),
        "residual should be empty, got {residual:?}"
    );

    // No substitution should reference itself (acyclic invariant).
    for (var_idx, expr) in &subs {
        for (term_var, _) in expr.terms() {
            assert_ne!(term_var.index(), *var_idx, "self-reference in subs map");
        }
    }
}
