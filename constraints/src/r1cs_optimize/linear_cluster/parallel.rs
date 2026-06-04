use std::collections::HashSet;

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use memory::FieldBackend;

use super::{solve_cluster_linear, CLUSTER_FALLBACK_THRESHOLD};
use crate::r1cs::Constraint;
use crate::r1cs::Variable;
use crate::r1cs_optimize::linear::optimize_linear_with_protected;
use crate::r1cs_optimize::predicates::is_linear;
use crate::r1cs_optimize::substitution::{apply_substitution_to_constraint_in_place, InvCache};
use crate::r1cs_optimize::types::SubstitutionMap;

const PARALLEL_SIGNAL_THRESHOLD: usize = 512;
const PARALLEL_SUBSTITUTION_THRESHOLD: usize = 512;

pub(super) struct SolvedCluster<F: FieldBackend> {
    pub(super) subs: SubstitutionMap<F>,
    pub(super) residual: Vec<Constraint<F>>,
    pub(super) fallback_len: usize,
    pub(super) fallback_rounds: usize,
}

pub(super) fn apply_substitutions_to_unmasked_constraints<F: FieldBackend>(
    constraints: &mut [Constraint<F>],
    skip_mask: &[bool],
    subs: &SubstitutionMap<F>,
) {
    debug_assert_eq!(constraints.len(), skip_mask.len());
    if constraints.len() < PARALLEL_SUBSTITUTION_THRESHOLD {
        for (constraint, skip) in constraints.iter_mut().zip(skip_mask) {
            if !*skip {
                apply_substitution_to_constraint_in_place(constraint, subs);
            }
        }
        return;
    }

    constraints
        .par_iter_mut()
        .zip(skip_mask.par_iter())
        .for_each(|(constraint, skip)| {
            if !*skip {
                apply_substitution_to_constraint_in_place(constraint, subs);
            }
        });
}

pub(super) fn linear_signal_entries_ordered<F: FieldBackend>(
    constraints: &[Constraint<F>],
    protected: &HashSet<usize>,
) -> Vec<(usize, Vec<usize>)> {
    if constraints.len() < PARALLEL_SIGNAL_THRESHOLD {
        return signal_entries_sequential(0, constraints, protected);
    }

    constraints
        .par_chunks(PARALLEL_SIGNAL_THRESHOLD)
        .enumerate()
        .map(|(chunk_idx, chunk)| {
            let base = chunk_idx * PARALLEL_SIGNAL_THRESHOLD;
            signal_entries_sequential(base, chunk, protected)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .collect()
}

fn signal_entries_sequential<F: FieldBackend>(
    base: usize,
    constraints: &[Constraint<F>],
    protected: &HashSet<usize>,
) -> Vec<(usize, Vec<usize>)> {
    let mut entries = Vec::new();
    for (offset, constraint) in constraints.iter().enumerate() {
        let Some((_k, other_lc, c_lc)) = is_linear(constraint) else {
            continue;
        };
        let mut seen: FxHashSet<usize> = FxHashSet::default();
        let mut signals = Vec::new();
        for (var, _coeff) in other_lc.terms().iter().chain(c_lc.terms().iter()) {
            let sig = var.index();
            if sig == Variable::ONE.index() || protected.contains(&sig) || !seen.insert(sig) {
                continue;
            }
            signals.push(sig);
        }
        if !signals.is_empty() {
            entries.push((base + offset, signals));
        }
    }
    entries
}

pub(super) fn solve_clusters_ordered<F: FieldBackend>(
    clusters: &[Vec<usize>],
    linear_constraints: &[Constraint<F>],
    round_protected: &HashSet<usize>,
    var_freq: &FxHashMap<usize, usize>,
) -> Vec<SolvedCluster<F>> {
    if clusters.len() <= 1 {
        return clusters
            .iter()
            .map(|cluster| {
                solve_one_cluster(cluster, linear_constraints, round_protected, var_freq)
            })
            .collect();
    }

    clusters
        .par_iter()
        .map(|cluster| solve_one_cluster(cluster, linear_constraints, round_protected, var_freq))
        .collect()
}

fn solve_one_cluster<F: FieldBackend>(
    cluster: &[usize],
    linear_constraints: &[Constraint<F>],
    round_protected: &HashSet<usize>,
    var_freq: &FxHashMap<usize, usize>,
) -> SolvedCluster<F> {
    let cluster_cons: Vec<Constraint<F>> = cluster
        .iter()
        .map(|&i| linear_constraints[i].clone())
        .collect();

    if cluster.len() > CLUSTER_FALLBACK_THRESHOLD {
        let mut subset = cluster_cons;
        let input_len = subset.len();
        let (subs, stats) = optimize_linear_with_protected(&mut subset, 0, round_protected);
        return SolvedCluster {
            subs,
            residual: subset,
            fallback_len: input_len,
            fallback_rounds: stats.rounds,
        };
    }

    let mut inv_cache: InvCache<F> = FxHashMap::default();
    let (subs, residual) =
        solve_cluster_linear(cluster_cons, round_protected, var_freq, &mut inv_cache);
    SolvedCluster {
        subs,
        residual,
        fallback_len: 0,
        fallback_rounds: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::ConstraintSystem;
    use crate::r1cs_optimize::linear_cluster::build_clusters_by_signal;
    use crate::r1cs_optimize::predicates::compute_variable_frequency;
    use crate::r1cs_optimize::tests::make_lc_var;
    use memory::Bn254Fr;

    #[test]
    fn solve_clusters_preserves_cluster_order() {
        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();
        let c = cs.alloc_witness();
        let d = cs.alloc_witness();

        cs.enforce_equal(make_lc_var(a), make_lc_var(b));
        cs.enforce_equal(make_lc_var(c), make_lc_var(d));

        let constraints = cs.constraints().to_vec();
        let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
        let clusters = build_clusters_by_signal(&constraints, &protected);
        let var_freq = compute_variable_frequency(&constraints);

        let solved = solve_clusters_ordered(&clusters, &constraints, &protected, &var_freq);

        assert_eq!(clusters.len(), 2);
        assert_eq!(solved.len(), 2);
        assert!(solved[0]
            .subs
            .keys()
            .all(|k| *k == a.index() || *k == b.index()));
        assert!(solved[1]
            .subs
            .keys()
            .all(|k| *k == c.index() || *k == d.index()));
    }

    #[test]
    fn signal_entries_keep_constraint_order() {
        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let public = cs.alloc_input();
        let mut vars = Vec::new();
        for _ in 0..(PARALLEL_SIGNAL_THRESHOLD + 3) {
            vars.push(cs.alloc_witness());
        }
        for window in vars.windows(2) {
            cs.enforce_equal(make_lc_var(window[0]), make_lc_var(window[1]));
        }
        cs.enforce_equal(make_lc_var(public), make_lc_var(vars[0]));

        let protected: HashSet<usize> = (0..=cs.num_pub_inputs()).collect();
        let entries = linear_signal_entries_ordered(cs.constraints(), &protected);

        assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(entries[0].0, 0);
        assert!(!entries.last().expect("entries").1.contains(&public.index()));
    }

    #[test]
    fn apply_substitutions_skips_masked_constraints() {
        use crate::r1cs::LinearCombination;
        use memory::FieldElement;

        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        let z = cs.alloc_witness();
        cs.enforce_equal(make_lc_var(x), make_lc_var(y));
        cs.enforce_equal(make_lc_var(y), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let before_masked = constraints[0].clone();
        let mut subs = SubstitutionMap::<Bn254Fr>::default();
        subs.insert(
            y.index(),
            LinearCombination::from_constant(FieldElement::from_u64(7)),
        );

        apply_substitutions_to_unmasked_constraints(&mut constraints, &[true, false], &subs);

        assert_eq!(
            constraints[0].b.terms(),
            before_masked.b.terms(),
            "masked constraint must stay byte-identical"
        );
        assert!(
            constraints[1]
                .a
                .terms()
                .iter()
                .any(|(var, _)| *var == Variable::ONE),
            "unmasked constraint should receive the substitution"
        );
    }
}
