use std::collections::HashSet;

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use memory::FieldBackend;

use super::{solve_cluster_linear, CLUSTER_FALLBACK_THRESHOLD};
use crate::r1cs::Constraint;
use crate::r1cs::Variable;
use crate::r1cs_optimize::linear::optimize_linear_with_protected;
use crate::r1cs_optimize::predicates::{is_linear, VarFreq};
use crate::r1cs_optimize::substitution::{apply_substitution_to_constraint_in_place, InvCache};
use crate::r1cs_optimize::types::SubstitutionMap;

const PARALLEL_SIGNAL_THRESHOLD: usize = 512;
const PARALLEL_SUBSTITUTION_THRESHOLD: usize = 512;

pub(super) struct SolvedCluster<F: FieldBackend> {
    pub(super) subs: SubstitutionMap<F>,
    pub(super) residual: Vec<Constraint<F>>,
    /// The cluster's pristine input rows, returned ONLY when the
    /// cluster yielded no substitutions. An all-empty (final) round
    /// restores them into the constraint set untouched; rounds that
    /// solved anything free them inside the solve instead.
    pub(super) unsolved_rows: Option<Vec<Constraint<F>>>,
    pub(super) fallback_len: usize,
    pub(super) fallback_rounds: usize,
}

pub(super) fn apply_substitutions_to_all_constraints<F: FieldBackend>(
    constraints: &mut [Constraint<F>],
    subs: &SubstitutionMap<F>,
) {
    if constraints.len() < PARALLEL_SUBSTITUTION_THRESHOLD {
        for constraint in constraints.iter_mut() {
            apply_substitution_to_constraint_in_place(constraint, subs);
        }
        return;
    }

    constraints.par_iter_mut().for_each(|constraint| {
        apply_substitution_to_constraint_in_place(constraint, subs);
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
    cluster_inputs: Vec<Vec<Constraint<F>>>,
    round_protected: &HashSet<usize>,
    var_freq: &VarFreq,
) -> Vec<SolvedCluster<F>> {
    if cluster_inputs.len() <= 1 {
        return cluster_inputs
            .into_iter()
            .map(|rows| solve_one_cluster(rows, round_protected, var_freq))
            .collect();
    }

    cluster_inputs
        .into_par_iter()
        .map(|rows| solve_one_cluster(rows, round_protected, var_freq))
        .collect()
}

fn solve_one_cluster<F: FieldBackend>(
    rows: Vec<Constraint<F>>,
    round_protected: &HashSet<usize>,
    var_freq: &VarFreq,
) -> SolvedCluster<F> {
    if rows.len() > CLUSTER_FALLBACK_THRESHOLD {
        // The greedy eliminator mutates its input into residual form,
        // so it runs on a copy; the pristine rows are kept only when
        // nothing was solved (the all-empty-round restore needs them)
        // and freed right here otherwise.
        let mut subset = rows.clone();
        let input_len = subset.len();
        let (subs, stats) = optimize_linear_with_protected(&mut subset, 0, round_protected);
        let unsolved_rows = if subs.is_empty() { Some(rows) } else { None };
        return SolvedCluster {
            subs,
            residual: subset,
            unsolved_rows,
            fallback_len: input_len,
            fallback_rounds: stats.rounds,
        };
    }

    let mut inv_cache: InvCache<F> = FxHashMap::default();
    let (subs, residual) = solve_cluster_linear(&rows, round_protected, var_freq, &mut inv_cache);
    let unsolved_rows = if subs.is_empty() { Some(rows) } else { None };
    SolvedCluster {
        subs,
        residual,
        unsolved_rows,
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

        let cluster_inputs: Vec<Vec<_>> = clusters
            .iter()
            .map(|cluster| cluster.iter().map(|&i| constraints[i].clone()).collect())
            .collect();
        let solved = solve_clusters_ordered(cluster_inputs, &protected, &var_freq);

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
    fn apply_substitutions_rewrites_every_constraint() {
        use crate::r1cs::LinearCombination;
        use memory::FieldElement;

        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        let z = cs.alloc_witness();
        cs.enforce_equal(make_lc_var(x), make_lc_var(y));
        cs.enforce_equal(make_lc_var(y), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let mut subs = SubstitutionMap::<Bn254Fr>::default();
        subs.insert(
            y.index(),
            LinearCombination::from_constant(FieldElement::from_u64(7)),
        );

        apply_substitutions_to_all_constraints(&mut constraints, &subs);

        for constraint in &constraints {
            assert!(
                constraint
                    .a
                    .terms()
                    .iter()
                    .chain(constraint.b.terms().iter())
                    .chain(constraint.c.terms().iter())
                    .all(|(var, _)| *var != y),
                "every reference to the substituted wire must be rewritten"
            );
        }
    }

    #[test]
    fn apply_substitutions_skips_untouched_constraints() {
        use crate::r1cs::LinearCombination;
        use memory::FieldElement;

        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        let z = cs.alloc_witness();
        let untouched = cs.alloc_witness();
        cs.enforce_equal(make_lc_var(x), make_lc_var(y));
        cs.enforce_equal(make_lc_var(untouched), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let before_untouched = constraints[1].clone();
        let mut subs = SubstitutionMap::<Bn254Fr>::default();
        subs.insert(
            y.index(),
            LinearCombination::from_constant(FieldElement::from_u64(7)),
        );

        apply_substitutions_to_all_constraints(&mut constraints, &subs);

        let touched_has_constant = constraints[0]
            .a
            .terms()
            .iter()
            .chain(constraints[0].b.terms().iter())
            .chain(constraints[0].c.terms().iter())
            .any(|(var, _)| *var == Variable::ONE);
        assert!(
            touched_has_constant,
            "touched constraint should receive the substitution"
        );
        assert_eq!(constraints[1].a.terms(), before_untouched.a.terms());
        assert_eq!(constraints[1].b.terms(), before_untouched.b.terms());
        assert_eq!(constraints[1].c.terms(), before_untouched.c.terms());
    }
}
