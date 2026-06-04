//! Structural-parity fixture for the cluster-Gauss O1 path.
//!
//! Unlike `o1_rayon_parity` (whose linear constraints union into a
//! single >500 component that routes to the greedy *fallback*), this
//! fixture deliberately builds clusters in all three size bands so the
//! rewritten `solve_cluster_linear` + both pickers are exercised:
//!
//! - 60 small paths (size 5)  -> Gauss + MaxFrequency picker
//! - one medium path (size 400, in [350, 500)) -> Gauss + MinOccurrence picker
//! - one giant path (size 600, > 500) -> greedy fallback
//!
//! Each group also carries a non-linear `a*b=c` row referencing its
//! endpoints + the public input, so substitutions flow into residual
//! constraints and the structural hash is sensitive to any divergence
//! in either the substitution map or the surviving constraints.
//!
//! Emits a single FNV-1a hash over (stats, surviving constraints,
//! substitution map). Run on this branch and on a baseline tree; an
//! identical hash is bit-identical structural evidence (I1).

use constraints::r1cs::{Constraint, ConstraintSystem, LinearCombination, Variable};
use constraints::r1cs_optimize::optimize_linear;
use memory::{Bn254Fr, FieldElement};

type F = Bn254Fr;
type Fe = FieldElement<F>;
type Lc = LinearCombination<F>;

fn lc_var(var: Variable) -> Lc {
    Lc::from_variable(var)
}

fn lc_const(n: u64) -> Lc {
    Lc::from_constant(Fe::from_u64(n))
}

fn add_lc(acc: &mut u64, lc: &Lc) {
    let mut terms = lc.clone().simplify().into_terms();
    terms.sort_unstable_by_key(|(var, _)| var.index());
    add_usize(acc, terms.len());
    for (var, coeff) in terms {
        add_usize(acc, var.index());
        for byte in coeff.to_le_bytes() {
            add_byte(acc, byte);
        }
    }
}

fn add_constraint(acc: &mut u64, c: &Constraint<F>) {
    add_lc(acc, &c.a);
    add_lc(acc, &c.b);
    add_lc(acc, &c.c);
}

fn add_usize(acc: &mut u64, value: usize) {
    for byte in value.to_le_bytes() {
        add_byte(acc, byte);
    }
}

fn add_byte(acc: &mut u64, byte: u8) {
    *acc ^= byte as u64;
    *acc = acc.wrapping_mul(0x100000001b3);
}

/// Build a path of `links` equality constraints over `links + 1` fresh
/// witnesses, returning the endpoints. Each link adds a small constant
/// so the rows are non-trivial linear constraints.
fn push_path(cs: &mut ConstraintSystem<F>, links: usize, salt: u64) -> (Variable, Variable) {
    let mut path = Vec::with_capacity(links + 1);
    for _ in 0..=links {
        path.push(cs.alloc_witness());
    }
    for (i, window) in path.windows(2).enumerate() {
        let bump = (i as u64 + salt) % 7 + 1;
        cs.enforce_equal(lc_var(window[0]) + lc_const(bump), lc_var(window[1]));
    }
    (path[0], path[links])
}

fn build_fixture() -> (Vec<Constraint<F>>, usize) {
    let mut cs = ConstraintSystem::<F>::new();
    let public = cs.alloc_input();

    // Group 1: 60 small independent clusters (size 5) -> MaxFrequency.
    for g in 0..60u64 {
        let (head, tail) = push_path(&mut cs, 5, g);
        cs.enforce(lc_var(head), lc_var(tail), lc_var(public));
    }

    // Group 2: one medium cluster (size 400, in [350, 500)) -> MinOccurrence.
    {
        let (head, tail) = push_path(&mut cs, 400, 2);
        cs.enforce(lc_var(head), lc_var(tail), lc_var(public));
    }

    // Group 3: one giant cluster (size 600, > 500) -> greedy fallback.
    {
        let (head, tail) = push_path(&mut cs, 600, 3);
        cs.enforce(lc_var(head), lc_var(tail), lc_var(public));
    }

    (cs.constraints().to_vec(), cs.num_pub_inputs())
}

fn main() {
    let (mut constraints, public_inputs) = build_fixture();
    let (subs, stats) = optimize_linear(&mut constraints, public_inputs);

    let mut acc = 0xcbf29ce484222325;
    add_usize(&mut acc, stats.constraints_before);
    add_usize(&mut acc, stats.constraints_after);
    add_usize(&mut acc, stats.variables_eliminated);
    add_usize(&mut acc, stats.duplicates_removed);
    add_usize(&mut acc, stats.trivial_removed);
    add_usize(&mut acc, stats.rounds);
    for (linear, newly_linear) in stats.round_details {
        add_usize(&mut acc, linear);
        add_usize(&mut acc, newly_linear);
    }
    for c in &constraints {
        add_constraint(&mut acc, c);
    }
    // Sort the substitution map by key: FxHashMap iteration order is not
    // part of the structural contract, only the (key -> LC) relation is.
    let mut sub_pairs: Vec<(usize, &Lc)> = subs.iter().map(|(k, v)| (*k, v)).collect();
    sub_pairs.sort_unstable_by_key(|(k, _)| *k);
    for (var, lc) in sub_pairs {
        add_usize(&mut acc, var);
        add_lc(&mut acc, lc);
    }

    println!("{acc:016x}");
}
