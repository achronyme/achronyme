//! Make surviving constraints reference no eliminated wire.
//!
//! The greedy eliminator (`linear::optimize_linear_with_protected`) picks
//! every pivot of a round from the original rows in one batch, so a value
//! `subs[k]` may reference another wire `j` eliminated the same round.
//! Applied one-pass, that leaves surviving constraints referencing
//! eliminated wires -- a dangling reference the verifier does not enforce,
//! which is forgeable (see `incremental.rs`). The Gauss path
//! (`linear_cluster::solve_cluster_linear`) avoids this by substituting
//! eagerly; the greedy batch does not.
//!
//! [`canonicalize_against_constraints`] closes it at the end of a driver:
//!
//! 1. **Break cycles.** A round's pivot order can chain wires into a cycle
//!    (`subs[a]` references `b`, `subs[b]` references `a`). The underlying
//!    rows are an ordinary coupled linear system `M x = b`; reduced-row-
//!    echelon over the field resolves each strongly connected component --
//!    pivot wires stay eliminated (expressed over the free wires + the rest
//!    of their row), free wires are reverted to survivors (a rank-deficient
//!    component genuinely does not determine them), and an all-zero row
//!    with a non-zero right-hand side is a constraint the deficiency
//!    exposes and is re-emitted. After this the substitution map is acyclic
//!    (its key-dependency graph is a DAG). See [`cycles`].
//!
//! 2. **Clean the survivors.** Only wires a surviving constraint actually
//!    references need a survivor-only definition. Those keys (and the
//!    acyclic closure they pull in) are flattened with memoization into a
//!    map local to the pass, then one pass over the constraints removes
//!    every eliminated wire. The substitution map itself keeps its chained
//!    definitions throughout: every consumer evaluates it in arbitrary
//!    order over a witness the op replay already filled with honest
//!    values, so a chained entry reconstructs the same value as a
//!    flattened one, and the flattened closure's term heap (multi-gigabyte
//!    at scale, roughly tripling the map) never outlives the apply pass.
//!
//! 3. **Budget the density.** Expanding a wide pivot copies its flattened
//!    form into every referencing survivor and into every flatten that
//!    consumes it, multiplying the surviving system's term count (and with
//!    it prover and keygen cost, which scale with matrix non-zeros). When
//!    the flatten's injected mass is large enough to matter, pivots whose
//!    expansion volume crosses a threshold are reverted to survivors
//!    instead: their defining row is re-emitted as an ordinary constraint
//!    (one copy of the form) and the wire leaves the substitution map.
//!    This trades a bounded number of extra constraints for a much
//!    sparser system; it cannot dangle anything (the wire becomes a
//!    survivor like any other, and its row is enforced by the verifier).

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use memory::{FieldBackend, FieldElement};

use super::substitution::apply_substitution_to_constraint_in_place;
use super::types::SubstitutionMap;
use crate::r1cs::{Constraint, LinearCombination, Variable};

mod cycles;

pub(super) use cycles::resolve_cycles;

const PARALLEL_CLEAN_THRESHOLD: usize = 512;

/// Revert a pivot to a survivor when its expansion volume
/// `(uses - 1) * flattened_size` reaches this many terms. `uses` counts
/// every copy site (term occurrences in surviving constraints plus
/// consumptions by other flatten builds); the `- 1` discounts the one
/// copy the re-emitted row itself carries, so a single-use pivot never
/// reverts (its expansion appears once either way and a revert would
/// only add a row). The score is a deliberately rough upper bound:
/// term cancellation shrinks realized expansion, and a consumption is
/// counted once per consuming build regardless of that build's own
/// fan-out. Only optimality is affected -- any revert set is sound.
const REVERT_SCORE_THRESHOLD: usize = 512;

/// The revert policy only engages when the flatten's total injected
/// mass (sum of `uses * flattened_size` over all flattened keys)
/// reaches this many terms. Below the floor the achievable savings are
/// small while the constraint-count cost is the same, and small and
/// mid-size circuits keep their exact constraint counts.
const REVERT_ACTIVATION_MASS: usize = 2_000_000;

/// Resolve cycles in `all_subs`, append any rows a rank-deficient cycle
/// exposes to `constraints`, rewrite `constraints` so none references an
/// eliminated wire, and re-emit the defining rows of pivots whose
/// expansion would blow up the surviving system's density. `all_subs`
/// stays a valid (acyclic) reconstruction map for the witness.
pub(super) fn canonicalize_against_constraints<F: FieldBackend>(
    all_subs: &mut SubstitutionMap<F>,
    constraints: &mut Vec<Constraint<F>>,
) {
    let leftovers = resolve_cycles(all_subs);
    constraints.extend(leftovers);
    clean_constraints(all_subs, constraints);

    debug_assert!(
        constraints
            .iter()
            .all(|c| !constraint_references_key(c, all_subs)),
        "no surviving constraint may reference an eliminated wire"
    );
}

fn constraint_references_key<F: FieldBackend>(
    constraint: &Constraint<F>,
    subs: &SubstitutionMap<F>,
) -> bool {
    [&constraint.a, &constraint.b, &constraint.c]
        .iter()
        .any(|lc| {
            lc.terms()
                .iter()
                .any(|(v, _)| subs.contains_key(&v.index()))
        })
}

/// Rewrite every constraint so it references only survivors. Flattens just
/// the keys constraints reach (memoized over the acyclic map) into a local
/// map and applies that once; `all_subs` itself is not rewritten. Pivots
/// the density budget reverts get their defining row appended and leave
/// the map.
fn clean_constraints<F: FieldBackend>(
    all_subs: &mut SubstitutionMap<F>,
    constraints: &mut Vec<Constraint<F>>,
) {
    let mut uses: FxHashMap<usize, usize> = FxHashMap::default();
    for c in constraints.iter() {
        for lc in [&c.a, &c.b, &c.c] {
            for (var, _) in lc.terms() {
                if all_subs.contains_key(&var.index()) {
                    *uses.entry(var.index()).or_insert(0) += 1;
                }
            }
        }
    }
    if uses.is_empty() {
        return;
    }
    let referenced: FxHashSet<usize> = uses.keys().copied().collect();

    let no_terminals = FxHashSet::default();
    let (flat, consumed) = flatten_referenced(&referenced, all_subs, &no_terminals);
    for (k, n) in consumed {
        *uses.entry(k).or_insert(0) += n;
    }

    // The flattened forms serve ONLY the apply pass and stay local.
    // Merging them into `all_subs` would triple the map's term heap
    // (the closure's flattened values dominate) for no consumer:
    // witness fixup evaluates the map in arbitrary order over a
    // witness the op replay already filled with honest values, so a
    // chained (unflattened) entry reconstructs the same value.
    let mass: usize = flat
        .iter()
        .map(|(k, lc)| uses.get(k).copied().unwrap_or(0) * lc.terms().len())
        .sum();
    let mut revert: Vec<usize> = if mass >= REVERT_ACTIVATION_MASS {
        flat.iter()
            .filter_map(|(k, lc)| {
                let u = uses.get(k).copied().unwrap_or(0);
                (u > 1 && (u - 1) * lc.terms().len() >= REVERT_SCORE_THRESHOLD).then_some(*k)
            })
            .collect()
    } else {
        Vec::new()
    };

    let apply_map = if revert.is_empty() {
        flat
    } else {
        // Re-flatten with the reverted pivots as terminals: a consumer
        // keeps the pivot as a single term (it is a survivor now), and
        // the pivots' own values are flattened for their re-emitted
        // rows. Decisions are not revisited against the shrunken
        // second-pass sizes -- an over-revert costs one extra row,
        // never soundness.
        drop(flat);
        let terminals: FxHashSet<usize> = revert.iter().copied().collect();
        let mut seeds: FxHashSet<usize> = referenced;
        seeds.extend(terminals.iter().copied());
        let (mut flat2, _) = flatten_referenced(&seeds, all_subs, &terminals);

        // Deterministic emission order; the rows reference only
        // survivors (and other reverted pivots, survivors themselves).
        revert.sort_unstable();
        for &k in &revert {
            let value = flat2.remove(&k).expect("reverted pivot was flattened");
            let mut row = LinearCombination::zero();
            row.add_term(Variable(k), FieldElement::<F>::one());
            for (var, coeff) in value.terms() {
                row.add_term(*var, coeff.neg());
            }
            row.simplify_in_place();
            constraints.push(Constraint {
                a: LinearCombination::from_constant(FieldElement::<F>::one()),
                b: row,
                c: LinearCombination::zero(),
            });
            all_subs.remove(&k);
        }
        flat2
    };

    if constraints.len() < PARALLEL_CLEAN_THRESHOLD {
        for c in constraints.iter_mut() {
            apply_substitution_to_constraint_in_place(c, &apply_map);
        }
    } else {
        constraints.par_iter_mut().for_each(|c| {
            apply_substitution_to_constraint_in_place(c, &apply_map);
        });
    }
}

/// Survivor-only flattening of every seed key and the acyclic closure it
/// reaches. Iterative post-order DFS (an explicit stack, not recursion, so
/// arbitrarily deep chains cannot overflow): a key stays on the stack while
/// its child keys resolve, so a value is built only once all the keys it
/// references are already flattened -- correct even when several keys share
/// a child. Keys in `terminals` are treated as survivors by consuming
/// builds (they contribute themselves as a single term), while still being
/// flattened in their own right when seeded.
///
/// Returns the `key -> survivor-only LC` map plus, per key, how many
/// builds consumed its flattened form (the expansion fan-in the density
/// budget scores).
fn flatten_referenced<F: FieldBackend>(
    seeds: &FxHashSet<usize>,
    all_subs: &SubstitutionMap<F>,
    terminals: &FxHashSet<usize>,
) -> (
    FxHashMap<usize, LinearCombination<F>>,
    FxHashMap<usize, usize>,
) {
    let mut flat: FxHashMap<usize, LinearCombination<F>> = FxHashMap::default();
    let mut consumed: FxHashMap<usize, usize> = FxHashMap::default();
    let mut expanded: FxHashSet<usize> = FxHashSet::default();
    let mut work: Vec<usize> = seeds.iter().copied().collect();
    while let Some(&k) = work.last() {
        if flat.contains_key(&k) {
            work.pop();
            continue;
        }
        if expanded.insert(k) {
            // First visit: queue the child keys above this key. Terminal
            // children stay plain terms, so their forms are not needed
            // here (they are seeded separately for their own rows).
            if let Some(raw) = all_subs.get(&k) {
                for (var, _) in raw.terms() {
                    let j = var.index();
                    if all_subs.contains_key(&j)
                        && !terminals.contains(&j)
                        && !flat.contains_key(&j)
                    {
                        work.push(j);
                    }
                }
            }
            continue;
        }
        // Second visit: every child key is flattened, build this key.
        work.pop();
        let mut out = LinearCombination::zero();
        if let Some(raw) = all_subs.get(&k) {
            for (var, coeff) in raw.terms() {
                match flat.get(&var.index()) {
                    Some(child) if !terminals.contains(&var.index()) => {
                        *consumed.entry(var.index()).or_insert(0) += 1;
                        for (sv, sc) in child.terms() {
                            out.add_term(*sv, coeff.mul(sc));
                        }
                    }
                    _ => out.add_term(*var, *coeff),
                }
            }
        }
        out.simplify_in_place();
        flat.insert(k, out);
    }
    (flat, consumed)
}
