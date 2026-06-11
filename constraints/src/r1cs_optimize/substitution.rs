//! Substitution primitives shared by both optimizer passes.
//!
//! - [`apply_substitution`] rewrites an LC by replacing every
//!   mapped variable with its substitute.
//! - [`apply_substitution_to_constraint`] does the same for all
//!   three LCs inside a constraint.
//! - [`solve_for_variable`] picks the best candidate to substitute
//!   (most-connected non-protected wire, tie-break on highest
//!   index) and returns its expression.
//!
//! These are the workhorses of the O1 fixpoint loop in `linear.rs`
//! and of the composition step in `deduce::optimize_o2`. They have
//! no knowledge of constraints' algebraic shape — that lives in
//! `predicates`.

use std::collections::HashSet;

use rustc_hash::FxHashMap;

use memory::{FieldBackend, FieldElement};

use super::predicates::VarFreq;
use super::types::SubstitutionMap;
use crate::r1cs::{Constraint, LinearCombination, Variable};

/// Apply all substitutions in `subs` to a linear combination, in place.
///
/// For each term `(var, coeff)` in `lc`: if `var` is in `subs`, replace
/// the term with `coeff * subs[var]`. The historical
/// `apply_substitution(&LC, &subs) -> LC` was removed in the
/// allocation-cleanup pass; callers that needed a fresh LC now clone
/// before calling this in-place variant. The hot loop callers
/// (greedy O1's per-round constraint sweep, cluster-Gauss's
/// substitution propagation) already owned mutable LCs and had been
/// re-allocating result LCs every call; switching to in-place
/// mutation removed that allocator pressure entirely.
///
/// **Allocation profile:** one `mem::take` swap of the underlying
/// `Vec` (no allocation), plus a `Vec::reserve` if the rewritten
/// terms outgrow the original capacity, plus the in-place sort +
/// linear-merge in `simplify_in_place`. Zero allocations for
/// substitutions that do not expand any term.
pub(super) fn apply_substitution_in_place<F: FieldBackend>(
    lc: &mut LinearCombination<F>,
    subs: &SubstitutionMap<F>,
) {
    if subs.is_empty() || !lc_references_any_substitution_var(lc, subs) {
        return;
    }
    // Take ownership of the existing terms; we will rebuild into a
    // fresh `Vec`. We could in principle reuse the same `Vec` if no
    // substitution expands beyond one term, but the branch is rare
    // and the bookkeeping not worth it.
    let old_terms = std::mem::take(&mut lc.terms);
    lc.terms.reserve(old_terms.len());
    for (var, coeff) in old_terms {
        if let Some(replacement) = subs.get(&var.index()) {
            for (rep_var, rep_coeff) in replacement.terms() {
                lc.terms.push((*rep_var, coeff.mul(rep_coeff)));
            }
        } else {
            lc.terms.push((var, coeff));
        }
    }
    lc.simplify_in_place();
    // Replacement fill-in grows the vec while the merge in
    // `simplify_in_place` shrinks `len` back down; without a shrink the
    // post-substitution arms retain their worst-case capacity for the
    // rest of the optimizer's lifetime (measured ~2.7x slack across the
    // surviving set). Only shrink on real waste so the common
    // no-expansion case stays allocation-free.
    if lc.terms.capacity() > lc.terms.len().saturating_mul(2) {
        lc.terms.shrink_to_fit();
    }
}

fn lc_references_any_substitution_var<F: FieldBackend>(
    lc: &LinearCombination<F>,
    subs: &SubstitutionMap<F>,
) -> bool {
    lc.terms()
        .iter()
        .any(|(var, _)| subs.contains_key(&var.index()))
}

pub(super) fn constraint_references_any_substitution_var<F: FieldBackend>(
    constraint: &Constraint<F>,
    subs: &SubstitutionMap<F>,
) -> bool {
    constraint
        .a
        .terms()
        .iter()
        .chain(constraint.b.terms().iter())
        .chain(constraint.c.terms().iter())
        .any(|(var, _)| subs.contains_key(&var.index()))
}

/// Apply one `var_idx -> replacement` substitution to an LC.
///
/// Returns `false` without mutating when `lc` does not reference `var_idx`.
/// This avoids the `mem::take` + simplify path in cluster Gauss, where each
/// pivot substitutes exactly one variable but most rows in the cluster often
/// do not contain that pivot.
pub(super) fn apply_single_substitution_in_place<F: FieldBackend>(
    lc: &mut LinearCombination<F>,
    var_idx: usize,
    replacement: &LinearCombination<F>,
) -> bool {
    if !lc.terms.iter().any(|(var, _)| var.index() == var_idx) {
        return false;
    }

    let old_terms = std::mem::take(&mut lc.terms);
    lc.terms.reserve(old_terms.len());
    for (var, coeff) in old_terms {
        if var.index() == var_idx {
            for (rep_var, rep_coeff) in replacement.terms() {
                lc.terms.push((*rep_var, coeff.mul(rep_coeff)));
            }
        } else {
            lc.terms.push((var, coeff));
        }
    }
    lc.simplify_in_place();
    true
}

/// In-place variant of substitution for an entire constraint:
/// rewrites `constraint.{a,b,c}` against `subs` without allocating
/// new constraint or LC shells. Hot-loop callers (greedy O1's
/// per-round constraint sweep, cluster-Gauss's substitution
/// propagation) all use this; the historical by-value
/// `apply_substitution_to_constraint` was removed in the
/// allocation-cleanup pass.
pub(super) fn apply_substitution_to_constraint_in_place<F: FieldBackend>(
    constraint: &mut Constraint<F>,
    subs: &SubstitutionMap<F>,
) {
    if subs.is_empty() || !constraint_references_any_substitution_var(constraint, subs) {
        return;
    }
    apply_substitution_in_place(&mut constraint.a, subs);
    apply_substitution_in_place(&mut constraint.b, subs);
    apply_substitution_in_place(&mut constraint.c, subs);
}

/// Memoized field inversion. The pivot denominator `target_coeff.neg()`
/// repeats heavily across `solve_for_variable*` calls within one
/// `optimize_linear*` invocation: empirically 99.98% duplicate rate on
/// SHA-256(64) (10 unique values across 41540 inversions), 93–95% on
/// EdDSAPoseidon and SMTVerifier. Caching collapses the Fermat-LT
/// `pow(p-2)` chain (≈256 Montgomery muls each) to a hashmap lookup
/// for hits, leaving misses on the first occurrence of each value.
pub(super) type InvCache<F> = FxHashMap<FieldElement<F>, FieldElement<F>>;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SolveProfile {
    pub candidate_terms: usize,
    pub result_terms: usize,
    pub pivot_coeff_one: bool,
    pub pivot_coeff_neg_one: bool,
}

#[inline]
pub(super) fn cached_inv<F: FieldBackend>(
    cache: &mut InvCache<F>,
    value: FieldElement<F>,
) -> Option<FieldElement<F>> {
    if value == FieldElement::<F>::one() {
        return Some(value);
    }
    let neg_one = FieldElement::<F>::one().neg();
    if value == neg_one {
        return Some(neg_one);
    }
    if let Some(inv) = cache.get(&value) {
        return Some(*inv);
    }
    let inv = value.inv()?;
    cache.insert(value, inv);
    Some(inv)
}

/// Given an LC that must equal zero, solve for a non-protected variable.
///
/// E.g., for `3*x + 2*y - z + 5*ONE = 0`, solving for z gives:
/// `z = 3*x + 2*y + 5*ONE`.
///
/// Prefers the variable that appears in the most constraints (maximizes
/// propagation). Breaks ties by highest index (intermediate wires).
pub(super) fn solve_for_variable<F: FieldBackend>(
    lc: LinearCombination<F>,
    protected: &HashSet<usize>,
    var_freq: &VarFreq,
    inv_cache: &mut InvCache<F>,
) -> Option<(Variable, LinearCombination<F>)> {
    let simplified = lc.simplify();
    solve_for_variable_simplified(&simplified, protected, var_freq, inv_cache)
}

/// Like [`solve_for_variable`], but the caller has already simplified `lc`.
pub(super) fn solve_for_variable_simplified<F: FieldBackend>(
    simplified: &LinearCombination<F>,
    protected: &HashSet<usize>,
    var_freq: &VarFreq,
    inv_cache: &mut InvCache<F>,
) -> Option<(Variable, LinearCombination<F>)> {
    solve_for_variable_simplified_with_extra(simplified, protected, None, var_freq, inv_cache)
}

pub(super) fn solve_for_variable_simplified_with_extra<F: FieldBackend>(
    simplified: &LinearCombination<F>,
    protected: &HashSet<usize>,
    extra_protected: Option<&HashSet<usize>>,
    var_freq: &VarFreq,
    inv_cache: &mut InvCache<F>,
) -> Option<(Variable, LinearCombination<F>)> {
    let (target_var, target_coeff, _) =
        select_solve_target(simplified, protected, extra_protected, var_freq)?;
    let result = build_solve_result(simplified, target_var, target_coeff, inv_cache)?;
    Some((target_var, result))
}

pub(super) fn solve_for_variable_simplified_profiled<F: FieldBackend>(
    simplified: &LinearCombination<F>,
    protected: &HashSet<usize>,
    var_freq: &VarFreq,
    inv_cache: &mut InvCache<F>,
) -> Option<(Variable, LinearCombination<F>, SolveProfile)> {
    let (target_var, target_coeff, _) = select_solve_target(simplified, protected, None, var_freq)?;
    let result = build_solve_result(simplified, target_var, target_coeff, inv_cache)?;
    let one = FieldElement::<F>::one();
    let profile = SolveProfile {
        candidate_terms: simplified.terms().len(),
        result_terms: result.terms().len(),
        pivot_coeff_one: target_coeff == one,
        pivot_coeff_neg_one: target_coeff == one.neg(),
    };
    Some((target_var, result, profile))
}

fn select_solve_target<F: FieldBackend>(
    simplified: &LinearCombination<F>,
    protected: &HashSet<usize>,
    extra_protected: Option<&HashSet<usize>>,
    var_freq: &VarFreq,
) -> Option<(Variable, FieldElement<F>, usize)> {
    let mut best: Option<(Variable, FieldElement<F>, usize)> = None;
    for (var, coeff) in simplified.terms() {
        let var_idx = var.index();
        if var_idx == 0
            || protected.contains(&var_idx)
            || extra_protected.is_some_and(|extra| extra.contains(&var_idx))
        {
            continue; // Never substitute Variable::ONE
        }
        let freq = var_freq.get(var_idx);
        match &best {
            None => best = Some((*var, *coeff, freq)),
            Some((prev_var, _, prev_freq)) => {
                if freq > *prev_freq || (freq == *prev_freq && var_idx > prev_var.index()) {
                    best = Some((*var, *coeff, freq));
                }
            }
        }
    }

    best
}

fn build_solve_result<F: FieldBackend>(
    simplified: &LinearCombination<F>,
    target_var: Variable,
    target_coeff: FieldElement<F>,
    inv_cache: &mut InvCache<F>,
) -> Option<LinearCombination<F>> {
    // We need to compute: target_var = (-1/target_coeff) * (all other terms)
    let neg_inv = cached_inv(inv_cache, target_coeff.neg())?;

    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in simplified.terms() {
        if *var == target_var {
            continue;
        }
        result.add_term(*var, coeff.mul(&neg_inv));
    }

    Some(result)
}

/// Compose two substitution maps that were applied in sequence: `earlier`
/// first (the incremental-collapse pass folded during constraint
/// emission), then `later` (the batch finalize pass over the collapse
/// survivors). Returns a single map equivalent to applying `earlier` then
/// `later`, so one forward pass over the result reconstructs every
/// eliminated wire.
///
/// A wire eliminated by `earlier` is replaced by an LC over the collapse
/// survivors; some of those survivors may themselves be eliminated by
/// `later`, so `later` is substituted into each `earlier` replacement.
/// Wires eliminated by `later` keep their replacement verbatim.
///
/// Preconditions, both of which hold for collapse∘finalize:
/// - **Disjoint domains.** `later` runs on the survivors `earlier` kept,
///   and no survivor references an `earlier`-eliminated wire, so `later`
///   cannot re-eliminate a wire `earlier` already removed. Asserted (not
///   `debug_assert`): a silent overwrite here would drop a wire's
///   reconstruction and yield a witness that satisfies a forged proof.
/// - **Acyclic, with no cross-map back-edge.** Each input map's
///   key-dependency graph is a DAG (the finalize pass breaks any cycle its
///   batch eliminator introduces — see `flatten::resolve_cycles`), and no
///   `later` replacement references an `earlier`-eliminated wire (the same
///   disjointness), so the composed map is acyclic. Note the finalize map
///   is not necessarily fully canonical: it leaves a chained (but acyclic)
///   definition for any wire no surviving constraint references. Forward
///   reconstruction of such a chained wire is still correct because the
///   witness fixup runs only after a complete producing-op pre-fill has
///   already assigned every wire its honest value (see the fixup sites in
///   the witness generators), so single-pass arbitrary-order evaluation
///   reads honest values for the references it does not itself rewrite.
pub fn compose_substitution_maps<F: FieldBackend>(
    mut earlier: SubstitutionMap<F>,
    later: &SubstitutionMap<F>,
) -> SubstitutionMap<F> {
    for lc in earlier.values_mut() {
        apply_substitution_in_place(lc, later);
    }
    for (var_idx, lc) in later {
        let prev = earlier.insert(*var_idx, lc.clone());
        assert!(
            prev.is_none(),
            "compose_substitution_maps: overlapping domains at wire {var_idx} \
             (the finalize pass re-eliminated a wire the collapse pass already removed)"
        );
    }
    earlier
}
