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

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

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
    if subs.is_empty() {
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
    apply_substitution_in_place(&mut constraint.a, subs);
    apply_substitution_in_place(&mut constraint.b, subs);
    apply_substitution_in_place(&mut constraint.c, subs);
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
    var_freq: &HashMap<usize, usize>,
) -> Option<(Variable, LinearCombination<F>)> {
    let simplified = lc.simplify();

    // Find the best candidate: most-frequent non-protected variable,
    // breaking ties by highest index.
    let mut best: Option<(Variable, FieldElement<F>, usize)> = None;
    for (var, coeff) in &simplified.terms {
        if protected.contains(&var.index()) {
            continue;
        }
        if var.index() == 0 {
            continue; // Never substitute Variable::ONE
        }
        let freq = var_freq.get(&var.index()).copied().unwrap_or(0);
        match &best {
            None => best = Some((*var, *coeff, freq)),
            Some((prev_var, _, prev_freq)) => {
                if freq > *prev_freq || (freq == *prev_freq && var.index() > prev_var.index()) {
                    best = Some((*var, *coeff, freq));
                }
            }
        }
    }

    let (target_var, target_coeff, _) = best?;

    // We need to compute: target_var = (-1/target_coeff) * (all other terms)
    let neg_inv = target_coeff.neg().inv()?;

    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in &simplified.terms {
        if *var == target_var {
            continue;
        }
        result.add_term(*var, coeff.mul(&neg_inv));
    }

    Some((target_var, result))
}
