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

/// Apply all substitutions in `subs` to a linear combination.
///
/// For each term `(var, coeff)` in `lc`: if `var` is in `subs`, replace the
/// term with `coeff * subs[var]`. Returns the simplified result.
pub(super) fn apply_substitution<F: FieldBackend>(
    lc: &LinearCombination<F>,
    subs: &SubstitutionMap<F>,
) -> LinearCombination<F> {
    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in &lc.terms {
        if let Some(replacement) = subs.get(&var.index()) {
            // var -> replacement LC, scaled by coeff
            result = result + replacement.clone() * *coeff;
        } else {
            result.add_term(*var, *coeff);
        }
    }
    result.simplify()
}

/// Apply substitutions to all three LCs in a constraint.
pub(super) fn apply_substitution_to_constraint<F: FieldBackend>(
    constraint: &Constraint<F>,
    subs: &SubstitutionMap<F>,
) -> Constraint<F> {
    Constraint {
        a: apply_substitution(&constraint.a, subs),
        b: apply_substitution(&constraint.b, subs),
        c: apply_substitution(&constraint.c, subs),
    }
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
