//! Side-effect-free predicates + shape queries over `Constraint`
//! and `LinearCombination` used by both optimizer passes.
//!
//! - [`is_linear`] — rewrites a constraint into `k * LC_a = LC_c`
//!   form when one side is a scalar, including the `0 * B = C`
//!   zero-product case. Returns `None` for genuinely quadratic
//!   constraints.
//! - [`is_trivially_satisfied`] — catches tautologies left over
//!   after substitution (`0 * B = 0`, `k1 * k2 = k3` with
//!   `k1*k2 = k3`, and `k * LC = C` where `C == k*LC`).
//! - [`compute_variable_frequency`] — per-variable count across
//!   A/B/C, feeds the "substitute the most-connected variable"
//!   heuristic.
//! - [`lc_fingerprint`] — deterministic byte hash of a simplified
//!   LC; shared by dedup and the decompose-for-DEDUCE cache.
//!
//! All four are `pub(super)` because they're called from every
//! sibling submodule (`linear`, `deduce`, `substitution`) and
//! from `tests.rs`.

use std::collections::HashSet;

use rustc_hash::FxHashMap;

use memory::{FieldBackend, FieldElement};

use crate::r1cs::{Constraint, LinearCombination};

/// Check if a constraint is linear (one side is a constant).
///
/// Returns `Some((constant_value, other_lc, c_lc))` where the constraint
/// encodes `constant * other_lc = c_lc`. Returns `None` if both A and B
/// contain variables (genuinely quadratic).
///
/// Also handles the zero-product case: if A=0 or B=0, the constraint
/// reduces to `C = 0`, returned as `(1, zero_lc, c_lc)`.
pub(super) fn is_linear<F: FieldBackend>(
    constraint: &Constraint<F>,
) -> Option<(FieldElement<F>, LinearCombination<F>, LinearCombination<F>)> {
    let a_simplified = constraint.a.simplify();
    if let Some(k) = a_simplified.constant_value() {
        if !k.is_zero() {
            return Some((k, constraint.b.simplify(), constraint.c.simplify()));
        }
        // A = 0: constraint is 0 * B = C, i.e., C = 0
        // Encode as: 1 * 0 = C (so combined = C - 0 = C, solve for var in C)
        let c_simplified = constraint.c.simplify();
        if !c_simplified.terms.is_empty() {
            return Some((FieldElement::one(), LinearCombination::zero(), c_simplified));
        }
        // C is also zero → trivially satisfied, handled elsewhere
        return None;
    }
    let b_simplified = constraint.b.simplify();
    if let Some(k) = b_simplified.constant_value() {
        if !k.is_zero() {
            return Some((k, constraint.a.simplify(), constraint.c.simplify()));
        }
        // B = 0: constraint is A * 0 = C, i.e., C = 0
        let c_simplified = constraint.c.simplify();
        if !c_simplified.terms.is_empty() {
            return Some((FieldElement::one(), LinearCombination::zero(), c_simplified));
        }
        return None;
    }
    None
}

/// Count how many constraints each variable appears in (across A, B, C).
///
/// Returns an `FxHashMap` keyed by `var.index()`. Hot path: probed
/// per-term in `solve_for_variable`. The default `RandomState`/SipHash
/// hasher accounted for ~18 % of SMTVerifier(10) pipeline wall before
/// the switch.
pub(super) fn compute_variable_frequency<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> FxHashMap<usize, usize> {
    let mut freq: FxHashMap<usize, usize> = FxHashMap::default();
    for constraint in constraints {
        let mut vars_in_constraint: HashSet<usize> = HashSet::new();
        for (var, _) in &constraint.a.terms {
            vars_in_constraint.insert(var.index());
        }
        for (var, _) in &constraint.b.terms {
            vars_in_constraint.insert(var.index());
        }
        for (var, _) in &constraint.c.terms {
            vars_in_constraint.insert(var.index());
        }
        for var_idx in vars_in_constraint {
            *freq.entry(var_idx).or_insert(0) += 1;
        }
    }
    freq
}

/// Check if a constraint is trivially satisfied regardless of witness values.
///
/// Catches patterns after substitution:
/// - `0 * B = 0` or `A * 0 = 0` (zero product with zero C)
/// - `k1 * k2 = k3` where k1*k2 == k3 (fully constant, tautological)
/// - `k * LC = C` where C - k*LC simplifies to zero (tautological linear)
pub(super) fn is_trivially_satisfied<F: FieldBackend>(constraint: &Constraint<F>) -> bool {
    let a = constraint.a.simplify();
    let b = constraint.b.simplify();
    let c = constraint.c.simplify();

    // If A or B simplifies to zero, then A*B = 0, constraint holds iff C = 0
    if (a.terms.is_empty() || b.terms.is_empty()) && c.terms.is_empty() {
        return true;
    }

    // All three are constants: verify k_a * k_b == k_c
    if let (Some(ka), Some(kb), Some(kc)) =
        (a.constant_value(), b.constant_value(), c.constant_value())
    {
        return ka.mul(&kb) == kc;
    }

    // Tautological linear: k * LC = C where C == k*LC
    // This happens when variable substitution makes both sides identical.
    if let Some(ka) = a.constant_value() {
        if !ka.is_zero() {
            let diff = (c.clone() - b.clone() * ka).simplify();
            if diff.terms.is_empty() {
                return true;
            }
        }
    }
    if let Some(kb) = b.constant_value() {
        if !kb.is_zero() {
            let diff = (c - a * kb).simplify();
            if diff.terms.is_empty() {
                return true;
            }
        }
    }

    false
}

/// Hash a simplified linear combination into a deterministic byte vector.
pub(super) fn lc_fingerprint<F: FieldBackend>(lc: &LinearCombination<F>) -> Vec<u8> {
    let simplified = lc.simplify();
    let mut bytes = Vec::with_capacity(simplified.terms.len() * 40);
    for (var, coeff) in &simplified.terms {
        bytes.extend_from_slice(&var.index().to_le_bytes());
        for limb in coeff.to_canonical().iter() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}
