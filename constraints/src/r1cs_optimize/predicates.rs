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

use std::sync::atomic::{AtomicU32, Ordering};

use rayon::prelude::*;
use rustc_hash::FxHashMap;

use memory::{FieldBackend, FieldElement};

use crate::r1cs::{Constraint, LinearCombination};

const PARALLEL_ANALYSIS_THRESHOLD: usize = 512;

/// Per-variable constraint-occurrence counts.
///
/// Replaces the historical `FxHashMap<usize, usize>`: the counts are
/// probed per-term inside every pivot selection, and at
/// multi-million-constraint scale the map's table alone held ~0.1 GB
/// across the round-1 transient. The full-system scan uses the dense
/// variant (4 B per allocated wire, probes without hashing); subset
/// scans (the greedy fallback's per-round recount over one cluster)
/// use the sparse variant, because a dense array would be sized by the
/// subset's MAX wire index — the full wire space — per inner round.
/// Counts are identical across variants (`u32` cannot overflow: a
/// variable appears in at most `constraints.len()` constraints).
#[derive(Clone)]
pub(super) enum VarFreq {
    Dense(Vec<u32>),
    Sparse(FxHashMap<usize, u32>),
}

impl VarFreq {
    /// Frequency-free instance for callers whose pivot choice must not
    /// depend on occurrence counts (every probe returns 0).
    pub(super) fn empty() -> Self {
        Self::Sparse(FxHashMap::default())
    }

    #[inline]
    pub(super) fn get(&self, var_idx: usize) -> usize {
        match self {
            Self::Dense(counts) => counts.get(var_idx).map(|c| *c as usize).unwrap_or(0),
            Self::Sparse(counts) => counts.get(&var_idx).map(|c| *c as usize).unwrap_or(0),
        }
    }
}

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
/// Hot path: probed per-term in `solve_for_variable`. The parallel
/// path uses one shared dense `AtomicU32` array with relaxed adds —
/// addition commutes, so the counts are exactly the sequential scan's.
pub(super) fn compute_variable_frequency<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> VarFreq {
    if constraints.len() >= PARALLEL_ANALYSIS_THRESHOLD {
        let max_idx = constraints
            .par_iter()
            .map(max_var_index)
            .reduce(|| 0, usize::max);
        let counts: Vec<AtomicU32> = (0..=max_idx).map(|_| AtomicU32::new(0)).collect();
        constraints
            .par_chunks(PARALLEL_ANALYSIS_THRESHOLD)
            .for_each(|chunk| {
                let mut vars_in_constraint = Vec::new();
                for constraint in chunk {
                    collect_constraint_vars(constraint, &mut vars_in_constraint);
                    for &var_idx in vars_in_constraint.iter() {
                        counts[var_idx].fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        return VarFreq::Dense(counts.into_iter().map(AtomicU32::into_inner).collect());
    }

    let mut counts: Vec<u32> = Vec::new();
    let mut vars_in_constraint = Vec::new();
    for constraint in constraints {
        collect_constraint_vars(constraint, &mut vars_in_constraint);
        for &var_idx in vars_in_constraint.iter() {
            if var_idx >= counts.len() {
                counts.resize(var_idx + 1, 0);
            }
            counts[var_idx] += 1;
        }
    }
    VarFreq::Dense(counts)
}

/// Sparse-table variant of [`compute_variable_frequency`] for SUBSET
/// scans, where the table should be sized by the subset's distinct
/// variables rather than the full wire space.
pub(super) fn compute_variable_frequency_sparse<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> VarFreq {
    let mut counts: FxHashMap<usize, u32> = FxHashMap::default();
    let mut vars_in_constraint = Vec::new();
    for constraint in constraints {
        collect_constraint_vars(constraint, &mut vars_in_constraint);
        for &var_idx in vars_in_constraint.iter() {
            *counts.entry(var_idx).or_insert(0) += 1;
        }
    }
    VarFreq::Sparse(counts)
}

fn max_var_index<F: FieldBackend>(constraint: &Constraint<F>) -> usize {
    constraint
        .a
        .terms
        .iter()
        .chain(constraint.b.terms.iter())
        .chain(constraint.c.terms.iter())
        .map(|(var, _)| var.index())
        .max()
        .unwrap_or(0)
}

/// Distinct variable indices of a constraint (each counted once even
/// when it appears in several arms), collected into the reusable
/// scratch vec.
fn collect_constraint_vars<F: FieldBackend>(
    constraint: &Constraint<F>,
    vars_in_constraint: &mut Vec<usize>,
) {
    vars_in_constraint.clear();
    vars_in_constraint.extend(constraint.a.terms.iter().map(|(var, _)| var.index()));
    vars_in_constraint.extend(constraint.b.terms.iter().map(|(var, _)| var.index()));
    vars_in_constraint.extend(constraint.c.terms.iter().map(|(var, _)| var.index()));
    vars_in_constraint.sort_unstable();
    vars_in_constraint.dedup();
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

pub(super) fn retain_nontrivial_constraints<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
) -> usize {
    let before = constraints.len();
    if before < PARALLEL_ANALYSIS_THRESHOLD {
        constraints.retain(|c| !is_trivially_satisfied(c));
        return before - constraints.len();
    }

    let keep: Vec<bool> = constraints
        .par_iter()
        .map(|c| !is_trivially_satisfied(c))
        .collect();
    let mut write = 0usize;
    for (read, keep_constraint) in keep.into_iter().enumerate() {
        if !keep_constraint {
            continue;
        }
        if write != read {
            constraints.swap(write, read);
        }
        write += 1;
    }
    constraints.truncate(write);
    before - constraints.len()
}

pub(super) fn count_nonlinear_constraints<F: FieldBackend>(constraints: &[Constraint<F>]) -> usize {
    if constraints.len() < PARALLEL_ANALYSIS_THRESHOLD {
        return constraints
            .iter()
            .filter(|constraint| is_linear(constraint).is_none())
            .count();
    }

    constraints
        .par_iter()
        .filter(|constraint| is_linear(constraint).is_none())
        .count()
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

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::r1cs::Variable;

    fn lc(indices: &[usize]) -> LinearCombination<Bn254Fr> {
        let mut lc = LinearCombination::zero();
        for &idx in indices {
            lc.add_term(Variable(idx), FieldElement::one());
        }
        lc
    }

    #[test]
    fn variable_frequency_counts_each_constraint_once() {
        let constraints = vec![
            Constraint {
                a: lc(&[1, 1]),
                b: lc(&[1, 2]),
                c: lc(&[2, 0]),
            },
            Constraint {
                a: lc(&[1]),
                b: LinearCombination::zero(),
                c: LinearCombination::zero(),
            },
        ];

        let freq = compute_variable_frequency(&constraints);

        assert_eq!(freq.get(0), 1);
        assert_eq!(freq.get(1), 2);
        assert_eq!(freq.get(2), 1);
    }
}
