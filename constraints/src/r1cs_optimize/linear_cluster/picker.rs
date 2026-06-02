use std::collections::HashSet;

use rustc_hash::FxHashMap;

use memory::{FieldBackend, FieldElement};

use super::{MIN_OCCURRENCE_LOWER, MIN_OCCURRENCE_UPPER};
use crate::r1cs::{LinearCombination, Variable};

use crate::r1cs_optimize::substitution::{cached_inv, solve_for_variable, InvCache};

/// Pivot variable selection strategy used by the per-cluster Gaussian
/// solver. Determined by cluster size: clusters in
/// `[MIN_OCCURRENCE_LOWER, MIN_OCCURRENCE_UPPER)` use
/// `MinOccurrence`, others use `MaxFrequency`. Mirrors circom 2.2.x
/// (`circom_algebra/src/simplification_utils.rs`):
/// `apply_less_ocurrences` switches to `take_signal_4` (min-occ)
/// inside the same band.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum Picker {
    MaxFrequency,
    MinOccurrence,
}

impl Picker {
    pub(super) fn for_cluster_size(size: usize) -> Self {
        if (MIN_OCCURRENCE_LOWER..MIN_OCCURRENCE_UPPER).contains(&size) {
            Picker::MinOccurrence
        } else {
            Picker::MaxFrequency
        }
    }
}

/// Pick a substitution variable from `lc` according to `picker`.
///
/// `MaxFrequency`: delegates to the existing
/// [`solve_for_variable`] -- pick the non-protected term with the
/// highest occurrence count, tie-break by highest index. This is the
/// achronyme-historical heuristic.
///
/// `MinOccurrence`: pick the non-protected term with the **lowest**
/// occurrence count, tie-break by **highest** index. Mirrors circom
/// 2.2.x's `take_signal_4`
/// (`circom_algebra/src/simplification_utils.rs:380`); the rationale
/// is that substituting a rarely-occurring variable propagates the
/// fewest changes, keeping subsequent rows shorter and reducing
/// overall fill-in.
pub(super) fn solve_for_variable_with_picker<F: FieldBackend>(
    lc: LinearCombination<F>,
    protected: &HashSet<usize>,
    var_freq: &FxHashMap<usize, usize>,
    picker: Picker,
    inv_cache: &mut InvCache<F>,
) -> Option<(Variable, LinearCombination<F>)> {
    match picker {
        Picker::MaxFrequency => solve_for_variable(lc, protected, var_freq, inv_cache),
        Picker::MinOccurrence => {
            let simplified = lc.simplify();
            let mut best: Option<(Variable, FieldElement<F>, usize)> = None;
            for (var, coeff) in simplified.terms() {
                if protected.contains(&var.index()) || var.index() == Variable::ONE.index() {
                    continue;
                }
                let freq = var_freq.get(&var.index()).copied().unwrap_or(0);
                match &best {
                    None => best = Some((*var, *coeff, freq)),
                    Some((prev_var, _, prev_freq)) => {
                        // pick MIN freq; tie-break by MAX index
                        if freq < *prev_freq
                            || (freq == *prev_freq && var.index() > prev_var.index())
                        {
                            best = Some((*var, *coeff, freq));
                        }
                    }
                }
            }
            let (target_var, target_coeff, _) = best?;
            let neg_inv = cached_inv(inv_cache, target_coeff.neg())?;
            let mut result = LinearCombination::<F>::zero();
            for (var, coeff) in simplified.terms() {
                if *var == target_var {
                    continue;
                }
                result.add_term(*var, coeff.mul(&neg_inv));
            }
            Some((target_var, result))
        }
    }
}
