use std::collections::HashMap;

use memory::FieldBackend;

use crate::passes::dense::{ConstIndex, DefIndex, DenseVarSet};
use crate::types::{Instruction, IrProgram, SsaVar};

use super::boolean::try_detect_boolean_enforcement;
use super::sum::try_extract_weighted_sum;

/// Result of the bit-pattern detection pass.
pub struct BitPatternResult {
    /// Inferred bitwidth bounds: variable → number of bits.
    pub bounds: HashMap<SsaVar, u32>,
    /// Number of boolean-enforced variables detected via `v*(v-1)=0`.
    pub booleans_detected: usize,
}

/// Detect Num2Bits-style bit patterns and return inferred bounds.
///
/// Takes the program and the set of already-proven booleans (from `bool_prop`).
/// Returns bounds that can be fed into `bound_inference` as `extra_bounds`.
pub fn detect_bit_patterns<F: FieldBackend>(
    program: &IrProgram<F>,
    proven_booleans: &DenseVarSet,
) -> BitPatternResult {
    let def_index = DefIndex::build(program);
    let const_index = ConstIndex::build(program);
    detect_bit_patterns_with(program, &def_index, &const_index, proven_booleans)
}

/// Core of [`detect_bit_patterns`] over caller-supplied indices, so
/// `optimize()` can share one defining-instruction/constant index build
/// with the boolean-propagation pass.
pub(crate) fn detect_bit_patterns_with<F: FieldBackend>(
    program: &IrProgram<F>,
    def_index: &DefIndex,
    const_index: &ConstIndex,
    proven_booleans: &DenseVarSet,
) -> BitPatternResult {
    // Step 1: Detect boolean-enforced variables via v*(v-1)=0 pattern
    let mut booleans = proven_booleans.clone();
    let mut new_booleans = 0usize;

    for inst in &program.instructions {
        if let Instruction::AssertEq { lhs, rhs, .. } = inst {
            // Pattern: AssertEq(Mul(v, Sub(v, 1)), 0)  — or symmetric
            if let Some(var) =
                try_detect_boolean_enforcement(*lhs, *rhs, program, def_index, const_index)
            {
                if booleans.insert(var) {
                    new_booleans += 1;
                }
            }
            if let Some(var) =
                try_detect_boolean_enforcement(*rhs, *lhs, program, def_index, const_index)
            {
                if booleans.insert(var) {
                    new_booleans += 1;
                }
            }
        }
    }

    // Step 2: Detect weighted boolean sums → infer bitwidth bounds
    let mut bounds: HashMap<SsaVar, u32> = HashMap::new();

    for inst in &program.instructions {
        if let Instruction::AssertEq { lhs, rhs, .. } = inst {
            // Try lhs as sum, rhs as target
            if let Some(n) =
                try_extract_weighted_sum(*lhs, program, def_index, const_index, &booleans)
            {
                merge_bound(&mut bounds, *rhs, n);
            }
            // Try rhs as sum, lhs as target
            if let Some(n) =
                try_extract_weighted_sum(*rhs, program, def_index, const_index, &booleans)
            {
                merge_bound(&mut bounds, *lhs, n);
            }
        }
    }

    BitPatternResult {
        bounds,
        booleans_detected: new_booleans,
    }
}
/// Merge a bound into the map, keeping the tightest (smallest) bound.
fn merge_bound(bounds: &mut HashMap<SsaVar, u32>, var: SsaVar, bits: u32) {
    let entry = bounds.entry(var).or_insert(bits);
    if bits < *entry {
        *entry = bits;
    }
}
