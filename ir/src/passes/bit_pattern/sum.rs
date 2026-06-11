use std::collections::HashSet;

use memory::{FieldBackend, FieldElement};

use crate::passes::dense::{ConstIndex, DefIndex, DenseVarSet};
use crate::types::{Instruction, IrProgram, SsaVar};

/// Try to decompose a variable as a weighted sum of booleans with power-of-2 coefficients.
///
/// Returns `Some(n)` where n is the number of contiguous bits {0, 1, ..., n-1}.
pub(super) fn try_extract_weighted_sum<F: FieldBackend>(
    var: SsaVar,
    program: &IrProgram<F>,
    def_index: &DefIndex,
    const_index: &ConstIndex,
    booleans: &DenseVarSet,
) -> Option<u32> {
    let terms = decompose_sum(var, program, def_index, const_index, booleans)?;

    if terms.is_empty() {
        return None;
    }

    // Validate: all bit positions are distinct
    let mut positions: HashSet<u32> = HashSet::new();
    for &(_, pos) in &terms {
        if !positions.insert(pos) {
            return None; // duplicate position
        }
    }

    // Validate: positions form a contiguous range {0, 1, ..., n-1}
    let n = terms.len() as u32;
    let max_pos = positions.iter().copied().max().unwrap_or(0);
    if max_pos != n - 1 {
        return None; // gap in positions
    }
    // min must be 0
    let min_pos = positions.iter().copied().min().unwrap_or(1);
    if min_pos != 0 {
        return None;
    }

    Some(n)
}

/// Recursively decompose a variable into `(boolean_var, bit_position)` pairs.
///
/// - `Add(lhs, rhs)` → decompose both sides, concatenate
/// - `Mul(bool, const_pow2)` → `[(bool, log2(const))]`
/// - boolean variable directly → `[(var, 0)]` (implicit coefficient 1 = 2^0)
fn decompose_sum<F: FieldBackend>(
    var: SsaVar,
    program: &IrProgram<F>,
    def_index: &DefIndex,
    const_index: &ConstIndex,
    booleans: &DenseVarSet,
) -> Option<Vec<(SsaVar, u32)>> {
    let Some(inst) = def_index.get(program, var) else {
        // Not defined in this program — if it's boolean, treat as bit 0
        if booleans.contains(var) {
            return Some(vec![(var, 0)]);
        }
        return None;
    };

    match inst {
        Instruction::Add { lhs, rhs, .. } => {
            let mut left = decompose_sum(*lhs, program, def_index, const_index, booleans)?;
            let right = decompose_sum(*rhs, program, def_index, const_index, booleans)?;
            left.extend(right);
            Some(left)
        }
        Instruction::Mul { lhs, rhs, .. } => {
            // Case 1: lhs is boolean, rhs is const power-of-2
            if booleans.contains(*lhs) {
                if let Some(val) = const_index.get(program, *rhs) {
                    if let Some(exp) = is_power_of_two(val) {
                        return Some(vec![(*lhs, exp)]);
                    }
                }
            }
            // Case 2: rhs is boolean, lhs is const power-of-2
            if booleans.contains(*rhs) {
                if let Some(val) = const_index.get(program, *lhs) {
                    if let Some(exp) = is_power_of_two(val) {
                        return Some(vec![(*rhs, exp)]);
                    }
                }
            }
            None
        }
        Instruction::Const { value, .. } => {
            // A constant in the sum tree — only valid if it's zero (no contribution)
            if value.is_zero() {
                Some(vec![])
            } else {
                None
            }
        }
        _ => {
            // Leaf: if the variable itself is boolean, it contributes bit 0 (coeff = 1 = 2^0)
            if booleans.contains(var) {
                Some(vec![(var, 0)])
            } else {
                None
            }
        }
    }
}

/// Check if a field element is a power of 2, returning `Some(exponent)` if so.
///
/// Works generically over any `FieldBackend` using canonical limb representation.
pub(super) fn is_power_of_two<F: FieldBackend>(val: &FieldElement<F>) -> Option<u32> {
    if val.is_zero() {
        return None;
    }

    let limbs = val.to_canonical();

    for (limb_idx, &limb) in limbs.iter().enumerate() {
        if limb != 0 {
            // All subsequent limbs must be zero
            if limbs[limb_idx + 1..].iter().all(|&l| l == 0) && limb.is_power_of_two() {
                return Some(limb_idx as u32 * 64 + limb.trailing_zeros());
            }
            return None;
        }
    }

    None
}
