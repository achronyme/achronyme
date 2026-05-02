//! Bit-pattern bound inference: detects Num2Bits-style patterns in the IR
//! and infers bitwidth bounds for variables constrained by weighted boolean sums.
//!
//! ## What it detects
//!
//! When circom's `Num2Bits(n)` is inlined, it produces:
//! 1. Boolean enforcement: `bit_i * (bit_i - 1) = 0` for each bit
//! 2. Sum check: `bit_0 * 1 + bit_1 * 2 + ... + bit_{n-1} * 2^{n-1} = input`
//!
//! This pass recognizes these patterns and infers that `input` fits in `n` bits,
//! enabling downstream `IsLt`/`IsLe` to use bounded decomposition instead of
//! full 252-bit (~761 constraints per comparison).
//!
//! ## Security
//!
//! Safe-by-default: if detection fails, no bound is inferred and comparisons
//! remain unbounded (correct but more constraints). Boolean detection is sound
//! over prime fields: `v*(v-1) = 0` has exactly two solutions {0, 1}.

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar};

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
    proven_booleans: &HashSet<SsaVar>,
) -> BitPatternResult {
    // Build definition map: SsaVar → &Instruction
    let def_map: HashMap<SsaVar, &Instruction<F>> = program
        .instructions
        .iter()
        .map(|inst| (inst.result_var(), inst))
        .collect();

    // Build constants map: SsaVar → FieldElement value (for Const instructions)
    let constants: HashMap<SsaVar, &FieldElement<F>> = program
        .instructions
        .iter()
        .filter_map(|inst| {
            if let Instruction::Const { result, value } = inst {
                Some((*result, value))
            } else {
                None
            }
        })
        .collect();

    // Step 1: Detect boolean-enforced variables via v*(v-1)=0 pattern
    let mut booleans: HashSet<SsaVar> = proven_booleans.clone();
    let mut new_booleans = 0usize;

    for inst in &program.instructions {
        if let Instruction::AssertEq { lhs, rhs, .. } = inst {
            // Pattern: AssertEq(Mul(v, Sub(v, 1)), 0)  — or symmetric
            if let Some(var) = try_detect_boolean_enforcement(*lhs, *rhs, &def_map, &constants) {
                if booleans.insert(var) {
                    new_booleans += 1;
                }
            }
            if let Some(var) = try_detect_boolean_enforcement(*rhs, *lhs, &def_map, &constants) {
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
            if let Some(n) = try_extract_weighted_sum(*lhs, &def_map, &constants, &booleans) {
                merge_bound(&mut bounds, *rhs, n);
            }
            // Try rhs as sum, lhs as target
            if let Some(n) = try_extract_weighted_sum(*rhs, &def_map, &constants, &booleans) {
                merge_bound(&mut bounds, *lhs, n);
            }
        }
    }

    BitPatternResult {
        bounds,
        booleans_detected: new_booleans,
    }
}

/// Try to detect `v*(v-1) = 0` boolean enforcement.
///
/// `mul_side` should be the side that might be `Mul(v, Sub(v, 1))`,
/// `zero_side` should be `Const(0)`.
fn try_detect_boolean_enforcement<F: FieldBackend>(
    mul_side: SsaVar,
    zero_side: SsaVar,
    def_map: &HashMap<SsaVar, &Instruction<F>>,
    constants: &HashMap<SsaVar, &FieldElement<F>>,
) -> Option<SsaVar> {
    // zero_side must be Const(0)
    let zero_val = constants.get(&zero_side)?;
    if !zero_val.is_zero() {
        return None;
    }

    // mul_side must be Mul(a, b)
    let mul_inst = def_map.get(&mul_side)?;
    let (a, b) = match mul_inst {
        Instruction::Mul { lhs, rhs, .. } => (*lhs, *rhs),
        _ => return None,
    };

    // One of (a, b) must be Sub(c, Const(1)) where c == the other operand.
    // Check b = Sub(a, 1)
    if is_sub_one(b, a, def_map, constants) {
        return Some(a);
    }
    // Check a = Sub(b, 1)
    if is_sub_one(a, b, def_map, constants) {
        return Some(b);
    }

    None
}

/// Check if `var` is defined as `Sub(expected_base, Const(1))`.
fn is_sub_one<F: FieldBackend>(
    var: SsaVar,
    expected_base: SsaVar,
    def_map: &HashMap<SsaVar, &Instruction<F>>,
    constants: &HashMap<SsaVar, &FieldElement<F>>,
) -> bool {
    let Some(inst) = def_map.get(&var) else {
        return false;
    };
    match inst {
        Instruction::Sub { lhs, rhs, .. } => {
            if *lhs != expected_base {
                return false;
            }
            let Some(val) = constants.get(rhs) else {
                return false;
            };
            **val == FieldElement::<F>::one()
        }
        _ => false,
    }
}

/// Try to decompose a variable as a weighted sum of booleans with power-of-2 coefficients.
///
/// Returns `Some(n)` where n is the number of contiguous bits {0, 1, ..., n-1}.
fn try_extract_weighted_sum<F: FieldBackend>(
    var: SsaVar,
    def_map: &HashMap<SsaVar, &Instruction<F>>,
    constants: &HashMap<SsaVar, &FieldElement<F>>,
    booleans: &HashSet<SsaVar>,
) -> Option<u32> {
    let terms = decompose_sum(var, def_map, constants, booleans)?;

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
    def_map: &HashMap<SsaVar, &Instruction<F>>,
    constants: &HashMap<SsaVar, &FieldElement<F>>,
    booleans: &HashSet<SsaVar>,
) -> Option<Vec<(SsaVar, u32)>> {
    let Some(inst) = def_map.get(&var) else {
        // Not defined in this program — if it's boolean, treat as bit 0
        if booleans.contains(&var) {
            return Some(vec![(var, 0)]);
        }
        return None;
    };

    match inst {
        Instruction::Add { lhs, rhs, .. } => {
            let mut left = decompose_sum(*lhs, def_map, constants, booleans)?;
            let right = decompose_sum(*rhs, def_map, constants, booleans)?;
            left.extend(right);
            Some(left)
        }
        Instruction::Mul { lhs, rhs, .. } => {
            // Case 1: lhs is boolean, rhs is const power-of-2
            if booleans.contains(lhs) {
                if let Some(val) = constants.get(rhs) {
                    if let Some(exp) = is_power_of_two(val) {
                        return Some(vec![(*lhs, exp)]);
                    }
                }
            }
            // Case 2: rhs is boolean, lhs is const power-of-2
            if booleans.contains(rhs) {
                if let Some(val) = constants.get(lhs) {
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
            if booleans.contains(&var) {
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
fn is_power_of_two<F: FieldBackend>(val: &FieldElement<F>) -> Option<u32> {
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

/// Merge a bound into the map, keeping the tightest (smallest) bound.
fn merge_bound(bounds: &mut HashMap<SsaVar, u32>, var: SsaVar, bits: u32) {
    let entry = bounds.entry(var).or_insert(bits);
    if bits < *entry {
        *entry = bits;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IrProgram, Visibility};

    /// Helper: build a Num2Bits(n) pattern in IR.
    ///
    /// Creates n boolean-enforced bits and a weighted sum asserting:
    ///   bit_0 * 1 + bit_1 * 2 + ... + bit_{n-1} * 2^{n-1} = input
    fn make_num2bits_program(n: u32) -> (IrProgram, SsaVar) {
        let mut p: IrProgram = IrProgram::new();

        // Input signal
        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        // Constant 1 (for Sub(bit, 1))
        let const_one = p.fresh_var();
        p.push(Instruction::Const {
            result: const_one,
            value: FieldElement::one(),
        });

        // Constant 0 (for AssertEq(..., 0))
        let const_zero = p.fresh_var();
        p.push(Instruction::Const {
            result: const_zero,
            value: FieldElement::zero(),
        });

        let mut bit_vars = Vec::new();

        // For each bit: create boolean enforcement v*(v-1)=0
        for _ in 0..n {
            let bit = p.fresh_var(); // the bit variable (witness)
            p.push(Instruction::Input {
                result: bit,
                name: "bit".into(),
                visibility: Visibility::Witness,
            });

            // Sub(bit, 1)
            let sub_result = p.fresh_var();
            p.push(Instruction::Sub {
                result: sub_result,
                lhs: bit,
                rhs: const_one,
            });

            // Mul(bit, sub_result) = bit * (bit - 1)
            let mul_result = p.fresh_var();
            p.push(Instruction::Mul {
                result: mul_result,
                lhs: bit,
                rhs: sub_result,
            });

            // AssertEq(mul_result, 0)
            let assert_result = p.fresh_var();
            p.push(Instruction::AssertEq {
                result: assert_result,
                lhs: mul_result,
                rhs: const_zero,
                message: None,
            });

            bit_vars.push(bit);
        }

        // Build weighted sum: bit_0 * 2^0 + bit_1 * 2^1 + ... + bit_{n-1} * 2^{n-1}
        // Start with bit_0 * 1 (= bit_0 * 2^0)
        let coeff_0 = p.fresh_var();
        p.push(Instruction::Const {
            result: coeff_0,
            value: FieldElement::from_u64(1),
        });
        let mut sum = p.fresh_var();
        p.push(Instruction::Mul {
            result: sum,
            lhs: bit_vars[0],
            rhs: coeff_0,
        });

        for i in 1..n {
            let coeff = p.fresh_var();
            p.push(Instruction::Const {
                result: coeff,
                value: FieldElement::from_u64(1u64 << i),
            });
            let term = p.fresh_var();
            p.push(Instruction::Mul {
                result: term,
                lhs: bit_vars[i as usize],
                rhs: coeff,
            });
            let new_sum = p.fresh_var();
            p.push(Instruction::Add {
                result: new_sum,
                lhs: sum,
                rhs: term,
            });
            sum = new_sum;
        }

        // AssertEq(sum, input)
        let assert_sum = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_sum,
            lhs: sum,
            rhs: input,
            message: None,
        });

        (p, input)
    }

    #[test]
    fn num2bits_3_detects_3bit_bound() {
        let (program, input) = make_num2bits_program(3);
        let booleans = HashSet::new();
        let result = detect_bit_patterns(&program, &booleans);

        assert_eq!(result.booleans_detected, 3);
        assert_eq!(result.bounds.get(&input), Some(&3));
    }

    #[test]
    fn num2bits_8_detects_8bit_bound() {
        let (program, input) = make_num2bits_program(8);
        let booleans = HashSet::new();
        let result = detect_bit_patterns(&program, &booleans);

        assert_eq!(result.booleans_detected, 8);
        assert_eq!(result.bounds.get(&input), Some(&8));
    }

    #[test]
    fn no_false_positive_without_boolean_enforcement() {
        // Weighted sum without boolean enforcement → should not infer bounds
        let mut p: IrProgram = IrProgram::new();
        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        let bit0 = p.fresh_var();
        p.push(Instruction::Input {
            result: bit0,
            name: "b0".into(),
            visibility: Visibility::Witness,
        });
        let bit1 = p.fresh_var();
        p.push(Instruction::Input {
            result: bit1,
            name: "b1".into(),
            visibility: Visibility::Witness,
        });

        let c1 = p.fresh_var();
        p.push(Instruction::Const {
            result: c1,
            value: FieldElement::from_u64(1),
        });
        let c2 = p.fresh_var();
        p.push(Instruction::Const {
            result: c2,
            value: FieldElement::from_u64(2),
        });

        let t0 = p.fresh_var();
        p.push(Instruction::Mul {
            result: t0,
            lhs: bit0,
            rhs: c1,
        });
        let t1 = p.fresh_var();
        p.push(Instruction::Mul {
            result: t1,
            lhs: bit1,
            rhs: c2,
        });
        let sum = p.fresh_var();
        p.push(Instruction::Add {
            result: sum,
            lhs: t0,
            rhs: t1,
        });
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: sum,
            rhs: input,
            message: None,
        });

        let booleans = HashSet::new();
        let result = detect_bit_patterns(&p, &booleans);
        assert!(result.bounds.is_empty());
    }

    #[test]
    fn no_false_positive_non_power_of_2_coefficients() {
        // Boolean-enforced vars but coefficient 3 (not power of 2)
        let mut p: IrProgram = IrProgram::new();
        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        let const_one = p.fresh_var();
        p.push(Instruction::Const {
            result: const_one,
            value: FieldElement::one(),
        });
        let const_zero = p.fresh_var();
        p.push(Instruction::Const {
            result: const_zero,
            value: FieldElement::zero(),
        });

        // bit0: boolean enforced
        let bit0 = p.fresh_var();
        p.push(Instruction::Input {
            result: bit0,
            name: "b0".into(),
            visibility: Visibility::Witness,
        });
        let sub0 = p.fresh_var();
        p.push(Instruction::Sub {
            result: sub0,
            lhs: bit0,
            rhs: const_one,
        });
        let mul0 = p.fresh_var();
        p.push(Instruction::Mul {
            result: mul0,
            lhs: bit0,
            rhs: sub0,
        });
        let a0 = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: a0,
            lhs: mul0,
            rhs: const_zero,
            message: None,
        });

        // bit0 * 3 (not a power of 2!)
        let c3 = p.fresh_var();
        p.push(Instruction::Const {
            result: c3,
            value: FieldElement::from_u64(3),
        });
        let term = p.fresh_var();
        p.push(Instruction::Mul {
            result: term,
            lhs: bit0,
            rhs: c3,
        });
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: term,
            rhs: input,
            message: None,
        });

        let booleans = HashSet::new();
        let result = detect_bit_patterns(&p, &booleans);
        // Should not infer a bound (coeff 3 is not power of 2 → decomposition fails)
        assert!(result.bounds.is_empty());
    }

    #[test]
    fn commuted_mul_operands() {
        // Mul(Sub(v, 1), v) instead of Mul(v, Sub(v, 1))
        let mut p: IrProgram = IrProgram::new();

        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        let const_one = p.fresh_var();
        p.push(Instruction::Const {
            result: const_one,
            value: FieldElement::one(),
        });
        let const_zero = p.fresh_var();
        p.push(Instruction::Const {
            result: const_zero,
            value: FieldElement::zero(),
        });

        let bit = p.fresh_var();
        p.push(Instruction::Input {
            result: bit,
            name: "bit".into(),
            visibility: Visibility::Witness,
        });

        // Sub(bit, 1)
        let sub_r = p.fresh_var();
        p.push(Instruction::Sub {
            result: sub_r,
            lhs: bit,
            rhs: const_one,
        });

        // COMMUTED: Mul(sub_r, bit) instead of Mul(bit, sub_r)
        let mul_r = p.fresh_var();
        p.push(Instruction::Mul {
            result: mul_r,
            lhs: sub_r,
            rhs: bit,
        });

        // AssertEq(mul_r, 0)
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: mul_r,
            rhs: const_zero,
            message: None,
        });

        // Weighted sum: bit * 1 = input
        let c1 = p.fresh_var();
        p.push(Instruction::Const {
            result: c1,
            value: FieldElement::from_u64(1),
        });
        let term = p.fresh_var();
        p.push(Instruction::Mul {
            result: term,
            lhs: bit,
            rhs: c1,
        });
        let assert_sum = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_sum,
            lhs: term,
            rhs: input,
            message: None,
        });

        let booleans = HashSet::new();
        let result = detect_bit_patterns(&p, &booleans);
        assert_eq!(result.booleans_detected, 1);
        assert_eq!(result.bounds.get(&input), Some(&1));
    }

    #[test]
    fn symmetric_assert_eq() {
        // AssertEq(0, mul_result) instead of AssertEq(mul_result, 0)
        let mut p: IrProgram = IrProgram::new();

        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        let const_one = p.fresh_var();
        p.push(Instruction::Const {
            result: const_one,
            value: FieldElement::one(),
        });
        let const_zero = p.fresh_var();
        p.push(Instruction::Const {
            result: const_zero,
            value: FieldElement::zero(),
        });

        let bit = p.fresh_var();
        p.push(Instruction::Input {
            result: bit,
            name: "bit".into(),
            visibility: Visibility::Witness,
        });
        let sub_r = p.fresh_var();
        p.push(Instruction::Sub {
            result: sub_r,
            lhs: bit,
            rhs: const_one,
        });
        let mul_r = p.fresh_var();
        p.push(Instruction::Mul {
            result: mul_r,
            lhs: bit,
            rhs: sub_r,
        });

        // SWAPPED: AssertEq(0, mul_result) — zero on the left
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: const_zero,
            rhs: mul_r,
            message: None,
        });

        // Weighted sum: bit * 1 = input (also swapped: AssertEq(input, sum))
        let c1 = p.fresh_var();
        p.push(Instruction::Const {
            result: c1,
            value: FieldElement::from_u64(1),
        });
        let term = p.fresh_var();
        p.push(Instruction::Mul {
            result: term,
            lhs: bit,
            rhs: c1,
        });
        let assert_sum = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_sum,
            lhs: input,
            rhs: term,
            message: None,
        });

        let booleans = HashSet::new();
        let result = detect_bit_patterns(&p, &booleans);
        assert_eq!(result.booleans_detected, 1);
        assert_eq!(result.bounds.get(&input), Some(&1));
    }

    #[test]
    fn single_bit_pattern() {
        // Num2Bits(1): single boolean with coefficient 2^0 = 1
        let (program, input) = make_num2bits_program(1);
        let booleans = HashSet::new();
        let result = detect_bit_patterns(&program, &booleans);

        assert_eq!(result.booleans_detected, 1);
        assert_eq!(result.bounds.get(&input), Some(&1));
    }

    #[test]
    fn integration_with_bool_prop_booleans() {
        // Use pre-proven booleans from bool_prop (e.g., comparison results)
        // instead of v*(v-1)=0 enforcement
        let mut p: IrProgram = IrProgram::new();

        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        // Two bits that are results of comparisons (proven boolean by bool_prop)
        let bit0 = p.fresh_var();
        let dummy0 = p.fresh_var();
        let dummy1 = p.fresh_var();
        p.push(Instruction::Input {
            result: dummy0,
            name: "d0".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::Input {
            result: dummy1,
            name: "d1".into(),
            visibility: Visibility::Witness,
        });
        p.push(Instruction::IsEq {
            result: bit0,
            lhs: dummy0,
            rhs: dummy1,
        });

        let bit1 = p.fresh_var();
        p.push(Instruction::IsEq {
            result: bit1,
            lhs: dummy0,
            rhs: dummy1,
        });

        // Weighted sum: bit0 * 1 + bit1 * 2 = input
        let c1 = p.fresh_var();
        p.push(Instruction::Const {
            result: c1,
            value: FieldElement::from_u64(1),
        });
        let c2 = p.fresh_var();
        p.push(Instruction::Const {
            result: c2,
            value: FieldElement::from_u64(2),
        });

        let t0 = p.fresh_var();
        p.push(Instruction::Mul {
            result: t0,
            lhs: bit0,
            rhs: c1,
        });
        let t1 = p.fresh_var();
        p.push(Instruction::Mul {
            result: t1,
            lhs: bit1,
            rhs: c2,
        });
        let sum = p.fresh_var();
        p.push(Instruction::Add {
            result: sum,
            lhs: t0,
            rhs: t1,
        });
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: sum,
            rhs: input,
            message: None,
        });

        // Pre-proven booleans from bool_prop
        let mut proven = HashSet::new();
        proven.insert(bit0);
        proven.insert(bit1);

        let result = detect_bit_patterns(&p, &proven);
        assert_eq!(result.booleans_detected, 0); // no NEW booleans detected
        assert_eq!(result.bounds.get(&input), Some(&2));
    }

    #[test]
    fn non_contiguous_bits_rejected() {
        // Bits at positions 0 and 2 (missing 1) → should not infer bound
        let mut p: IrProgram = IrProgram::new();
        let input = p.fresh_var();
        p.push(Instruction::Input {
            result: input,
            name: "input".into(),
            visibility: Visibility::Witness,
        });

        let const_one = p.fresh_var();
        p.push(Instruction::Const {
            result: const_one,
            value: FieldElement::one(),
        });
        let const_zero = p.fresh_var();
        p.push(Instruction::Const {
            result: const_zero,
            value: FieldElement::zero(),
        });

        // Two boolean-enforced bits
        let mut bits = Vec::new();
        for _ in 0..2 {
            let bit = p.fresh_var();
            p.push(Instruction::Input {
                result: bit,
                name: "bit".into(),
                visibility: Visibility::Witness,
            });
            let sub_r = p.fresh_var();
            p.push(Instruction::Sub {
                result: sub_r,
                lhs: bit,
                rhs: const_one,
            });
            let mul_r = p.fresh_var();
            p.push(Instruction::Mul {
                result: mul_r,
                lhs: bit,
                rhs: sub_r,
            });
            let assert_r = p.fresh_var();
            p.push(Instruction::AssertEq {
                result: assert_r,
                lhs: mul_r,
                rhs: const_zero,
                message: None,
            });
            bits.push(bit);
        }

        // bit0 * 1 + bit1 * 4  (positions 0 and 2 — gap at 1!)
        let c1 = p.fresh_var();
        p.push(Instruction::Const {
            result: c1,
            value: FieldElement::from_u64(1),
        });
        let c4 = p.fresh_var();
        p.push(Instruction::Const {
            result: c4,
            value: FieldElement::from_u64(4),
        });

        let t0 = p.fresh_var();
        p.push(Instruction::Mul {
            result: t0,
            lhs: bits[0],
            rhs: c1,
        });
        let t1 = p.fresh_var();
        p.push(Instruction::Mul {
            result: t1,
            lhs: bits[1],
            rhs: c4,
        });
        let sum = p.fresh_var();
        p.push(Instruction::Add {
            result: sum,
            lhs: t0,
            rhs: t1,
        });
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: sum,
            rhs: input,
            message: None,
        });

        let booleans = HashSet::new();
        let result = detect_bit_patterns(&p, &booleans);
        assert!(
            result.bounds.is_empty(),
            "non-contiguous bits should be rejected"
        );
    }

    #[test]
    fn is_power_of_two_works() {
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(1)),
            Some(0)
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(2)),
            Some(1)
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(4)),
            Some(2)
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(8)),
            Some(3)
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(1 << 63)),
            Some(63)
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(0)),
            None
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(3)),
            None
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(5)),
            None
        );
        assert_eq!(
            is_power_of_two::<memory::Bn254Fr>(&FieldElement::from_u64(6)),
            None
        );
    }
}
