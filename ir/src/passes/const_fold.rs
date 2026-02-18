use std::collections::HashMap;

use memory::FieldElement;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Constant folding pass.
///
/// Forward pass O(n). Tracks which SSA variables have known constant values.
/// If all operands of an arithmetic instruction are constants, replaces the
/// instruction with a `Const`.
pub fn constant_fold(program: &mut IrProgram) {
    let mut constants: HashMap<SsaVar, FieldElement> = HashMap::new();

    for inst in &mut program.instructions {
        match inst {
            Instruction::Const { result, value } => {
                constants.insert(*result, *value);
            }
            Instruction::Neg { result, operand } => {
                if let Some(v) = constants.get(operand) {
                    let folded = v.neg();
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Add { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = a.add(b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = a.sub(b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                // Special case: x * 0 → 0 (even if x is not constant)
                let lhs_zero = constants.get(lhs).map_or(false, |v| v.is_zero());
                let rhs_zero = constants.get(rhs).map_or(false, |v| v.is_zero());
                if lhs_zero || rhs_zero {
                    constants.insert(*result, FieldElement::ZERO);
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::ZERO,
                    };
                } else if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = a.mul(b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Div { result, lhs, rhs } => {
                // Special case: 0 / x → 0 (for any non-zero x)
                let lhs_zero = constants.get(lhs).map_or(false, |v| v.is_zero());
                let rhs_zero = constants.get(rhs).map_or(false, |v| v.is_zero());
                if lhs_zero && !rhs_zero {
                    constants.insert(*result, FieldElement::ZERO);
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::ZERO,
                    };
                } else if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    if let Some(inv) = b.inv() {
                        let folded = a.mul(&inv);
                        constants.insert(*result, folded);
                        *inst = Instruction::Const {
                            result: *result,
                            value: folded,
                        };
                    }
                }
            }
            // Mux with constant condition
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let cond_val = constants.get(cond).copied();
                if let Some(c) = cond_val {
                    if c.is_zero() {
                        if let Some(val) = constants.get(if_false).copied() {
                            constants.insert(*result, val);
                            *inst = Instruction::Const {
                                result: *result,
                                value: val,
                            };
                        }
                    } else if c == FieldElement::ONE {
                        if let Some(val) = constants.get(if_true).copied() {
                            constants.insert(*result, val);
                            *inst = Instruction::Const {
                                result: *result,
                                value: val,
                            };
                        }
                    }
                }
            }
            // RangeCheck: if operand is constant and fits in bits, propagate constant
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                if let Some(val) = constants.get(operand) {
                    let limbs = val.to_canonical();
                    let fits = if *bits >= 64 {
                        // For ≥64 bits, check upper limbs cover the value
                        let full_limbs_needed = (*bits / 64) as usize;
                        let remaining_bits = *bits % 64;
                        let mut ok = true;
                        for i in (full_limbs_needed + 1)..4 {
                            if limbs[i] != 0 {
                                ok = false;
                            }
                        }
                        if ok && full_limbs_needed < 4 && remaining_bits > 0 {
                            ok = limbs[full_limbs_needed] < (1u64 << remaining_bits);
                        }
                        ok
                    } else {
                        limbs[0] < (1u64 << *bits) && limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0
                    };
                    if fits {
                        constants.insert(*result, *val);
                    }
                }
            }
            // Input, AssertEq, PoseidonHash — no folding
            _ => {}
        }
    }
}
