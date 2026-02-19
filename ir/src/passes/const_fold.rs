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
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // x + 0 → x, 0 + x → x
                if lhs_val.map_or(false, |v| v.is_zero()) {
                    if let Some(val) = rhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const { result: *result, value: val };
                    }
                } else if rhs_val.map_or(false, |v| v.is_zero()) {
                    if let Some(val) = lhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const { result: *result, value: val };
                    }
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    let folded = a.add(&b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const { result: *result, value: folded };
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // x - 0 → x
                if rhs_val.map_or(false, |v| v.is_zero()) {
                    if let Some(val) = lhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const { result: *result, value: val };
                    }
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    let folded = a.sub(&b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const { result: *result, value: folded };
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // x * 0 → 0, 0 * x → 0
                let lhs_zero = lhs_val.map_or(false, |v| v.is_zero());
                let rhs_zero = rhs_val.map_or(false, |v| v.is_zero());
                if lhs_zero || rhs_zero {
                    constants.insert(*result, FieldElement::ZERO);
                    *inst = Instruction::Const { result: *result, value: FieldElement::ZERO };
                // x * 1 → x, 1 * x → x
                } else if lhs_val == Some(FieldElement::ONE) {
                    if let Some(val) = rhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const { result: *result, value: val };
                    }
                } else if rhs_val == Some(FieldElement::ONE) {
                    if let Some(val) = lhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const { result: *result, value: val };
                    }
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    let folded = a.mul(&b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const { result: *result, value: folded };
                }
            }
            Instruction::Div { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // 0 / x → 0 (for any non-zero x)
                let lhs_zero = lhs_val.map_or(false, |v| v.is_zero());
                let rhs_zero = rhs_val.map_or(false, |v| v.is_zero());
                if lhs_zero && !rhs_zero {
                    constants.insert(*result, FieldElement::ZERO);
                    *inst = Instruction::Const { result: *result, value: FieldElement::ZERO };
                // x / 1 → x
                } else if rhs_val == Some(FieldElement::ONE) {
                    if let Some(val) = lhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const { result: *result, value: val };
                    }
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    if let Some(inv) = b.inv() {
                        let folded = a.mul(&inv);
                        constants.insert(*result, folded);
                        *inst = Instruction::Const { result: *result, value: folded };
                    }
                }
            }
            // Mux with constant condition or equal branches
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let cond_val = constants.get(cond).copied();
                let true_val = constants.get(if_true).copied();
                let false_val = constants.get(if_false).copied();
                // Equal branches: mux(c, x, x) → x
                if let (Some(t), Some(f)) = (true_val, false_val) {
                    if t == f {
                        constants.insert(*result, t);
                        *inst = Instruction::Const {
                            result: *result,
                            value: t,
                        };
                    } else if let Some(c) = cond_val {
                        let val = if c.is_zero() { f } else { t };
                        constants.insert(*result, val);
                        *inst = Instruction::Const {
                            result: *result,
                            value: val,
                        };
                    }
                } else if let Some(c) = cond_val {
                    if c.is_zero() {
                        if let Some(val) = false_val {
                            constants.insert(*result, val);
                            *inst = Instruction::Const {
                                result: *result,
                                value: val,
                            };
                        }
                    } else if c == FieldElement::ONE {
                        if let Some(val) = true_val {
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
            Instruction::Not { result, operand } => {
                if let Some(v) = constants.get(operand) {
                    let folded = if v.is_zero() {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::And { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // Short-circuit: 0 && x = 0
                if lhs_val.map_or(false, |v| v.is_zero())
                    || rhs_val.map_or(false, |v| v.is_zero())
                {
                    constants.insert(*result, FieldElement::ZERO);
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::ZERO,
                    };
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    let folded = a.mul(&b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Or { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // Short-circuit: 1 || x = 1
                if lhs_val.map_or(false, |v| v == FieldElement::ONE)
                    || rhs_val.map_or(false, |v| v == FieldElement::ONE)
                {
                    constants.insert(*result, FieldElement::ONE);
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::ONE,
                    };
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    // a + b - a*b
                    let folded = a.add(&b).sub(&a.mul(&b));
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsEq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = if a == b {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = if a != b {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsLt { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    // Compare canonical representations (little-endian limbs)
                    let la = a.to_canonical();
                    let lb = b.to_canonical();
                    let less = (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]);
                    let folded = if less {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsLe { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let la = a.to_canonical();
                    let lb = b.to_canonical();
                    let le = (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0]);
                    let folded = if le {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            // Input, AssertEq, Assert, PoseidonHash — no folding
            _ => {}
        }
    }
}
