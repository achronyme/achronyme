use std::collections::HashMap;

use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, SsaVar};

/// Try to detect `v*(v-1) = 0` boolean enforcement.
///
/// `mul_side` should be the side that might be `Mul(v, Sub(v, 1))`,
/// `zero_side` should be `Const(0)`.
pub(super) fn try_detect_boolean_enforcement<F: FieldBackend>(
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
