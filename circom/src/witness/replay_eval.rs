//! Slot-addressed expression evaluator for the hints replay.
//!
//! Arm-for-arm mirror of the reference evaluator in [`super::eval`]:
//! same `Option` totality (an unknown name or off-circuit construct
//! yields `None`, never an error), same div-by-zero-is-zero rule,
//! same lazy `Mux`, same canonical-limbs integer semantics for the
//! bitwise / shift / comparison / int-div arms. The only difference
//! is name resolution: leaves carry pre-compiled ids resolved through
//! the instance's slot cache instead of `String` keys.

use ir_forge::types::{CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitUnaryOp};
use memory::{FieldBackend, FieldElement};

use super::limbs::{bit_mask_limbs, shift_left_limbs, shift_right_limbs};
use super::profile;
use super::replay::{resolve, Cx, Instance};
use super::template::{ExprId, TExpr};

/// Evaluate an expression and extract a u64 index value.
pub(super) fn eval_u64<F: FieldBackend>(
    eid: ExprId,
    inst: &Instance<'_, '_, F>,
    cx: &mut Cx<'_, '_, F>,
) -> Option<u64> {
    let val = eval(eid, inst, cx)?;
    let limbs = val.to_canonical();
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        Some(limbs[0])
    } else {
        None
    }
}

/// Evaluate a compiled expression as a concrete field value.
pub(super) fn eval<F: FieldBackend>(
    eid: ExprId,
    inst: &Instance<'_, '_, F>,
    cx: &mut Cx<'_, '_, F>,
) -> Option<FieldElement<F>> {
    match &inst.template.exprs[eid as usize] {
        TExpr::Const(fc) => fc.to_field::<F>(),
        TExpr::Name(nid) => {
            let slot = resolve(*nid, inst, cx);
            cx.env.get(slot)
        }
        TExpr::Capture(nid) => {
            // A substituted template parameter evaluates to the
            // argument's value in the parent context (computed once
            // at instance creation); an unsubstituted capture reads
            // the env under its qualified name, exactly like a Var.
            let name = &inst.template.names[*nid as usize];
            match inst.subs.get(name.as_str()) {
                Some(binding) => binding.value,
                None => {
                    let slot = resolve(*nid, inst, cx);
                    cx.env.get(slot)
                }
            }
        }

        TExpr::BinOp { op, lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?;
            let r = eval(*rhs, inst, cx)?;
            match op {
                CircuitBinOp::Add => Some(l.add(&r)),
                CircuitBinOp::Sub => Some(l.sub(&r)),
                CircuitBinOp::Mul => Some(l.mul(&r)),
                // Circom-compatible: division by zero in witness hints
                // produces 0 (the official witness calculator treats
                // 0/0 = 0).
                CircuitBinOp::Div => {
                    profile::record_hint_div(r.is_zero());
                    Some(l.div(&r).unwrap_or_else(FieldElement::<F>::zero))
                }
            }
        }

        TExpr::UnaryOp { op, operand } => {
            let v = eval(*operand, inst, cx)?;
            Some(match op {
                CircuitUnaryOp::Neg => v.neg(),
                CircuitUnaryOp::Not => {
                    if v == FieldElement::<F>::zero() {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    }
                }
            })
        }

        TExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            let c = eval(*cond, inst, cx)?;
            // Lazy: only the taken branch (e.g. `in != 0 ? 1/in : 0`
            // must not evaluate 1/in when in == 0).
            if c != FieldElement::<F>::zero() {
                eval(*if_true, inst, cx)
            } else {
                eval(*if_false, inst, cx)
            }
        }

        TExpr::BitAnd { lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?.to_canonical();
            let r = eval(*rhs, inst, cx)?.to_canonical();
            Some(FieldElement::<F>::from_canonical([
                l[0] & r[0],
                l[1] & r[1],
                l[2] & r[2],
                l[3] & r[3],
            ]))
        }
        TExpr::BitOr { lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?.to_canonical();
            let r = eval(*rhs, inst, cx)?.to_canonical();
            Some(FieldElement::<F>::from_canonical([
                l[0] | r[0],
                l[1] | r[1],
                l[2] | r[2],
                l[3] | r[3],
            ]))
        }
        TExpr::BitXor { lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?.to_canonical();
            let r = eval(*rhs, inst, cx)?.to_canonical();
            Some(FieldElement::<F>::from_canonical([
                l[0] ^ r[0],
                l[1] ^ r[1],
                l[2] ^ r[2],
                l[3] ^ r[3],
            ]))
        }
        TExpr::BitNot { operand, num_bits } => {
            let limbs = eval(*operand, inst, cx)?.to_canonical();
            let mask = bit_mask_limbs(*num_bits);
            Some(FieldElement::<F>::from_canonical([
                limbs[0] ^ mask[0],
                limbs[1] ^ mask[1],
                limbs[2] ^ mask[2],
                limbs[3] ^ mask[3],
            ]))
        }
        TExpr::ShiftR { operand, shift } => {
            let v = eval(*operand, inst, cx)?;
            let s = eval(*shift, inst, cx)?;
            let shift_val = s.to_canonical()[0] as u32;
            Some(FieldElement::<F>::from_canonical(shift_right_limbs(
                v.to_canonical(),
                shift_val,
            )))
        }
        TExpr::ShiftL { operand, shift } => {
            let v = eval(*operand, inst, cx)?;
            let s = eval(*shift, inst, cx)?;
            let shift_val = s.to_canonical()[0] as u32;
            Some(FieldElement::<F>::from_canonical(shift_left_limbs(
                v.to_canonical(),
                shift_val,
            )))
        }

        TExpr::Comparison { op, lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?;
            let r = eval(*rhs, inst, cx)?;
            let result = match op {
                CircuitCmpOp::Eq => l == r,
                CircuitCmpOp::Neq => l != r,
                // Lt/Le/Gt/Ge compare canonical representations.
                CircuitCmpOp::Lt => l.to_canonical() < r.to_canonical(),
                CircuitCmpOp::Le => l.to_canonical() <= r.to_canonical(),
                CircuitCmpOp::Gt => l.to_canonical() > r.to_canonical(),
                CircuitCmpOp::Ge => l.to_canonical() >= r.to_canonical(),
            };
            Some(if result {
                FieldElement::<F>::one()
            } else {
                FieldElement::<F>::zero()
            })
        }

        TExpr::BoolOp { op, lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?;
            let r = eval(*rhs, inst, cx)?;
            let l_bool = l != FieldElement::<F>::zero();
            let r_bool = r != FieldElement::<F>::zero();
            let result = match op {
                CircuitBoolOp::And => l_bool && r_bool,
                CircuitBoolOp::Or => l_bool || r_bool,
            };
            Some(if result {
                FieldElement::<F>::one()
            } else {
                FieldElement::<F>::zero()
            })
        }

        TExpr::Pow { base, exp } => {
            let b = eval(*base, inst, cx)?;
            let mut result = FieldElement::<F>::one();
            for _ in 0..*exp {
                result = result.mul(&b);
            }
            Some(result)
        }

        TExpr::IntDiv { lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?.to_canonical();
            let r = eval(*rhs, inst, cx)?.to_canonical();
            // Integer division for values that fit in u64; larger
            // operands are not evaluable in hints.
            if l[1] == 0
                && l[2] == 0
                && l[3] == 0
                && r[1] == 0
                && r[2] == 0
                && r[3] == 0
                && r[0] != 0
            {
                Some(FieldElement::<F>::from_u64(l[0] / r[0]))
            } else {
                None
            }
        }
        TExpr::IntMod { lhs, rhs } => {
            let l = eval(*lhs, inst, cx)?.to_canonical();
            let r = eval(*rhs, inst, cx)?.to_canonical();
            if l[1] == 0
                && l[2] == 0
                && l[3] == 0
                && r[1] == 0
                && r[2] == 0
                && r[3] == 0
                && r[0] != 0
            {
                Some(FieldElement::<F>::from_u64(l[0] % r[0]))
            } else {
                None
            }
        }

        // Array element access: `arr[i]` reads the flat `arr_i` name.
        // A plain read — a missing element leaves no trace in the env.
        TExpr::ArrayIndex { array, index } => {
            let idx = eval_u64(*index, inst, cx)?;
            let array_name = &inst.template.names[*array as usize];
            cx.scratch.clear();
            if !inst.prefix.is_empty() {
                cx.scratch.push_str(&inst.prefix);
                cx.scratch.push('.');
            }
            cx.scratch.push_str(array_name);
            use std::fmt::Write as _;
            let _ = write!(cx.scratch, "_{idx}");
            cx.env.lookup(&cx.scratch)
        }

        TExpr::Unevaluable => None,
    }
}
