use std::collections::HashMap;

use ir_forge::types::CircuitExpr;
use memory::{FieldBackend, FieldElement};

use super::limbs::{bit_mask_limbs, shift_left_limbs, shift_right_limbs};
use super::profile;

/// Evaluate an expression and extract a u64 index value.
pub(super) fn eval_hint_u64<F: FieldBackend>(
    expr: &CircuitExpr,
    env: &HashMap<String, FieldElement<F>>,
) -> Option<u64> {
    let val = eval_hint(expr, env)?;
    let limbs = val.to_canonical();
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        Some(limbs[0])
    } else {
        None
    }
}

/// Evaluate a circuit expression as a concrete field value.
///
/// Returns `None` if any referenced variable is unknown or the expression
/// contains constructs that can't be evaluated off-circuit.
pub(super) fn eval_hint<F: FieldBackend>(
    expr: &CircuitExpr,
    env: &HashMap<String, FieldElement<F>>,
) -> Option<FieldElement<F>> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_field::<F>(),
        // R1″ contract: substitution must run before witness eval. If
        // the placeholder reaches here, the memoization pipeline
        // emitted unsubstituted IR — fall back gracefully so the
        // callee can fault into the slow path instead of producing a
        // bogus witness value.
        CircuitExpr::LoopVar(_) => None,
        CircuitExpr::Input(name) | CircuitExpr::Var(name) | CircuitExpr::Capture(name) => {
            env.get(name).copied()
        }

        CircuitExpr::BinOp { op, lhs, rhs } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            use ir_forge::types::CircuitBinOp;
            match op {
                CircuitBinOp::Add => Some(l.add(&r)),
                CircuitBinOp::Sub => Some(l.sub(&r)),
                CircuitBinOp::Mul => Some(l.mul(&r)),
                // Circom-compatible: division by zero in witness hints
                // produces 0 (the official witness calculator treats 0/0 = 0).
                CircuitBinOp::Div => {
                    profile::record_hint_div(r.is_zero());
                    Some(l.div(&r).unwrap_or_else(FieldElement::<F>::zero))
                }
            }
        }

        CircuitExpr::UnaryOp { op, operand } => {
            let v = eval_hint(operand, env)?;
            use ir_forge::types::CircuitUnaryOp;
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

        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            let c = eval_hint(cond, env)?;
            // Lazy: only evaluate the taken branch (e.g. `in != 0 ? 1/in : 0`
            // must not evaluate 1/in when in == 0).
            if c != FieldElement::<F>::zero() {
                eval_hint(if_true, env)
            } else {
                eval_hint(if_false, env)
            }
        }

        // ── Bitwise ops: evaluate using integer arithmetic ────────
        CircuitExpr::BitAnd { lhs, rhs, .. } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            let l_limbs = l.to_canonical();
            let r_limbs = r.to_canonical();
            let result = [
                l_limbs[0] & r_limbs[0],
                l_limbs[1] & r_limbs[1],
                l_limbs[2] & r_limbs[2],
                l_limbs[3] & r_limbs[3],
            ];
            Some(FieldElement::<F>::from_canonical(result))
        }
        CircuitExpr::BitOr { lhs, rhs, .. } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            let l_limbs = l.to_canonical();
            let r_limbs = r.to_canonical();
            let result = [
                l_limbs[0] | r_limbs[0],
                l_limbs[1] | r_limbs[1],
                l_limbs[2] | r_limbs[2],
                l_limbs[3] | r_limbs[3],
            ];
            Some(FieldElement::<F>::from_canonical(result))
        }
        CircuitExpr::BitXor { lhs, rhs, .. } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            let l_limbs = l.to_canonical();
            let r_limbs = r.to_canonical();
            let result = [
                l_limbs[0] ^ r_limbs[0],
                l_limbs[1] ^ r_limbs[1],
                l_limbs[2] ^ r_limbs[2],
                l_limbs[3] ^ r_limbs[3],
            ];
            Some(FieldElement::<F>::from_canonical(result))
        }
        CircuitExpr::BitNot { operand, num_bits } => {
            let v = eval_hint(operand, env)?;
            let limbs = v.to_canonical();
            // Create mask for num_bits
            let mask = bit_mask_limbs(*num_bits);
            let result = [
                limbs[0] ^ mask[0],
                limbs[1] ^ mask[1],
                limbs[2] ^ mask[2],
                limbs[3] ^ mask[3],
            ];
            Some(FieldElement::<F>::from_canonical(result))
        }
        CircuitExpr::ShiftR { operand, shift, .. } => {
            let v = eval_hint(operand, env)?;
            let s = eval_hint(shift, env)?;
            let s_limbs = s.to_canonical();
            let shift_val = s_limbs[0] as u32;
            let limbs = v.to_canonical();
            let shifted = shift_right_limbs(limbs, shift_val);
            Some(FieldElement::<F>::from_canonical(shifted))
        }
        CircuitExpr::ShiftL { operand, shift, .. } => {
            let v = eval_hint(operand, env)?;
            let s = eval_hint(shift, env)?;
            let s_limbs = s.to_canonical();
            let shift_val = s_limbs[0] as u32;
            let limbs = v.to_canonical();
            let shifted = shift_left_limbs(limbs, shift_val);
            Some(FieldElement::<F>::from_canonical(shifted))
        }

        // ── Comparison ops ──────────────────────────────────────
        CircuitExpr::Comparison { op, lhs, rhs } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            use ir_forge::types::CircuitCmpOp;
            let result = match op {
                CircuitCmpOp::Eq => l == r,
                CircuitCmpOp::Neq => l != r,
                // For Lt/Le/Gt/Ge, compare canonical representations
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

        CircuitExpr::BoolOp { op, lhs, rhs } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            let l_bool = l != FieldElement::<F>::zero();
            let r_bool = r != FieldElement::<F>::zero();
            use ir_forge::types::CircuitBoolOp;
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

        CircuitExpr::Pow { base, exp } => {
            let b = eval_hint(base, env)?;
            let mut result = FieldElement::<F>::one();
            for _ in 0..*exp {
                result = result.mul(&b);
            }
            Some(result)
        }

        CircuitExpr::IntDiv { lhs, rhs, .. } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            let l_limbs = l.to_canonical();
            let r_limbs = r.to_canonical();
            // Simple integer division for small values (fits in u64)
            if l_limbs[1] == 0
                && l_limbs[2] == 0
                && l_limbs[3] == 0
                && r_limbs[1] == 0
                && r_limbs[2] == 0
                && r_limbs[3] == 0
                && r_limbs[0] != 0
            {
                Some(FieldElement::<F>::from_u64(l_limbs[0] / r_limbs[0]))
            } else {
                None // Large integer division not yet supported in hints
            }
        }

        CircuitExpr::IntMod { lhs, rhs, .. } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            let l_limbs = l.to_canonical();
            let r_limbs = r.to_canonical();
            if l_limbs[1] == 0
                && l_limbs[2] == 0
                && l_limbs[3] == 0
                && r_limbs[1] == 0
                && r_limbs[2] == 0
                && r_limbs[3] == 0
                && r_limbs[0] != 0
            {
                Some(FieldElement::<F>::from_u64(l_limbs[0] % r_limbs[0]))
            } else {
                None
            }
        }

        // Array element access: resolve `arr[i]` → lookup `arr_i` in env
        CircuitExpr::ArrayIndex { array, index } => {
            let idx = eval_hint_u64(index, env)?;
            let elem_name = format!("{array}_{idx}");
            env.get(&elem_name).copied()
        }

        // Expressions we can't evaluate off-circuit
        CircuitExpr::PoseidonHash { .. }
        | CircuitExpr::PoseidonMany(_)
        | CircuitExpr::RangeCheck { .. }
        | CircuitExpr::MerkleVerify { .. }
        | CircuitExpr::ArrayLen(_) => None,
    }
}

/// Evaluate a circuit expression to a u64 using capture values (template params).
///
/// Used for `ForRange::WithExpr` where the loop bound is a computed expression
/// (e.g., `n + 1` from component instantiation `Num2Bits(n+1)`).
pub(super) fn eval_const_expr_u64(
    expr: &CircuitExpr,
    captures: &HashMap<String, u64>,
) -> Option<u64> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_u64(),
        CircuitExpr::Capture(name) => captures.get(name).copied(),
        CircuitExpr::BinOp { op, lhs, rhs } => {
            let l = eval_const_expr_u64(lhs, captures)?;
            let r = eval_const_expr_u64(rhs, captures)?;
            use ir_forge::types::CircuitBinOp;
            match op {
                CircuitBinOp::Add => Some(l.wrapping_add(r)),
                CircuitBinOp::Sub => Some(l.wrapping_sub(r)),
                CircuitBinOp::Mul => Some(l.wrapping_mul(r)),
                CircuitBinOp::Div => l.checked_div(r),
            }
        }
        _ => None,
    }
}
