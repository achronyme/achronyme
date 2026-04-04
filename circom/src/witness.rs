//! Witness computation for Circom `<--` hint expressions.
//!
//! Evaluates hint expressions off-circuit using concrete field values
//! to produce witness assignments. This is the Circom equivalent of
//! a witness calculator — it runs the prover-side computation that
//! determines signal values without generating any constraints.
//!
//! Bitwise operations (`>>`, `<<`, `&`, `|`, `^`, `~`) are evaluated
//! using integer arithmetic on the canonical field representation.

use std::collections::HashMap;

use ir::prove_ir::types::{CircuitExpr, CircuitNode, ForRange, ProveIR};
use memory::{FieldBackend, FieldElement};

/// Compute all witness hint values from a ProveIR body.
///
/// Takes user-provided inputs and evaluates `WitnessHint` expressions
/// in order, building up a map of signal_name → FieldElement.
/// Later hints can reference earlier-computed values.
///
/// Returns `Err` if a Circom `assert()` fails during witness computation.
pub fn compute_witness_hints<F: FieldBackend>(
    prove_ir: &ProveIR,
    inputs: &HashMap<String, FieldElement<F>>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessError> {
    compute_witness_hints_with_captures(prove_ir, inputs, &HashMap::new())
}

/// Compute witness hints with capture values (template parameters).
///
/// Captures are needed to resolve For loop bounds like `for i < n`
/// where `n` is a template parameter.
///
/// Returns `Err` if a Circom `assert()` fails during witness computation.
pub fn compute_witness_hints_with_captures<F: FieldBackend>(
    prove_ir: &ProveIR,
    inputs: &HashMap<String, FieldElement<F>>,
    captures: &HashMap<String, u64>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessError> {
    let mut env: HashMap<String, FieldElement<F>> = inputs.clone();
    // Seed env with capture values so expressions like `1 << n` can
    // evaluate when `n` is a template parameter / capture.
    for (name, val) in captures {
        env.entry(name.clone())
            .or_insert_with(|| FieldElement::<F>::from_u64(*val));
    }
    collect_hints_recursive(&prove_ir.body, &mut env, captures)?;
    Ok(env)
}

/// Error during witness computation.
#[derive(Debug)]
pub struct WitnessError {
    pub message: String,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WitnessError {}

fn collect_hints_recursive<F: FieldBackend>(
    nodes: &[CircuitNode],
    env: &mut HashMap<String, FieldElement<F>>,
    captures: &HashMap<String, u64>,
) -> Result<(), WitnessError> {
    for node in nodes {
        match node {
            CircuitNode::WitnessHint { name, hint, .. } => {
                if let Some(val) = eval_hint(hint, env) {
                    env.insert(name.clone(), val);
                }
            }
            CircuitNode::WitnessHintIndexed {
                array, index, hint, ..
            } => {
                if let (Some(idx), Some(val)) = (eval_hint_u64(index, env), eval_hint(hint, env)) {
                    let elem_name = format!("{array}_{idx}");
                    env.insert(elem_name, val);
                }
            }
            CircuitNode::Let { name, value, .. } => {
                if let Some(val) = eval_hint(value, env) {
                    env.insert(name.clone(), val);
                }
            }
            CircuitNode::LetIndexed {
                array,
                index,
                value,
                ..
            } => {
                if let (Some(idx), Some(val)) = (eval_hint_u64(index, env), eval_hint(value, env)) {
                    let elem_name = format!("{array}_{idx}");
                    env.insert(elem_name, val);
                }
            }
            CircuitNode::For {
                var, range, body, ..
            } => {
                let (start, end) = match range {
                    ForRange::Literal { start, end } => (Some(*start), Some(*end)),
                    ForRange::WithCapture { start, end_capture } => {
                        (Some(*start), captures.get(end_capture).copied())
                    }
                    ForRange::WithExpr { start, end_expr } => {
                        let end_val = eval_const_expr_u64(end_expr, captures);
                        (Some(*start), end_val)
                    }
                    ForRange::Array(_) => (None, None),
                };
                if let (Some(start), Some(end)) = (start, end) {
                    for i in start..end {
                        env.insert(var.clone(), FieldElement::<F>::from_u64(i));
                        collect_hints_recursive(body, env, captures)?;
                    }
                } else {
                    collect_hints_recursive(body, env, captures)?;
                }
            }
            CircuitNode::If {
                cond,
                then_body,
                else_body,
                ..
            } => {
                if let Some(val) = eval_hint(cond, env) {
                    if val != FieldElement::<F>::zero() {
                        collect_hints_recursive(then_body, env, captures)?;
                    } else {
                        collect_hints_recursive(else_body, env, captures)?;
                    }
                } else {
                    collect_hints_recursive(then_body, env, captures)?;
                    collect_hints_recursive(else_body, env, captures)?;
                }
            }
            CircuitNode::Assert { expr, message, .. } => {
                if let Some(val) = eval_hint(expr, env) {
                    if val == FieldElement::<F>::zero() {
                        let msg = message
                            .as_deref()
                            .unwrap_or("circom assert() failed during witness computation");
                        return Err(WitnessError {
                            message: msg.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Evaluate an expression and extract a u64 index value.
fn eval_hint_u64<F: FieldBackend>(
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
fn eval_hint<F: FieldBackend>(
    expr: &CircuitExpr,
    env: &HashMap<String, FieldElement<F>>,
) -> Option<FieldElement<F>> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_field::<F>(),
        CircuitExpr::Input(name) | CircuitExpr::Var(name) | CircuitExpr::Capture(name) => {
            env.get(name).copied()
        }

        CircuitExpr::BinOp { op, lhs, rhs } => {
            let l = eval_hint(lhs, env)?;
            let r = eval_hint(rhs, env)?;
            use ir::prove_ir::types::CircuitBinOp;
            match op {
                CircuitBinOp::Add => Some(l.add(&r)),
                CircuitBinOp::Sub => Some(l.sub(&r)),
                CircuitBinOp::Mul => Some(l.mul(&r)),
                CircuitBinOp::Div => l.div(&r),
            }
        }

        CircuitExpr::UnaryOp { op, operand } => {
            let v = eval_hint(operand, env)?;
            use ir::prove_ir::types::CircuitUnaryOp;
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
            use ir::prove_ir::types::CircuitCmpOp;
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
            use ir::prove_ir::types::CircuitBoolOp;
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
fn eval_const_expr_u64(expr: &CircuitExpr, captures: &HashMap<String, u64>) -> Option<u64> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_u64(),
        CircuitExpr::Capture(name) => captures.get(name).copied(),
        CircuitExpr::BinOp { op, lhs, rhs } => {
            let l = eval_const_expr_u64(lhs, captures)?;
            let r = eval_const_expr_u64(rhs, captures)?;
            use ir::prove_ir::types::CircuitBinOp;
            match op {
                CircuitBinOp::Add => Some(l.wrapping_add(r)),
                CircuitBinOp::Sub => Some(l.wrapping_sub(r)),
                CircuitBinOp::Mul => Some(l.wrapping_mul(r)),
                CircuitBinOp::Div => {
                    if r != 0 {
                        Some(l / r)
                    } else {
                        None
                    }
                }
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 256-bit integer helpers (4 × u64 limbs, little-endian)
// ---------------------------------------------------------------------------

/// Right-shift a 4-limb integer by `shift` bits.
#[allow(clippy::needless_range_loop)]
fn shift_right_limbs(limbs: [u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..4 {
        let src = i + word_shift;
        if src < 4 {
            result[i] = limbs[src] >> bit_shift;
            if bit_shift > 0 && src + 1 < 4 {
                result[i] |= limbs[src + 1] << (64 - bit_shift);
            }
        }
    }
    result
}

/// Left-shift a 4-limb integer by `shift` bits.
#[allow(clippy::needless_range_loop)]
fn shift_left_limbs(limbs: [u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..4 {
        if i >= word_shift {
            let src = i - word_shift;
            result[i] = limbs[src] << bit_shift;
            if bit_shift > 0 && src > 0 {
                result[i] |= limbs[src - 1] >> (64 - bit_shift);
            }
        }
    }
    result
}

/// Create a bitmask with `num_bits` set bits (as 4 limbs).
fn bit_mask_limbs(num_bits: u32) -> [u64; 4] {
    let mut mask = [0u64; 4];
    for i in 0..4 {
        let bits_in_limb = num_bits.saturating_sub(i as u32 * 64).min(64);
        if bits_in_limb == 64 {
            mask[i as usize] = u64::MAX;
        } else if bits_in_limb > 0 {
            mask[i as usize] = (1u64 << bits_in_limb) - 1;
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::prove_ir::types::FieldConst;
    use memory::Bn254Fr;

    type Fe = FieldElement<Bn254Fr>;

    fn fe(v: u64) -> Fe {
        Fe::from_u64(v)
    }

    fn make_env(pairs: &[(&str, u64)]) -> HashMap<String, Fe> {
        pairs.iter().map(|(k, v)| (k.to_string(), fe(*v))).collect()
    }

    #[test]
    fn eval_const() {
        let env: HashMap<String, Fe> = HashMap::new();
        let expr = CircuitExpr::Const(FieldConst::from_u64(42));
        assert_eq!(eval_hint(&expr, &env), Some(fe(42)));
    }

    #[test]
    fn eval_input() {
        let env = make_env(&[("x", 10)]);
        let expr = CircuitExpr::Input("x".to_string());
        assert_eq!(eval_hint(&expr, &env), Some(fe(10)));
    }

    #[test]
    fn eval_shift_right() {
        let env = make_env(&[("x", 13)]);
        // x >> 1 = 6 (13 = 1101, >> 1 = 110 = 6)
        let expr = CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Input("x".to_string())),
            shift: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
            num_bits: 253,
        };
        assert_eq!(eval_hint(&expr, &env), Some(fe(6)));
    }

    #[test]
    fn eval_bit_and() {
        let env = make_env(&[("x", 13)]);
        // 13 & 1 = 1
        let expr = CircuitExpr::BitAnd {
            lhs: Box::new(CircuitExpr::Input("x".to_string())),
            rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
            num_bits: 253,
        };
        assert_eq!(eval_hint(&expr, &env), Some(fe(1)));
    }

    #[test]
    fn eval_shift_and_mask() {
        let env = make_env(&[("in", 13)]);
        // (in >> 3) & 1 = bit 3 of 13 (1101) = 1
        let expr = CircuitExpr::BitAnd {
            lhs: Box::new(CircuitExpr::ShiftR {
                operand: Box::new(CircuitExpr::Input("in".to_string())),
                shift: Box::new(CircuitExpr::Const(FieldConst::from_u64(3))),
                num_bits: 253,
            }),
            rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
            num_bits: 253,
        };
        assert_eq!(eval_hint(&expr, &env), Some(fe(1)));

        // (in >> 1) & 1 = bit 1 of 13 (1101) = 0
        let expr2 = CircuitExpr::BitAnd {
            lhs: Box::new(CircuitExpr::ShiftR {
                operand: Box::new(CircuitExpr::Input("in".to_string())),
                shift: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
                num_bits: 253,
            }),
            rhs: Box::new(CircuitExpr::Const(FieldConst::from_u64(1))),
            num_bits: 253,
        };
        assert_eq!(eval_hint(&expr2, &env), Some(fe(0)));
    }

    #[test]
    fn eval_arithmetic() {
        let env = make_env(&[("a", 3), ("b", 7)]);
        let expr = CircuitExpr::BinOp {
            op: ir::prove_ir::types::CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Input("a".to_string())),
            rhs: Box::new(CircuitExpr::Input("b".to_string())),
        };
        assert_eq!(eval_hint(&expr, &env), Some(fe(21)));
    }

    #[test]
    fn shift_right_limbs_basic() {
        assert_eq!(shift_right_limbs([13, 0, 0, 0], 1), [6, 0, 0, 0]);
        assert_eq!(shift_right_limbs([13, 0, 0, 0], 3), [1, 0, 0, 0]);
        assert_eq!(shift_right_limbs([0, 1, 0, 0], 64), [1, 0, 0, 0]);
    }

    #[test]
    fn bit_mask_limbs_basic() {
        assert_eq!(bit_mask_limbs(8), [0xFF, 0, 0, 0]);
        assert_eq!(bit_mask_limbs(64), [u64::MAX, 0, 0, 0]);
        assert_eq!(bit_mask_limbs(1), [1, 0, 0, 0]);
    }
}
