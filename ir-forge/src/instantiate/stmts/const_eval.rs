use memory::{FieldBackend, FieldElement};

use super::super::utils::{fe_to_u64, fe_to_usize};
use super::super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::types::*;

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    /// Evaluate a circuit expression to a u64 using capture values.
    ///
    /// Used for `ForRange::WithExpr` where the loop bound is a computed
    /// expression over captures (e.g., `n + 1` from `Num2Bits(n+1)`).
    pub(in crate::instantiate) fn eval_const_expr_u64(
        &self,
        expr: &CircuitExpr,
    ) -> Result<u64, ProveIrError> {
        let fe = self.eval_const_expr(expr)?;
        fe_to_u64(&fe, "<expr>")
    }

    pub(in crate::instantiate) fn eval_const_expr(
        &self,
        expr: &CircuitExpr,
    ) -> Result<FieldElement<F>, ProveIrError> {
        match expr {
            CircuitExpr::LoopVar(token) => Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "internal: CircuitExpr::LoopVar({token}) reached eval_const_expr; \
                     R1″ placeholder must be substituted before instantiation"
                ),
                span: None,
            }),
            CircuitExpr::Const(fc) => {
                fc.to_field::<F>()
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: "constant out of field range".into(),
                        span: None,
                    })
            }
            CircuitExpr::Capture(name) => {
                self.captures
                    .get(name)
                    .copied()
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "missing capture value `{name}` in constant expression"
                        ),
                        span: None,
                    })
            }
            CircuitExpr::BinOp { op, lhs, rhs } => {
                let l = self.eval_const_expr(lhs)?;
                let r = self.eval_const_expr(rhs)?;
                match op {
                    CircuitBinOp::Add => Ok(l.add(&r)),
                    CircuitBinOp::Sub => Ok(l.sub(&r)),
                    CircuitBinOp::Mul => Ok(l.mul(&r)),
                    CircuitBinOp::Div => {
                        l.div(&r).ok_or_else(|| ProveIrError::UnsupportedOperation {
                            description: "division by zero in constant expression".into(),
                            span: None,
                        })
                    }
                }
            }
            CircuitExpr::UnaryOp { op, operand } => {
                let v = self.eval_const_expr(operand)?;
                match op {
                    CircuitUnaryOp::Neg => Ok(v.neg()),
                    CircuitUnaryOp::Not => {
                        // Logical NOT on 0/1: 1 - v. For non-bool values
                        // circom treats this as (v == 0).
                        Ok(if v.is_zero() {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        })
                    }
                }
            }
            CircuitExpr::Var(name) | CircuitExpr::Input(name) => {
                // Look up the variable in the env — if it's a scalar SSA var
                // that was defined as a Const (e.g., loop variable after unroll),
                // extract its value via the const_values cache.
                if let Some(InstEnvValue::Scalar(ssa)) = self.env.get(name) {
                    if let Some(value) = self.const_value_of(*ssa) {
                        return Ok(value);
                    }
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "variable `{name}` is not a compile-time constant in this context"
                    ),
                    span: None,
                })
            }
            // Integer-semantic ops: evaluate as u64 arithmetic, return as
            // field element. Circomlib's rotation / shift templates
            // (e.g. `RotR(n, r)`, `ShR(n, r)`) produce `(i+r) % n` and
            // `i + r` on loop vars + captures — both must fold here so
            // the downstream signal-array index resolves to a literal.
            CircuitExpr::IntDiv { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                if r == 0 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "integer division by zero in constant expression".into(),
                        span: None,
                    });
                }
                Ok(FieldElement::<F>::from_u64(l / r))
            }
            CircuitExpr::IntMod { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                if r == 0 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "modulo by zero in constant expression".into(),
                        span: None,
                    });
                }
                Ok(FieldElement::<F>::from_u64(l % r))
            }
            CircuitExpr::BitAnd { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                Ok(FieldElement::<F>::from_u64(l & r))
            }
            CircuitExpr::BitOr { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                Ok(FieldElement::<F>::from_u64(l | r))
            }
            CircuitExpr::BitXor { lhs, rhs, .. } => {
                let l = self.eval_const_expr_u64(lhs)?;
                let r = self.eval_const_expr_u64(rhs)?;
                Ok(FieldElement::<F>::from_u64(l ^ r))
            }
            CircuitExpr::BitNot { operand, num_bits } => {
                let v = self.eval_const_expr_u64(operand)?;
                let mask = if *num_bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << num_bits) - 1
                };
                Ok(FieldElement::<F>::from_u64((!v) & mask))
            }
            CircuitExpr::ShiftL { operand, shift, .. } => {
                // `x << s` is `x * 2^s` in the field. Use `FieldElement::pow`
                // so shifts >= 64 (e.g. circomlib's `LessThan(64)` computing
                // `1 << 64`) don't collapse to 0 via `u64::checked_shl`.
                // BN254 is 254-bit so `2^s` for `s <= 253` is always a
                // valid field element; shifts larger than that overflow
                // the field and we bail out explicitly rather than
                // silently wrap.
                let op_val = self.eval_const_expr(operand)?;
                let shift_val = self.eval_const_expr_u64(shift)?;
                if shift_val >= 254 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "left shift amount {shift_val} exceeds BN254 field width (254 bits)"
                        ),
                        span: None,
                    });
                }
                let two = FieldElement::<F>::from_u64(2);
                let two_to_s = two.pow(&[shift_val, 0, 0, 0]);
                Ok(op_val.mul(&two_to_s))
            }
            CircuitExpr::ShiftR { operand, shift, .. } => {
                let op_val = self.eval_const_expr_u64(operand)?;
                let shift_val = self.eval_const_expr_u64(shift)?;
                let result = if shift_val >= 64 {
                    0
                } else {
                    op_val >> (shift_val as u32)
                };
                Ok(FieldElement::<F>::from_u64(result))
            }
            CircuitExpr::Pow { base, exp } => {
                let b = self.eval_const_expr(base)?;
                Ok(b.pow(&[*exp, 0, 0, 0]))
            }
            CircuitExpr::ArrayLen(name) => match self.env.get(name) {
                Some(InstEnvValue::Array(elems)) => {
                    Ok(FieldElement::<F>::from_u64(elems.len() as u64))
                }
                _ => Err(ProveIrError::UnsupportedOperation {
                    description: format!("`{name}` is not an array in const eval"),
                    span: None,
                }),
            },
            CircuitExpr::ArrayIndex { array, index } => {
                let idx = fe_to_usize(&self.eval_const_expr(index)?, array)?;
                match self.env.get(array) {
                    Some(InstEnvValue::Array(elems)) => {
                        let ssa = elems.get(idx).copied().ok_or_else(|| {
                            ProveIrError::IndexOutOfBounds {
                                name: array.clone(),
                                index: idx,
                                length: elems.len(),
                                span: None,
                            }
                        })?;
                        if let Some(value) = self.const_value_of(ssa) {
                            return Ok(value);
                        }
                        Err(ProveIrError::UnsupportedOperation {
                            description: format!("`{array}[{idx}]` is not a compile-time constant"),
                            span: None,
                        })
                    }
                    _ => Err(ProveIrError::UnsupportedOperation {
                        description: format!("`{array}` is not an array"),
                        span: None,
                    }),
                }
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                let l = self.eval_const_expr(lhs)?;
                let r = self.eval_const_expr(rhs)?;
                let (ok, descr): (bool, &str) = match op {
                    CircuitCmpOp::Eq => (l == r, "=="),
                    CircuitCmpOp::Neq => (l != r, "!="),
                    // Ordering on field elements is treated as u64-signed
                    // for small captures (loop bounds, array sizes). This
                    // matches the sign of values template authors actually
                    // use in const contexts.
                    CircuitCmpOp::Lt => (fe_to_u64(&l, "<")? < fe_to_u64(&r, "<")?, "<"),
                    CircuitCmpOp::Le => (fe_to_u64(&l, "<=")? <= fe_to_u64(&r, "<=")?, "<="),
                    CircuitCmpOp::Gt => (fe_to_u64(&l, ">")? > fe_to_u64(&r, ">")?, ">"),
                    CircuitCmpOp::Ge => (fe_to_u64(&l, ">=")? >= fe_to_u64(&r, ">=")?, ">="),
                };
                let _ = descr;
                Ok(if ok {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                })
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                let l = self.eval_const_expr(lhs)?;
                let r = self.eval_const_expr(rhs)?;
                let lb = !l.is_zero();
                let rb = !r.is_zero();
                let out = match op {
                    CircuitBoolOp::And => lb && rb,
                    CircuitBoolOp::Or => lb || rb,
                };
                Ok(if out {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                })
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => {
                let c = self.eval_const_expr(cond)?;
                if !c.is_zero() {
                    self.eval_const_expr(if_true)
                } else {
                    self.eval_const_expr(if_false)
                }
            }
            // Nodes below emit gadgets (hash, merkle, range) or cannot
            // appear in const position. Failing here tells the caller
            // to fall back to emit + extract_const_index, which is the
            // correct behaviour when the expression genuinely depends
            // on a runtime signal.
            CircuitExpr::PoseidonHash { .. }
            | CircuitExpr::PoseidonMany(_)
            | CircuitExpr::RangeCheck { .. }
            | CircuitExpr::MerkleVerify { .. } => Err(ProveIrError::UnsupportedOperation {
                description: "gadget expression not allowed in const eval".into(),
                span: None,
            }),
        }
    }
}
