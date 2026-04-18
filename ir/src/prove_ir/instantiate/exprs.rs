//! Expression-level emission on [`Instantiator`].
//!
//! [`emit_expr`] is the big match that turns each [`CircuitExpr`]
//! variant into its SSA program form. Two helpers live here:
//!
//! - [`resolve_scalar`] — env lookup (rejects array references at
//!   scalar positions).
//! - [`emit_pow`] — square-and-multiply expansion of constant-exponent
//!   `Pow` nodes.
//!
//! Bit-level expansion (`emit_decompose_bits`, `emit_recompose`,
//! shifts, bitwise binops) lives in [`super::bits`] — `emit_expr`
//! delegates there for the bitwise variants.

use memory::{FieldBackend, FieldElement};

use super::{BitwiseOp, InstEnvValue, Instantiator};
use crate::prove_ir::error::ProveIrError;
use crate::prove_ir::types::*;
use crate::types::{Instruction, IrType, SsaVar};

impl<F: FieldBackend> Instantiator<F> {
    pub(super) fn emit_expr(&mut self, expr: &CircuitExpr) -> Result<SsaVar, ProveIrError> {
        match expr {
            CircuitExpr::Const(field_const) => {
                let fe = field_const.to_field::<F>().ok_or_else(|| {
                    ProveIrError::UnsupportedOperation {
                        description: format!(
                            "field constant {field_const:?} is not valid in the target field"
                        ),
                        span: None,
                    }
                })?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Const {
                    result: v,
                    value: fe,
                });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::Input(name) => self.resolve_scalar(name),
            CircuitExpr::Var(name) => self.resolve_scalar(name),
            CircuitExpr::Capture(name) => {
                // Captures should already be in env (declared in step 4).
                // If not, it means the capture classification missed it.
                self.resolve_scalar(name)
            }
            CircuitExpr::BinOp { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                let inst = match op {
                    CircuitBinOp::Add => Instruction::Add {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBinOp::Sub => Instruction::Sub {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBinOp::Mul => Instruction::Mul {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBinOp::Div => Instruction::Div {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                };
                self.push_inst(inst);
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::UnaryOp { op, operand } => {
                let inner = self.emit_expr(operand)?;
                let v = self.program.fresh_var();
                let inst = match op {
                    CircuitUnaryOp::Neg => Instruction::Neg {
                        result: v,
                        operand: inner,
                    },
                    CircuitUnaryOp::Not => Instruction::Not {
                        result: v,
                        operand: inner,
                    },
                };
                self.push_inst(inst);
                let ty = match op {
                    CircuitUnaryOp::Neg => IrType::Field,
                    CircuitUnaryOp::Not => IrType::Bool,
                };
                self.program.set_type(v, ty);
                Ok(v)
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                // Gt and Ge are desugared by swapping operands.
                let inst = match op {
                    CircuitCmpOp::Eq => Instruction::IsEq {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Neq => Instruction::IsNeq {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Lt => Instruction::IsLt {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Le => Instruction::IsLe {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitCmpOp::Gt => Instruction::IsLt {
                        result: v,
                        lhs: r,
                        rhs: l,
                    },
                    CircuitCmpOp::Ge => Instruction::IsLe {
                        result: v,
                        lhs: r,
                        rhs: l,
                    },
                };
                self.push_inst(inst);
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                let inst = match op {
                    CircuitBoolOp::And => Instruction::And {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                    CircuitBoolOp::Or => Instruction::Or {
                        result: v,
                        lhs: l,
                        rhs: r,
                    },
                };
                self.push_inst(inst);
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => {
                let c = self.emit_expr(cond)?;
                let t = self.emit_expr(if_true)?;
                let f = self.emit_expr(if_false)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Mux {
                    result: v,
                    cond: c,
                    if_true: t,
                    if_false: f,
                });
                // Propagate type if both branches agree
                if let (Some(tt), Some(ft)) = (self.program.get_type(t), self.program.get_type(f)) {
                    if tt == ft {
                        self.program.set_type(v, tt);
                    }
                }
                Ok(v)
            }
            CircuitExpr::PoseidonHash { left, right } => {
                let l = self.emit_expr(left)?;
                let r = self.emit_expr(right)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::PoseidonHash {
                    result: v,
                    left: l,
                    right: r,
                });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::PoseidonMany(args) => {
                if args.is_empty() {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "poseidon_many requires at least 2 arguments".into(),
                        span: None,
                    });
                }

                let compiled: Vec<SsaVar> = args
                    .iter()
                    .map(|a| self.emit_expr(a))
                    .collect::<Result<_, _>>()?;

                if compiled.len() == 1 {
                    // Match IrLowering semantics: single arg → poseidon(arg, ZERO)
                    let zero = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: zero,
                        value: FieldElement::<F>::zero(),
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left: compiled[0],
                        right: zero,
                    });
                    return Ok(v);
                }

                // Left-fold: poseidon(poseidon(a0, a1), a2), ...
                let mut iter = compiled.into_iter();
                let mut acc = iter.next().expect("checked non-empty above");
                for next in iter {
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left: acc,
                        right: next,
                    });
                    acc = v;
                }
                Ok(acc)
            }
            CircuitExpr::RangeCheck { value, bits } => {
                let operand = self.emit_expr(value)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::RangeCheck {
                    result: v,
                    operand,
                    bits: *bits,
                });
                Ok(v)
            }
            CircuitExpr::MerkleVerify {
                root,
                leaf,
                path,
                indices,
            } => {
                // Merkle verification: hash leaf up the tree using path and indices.
                // path and indices are arrays in env.
                let root_var = self.emit_expr(root)?;
                let leaf_var = self.emit_expr(leaf)?;

                let path_elems = match self.env.get(path) {
                    Some(InstEnvValue::Array(elems)) => elems.clone(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!("merkle_verify path `{path}` is not an array"),
                            span: None,
                        });
                    }
                };
                let idx_elems = match self.env.get(indices) {
                    Some(InstEnvValue::Array(elems)) => elems.clone(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "merkle_verify indices `{indices}` is not an array"
                            ),
                            span: None,
                        });
                    }
                };

                if path_elems.len() != idx_elems.len() {
                    return Err(ProveIrError::ArrayLengthMismatch {
                        expected: path_elems.len(),
                        got: idx_elems.len(),
                        span: None,
                    });
                }

                // Walk up the tree: conditional swap + single hash per level.
                // idx=0 → current is left child:  poseidon(current, sibling)
                // idx=1 → current is right child: poseidon(sibling, current)
                // Cost: 2 Mux + 1 Poseidon (365) instead of 2 Poseidon + 1 Mux (724).
                let mut current = leaf_var;
                for (sibling, idx) in path_elems.iter().zip(idx_elems.iter()) {
                    let left = self.program.fresh_var();
                    self.push_inst(Instruction::Mux {
                        result: left,
                        cond: *idx,
                        if_true: *sibling,
                        if_false: current,
                    });
                    let right = self.program.fresh_var();
                    self.push_inst(Instruction::Mux {
                        result: right,
                        cond: *idx,
                        if_true: current,
                        if_false: *sibling,
                    });
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left,
                        right,
                    });
                    current = v;
                }

                // Assert computed root == expected root
                let v = self.program.fresh_var();
                self.push_inst(Instruction::AssertEq {
                    result: v,
                    lhs: current,
                    rhs: root_var,
                    message: None,
                });
                Ok(v)
            }
            CircuitExpr::ArrayIndex { array, index } => {
                // The index must resolve to a constant. Try evaluating as a
                // constant expression first (handles captures like `n` that are
                // known at instantiation time), then fall back to emitting and
                // extracting from the instruction stream.
                let idx = self
                    .eval_const_expr(index)
                    .ok()
                    .and_then(|fe| {
                        let limbs = fe.to_canonical();
                        if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                            usize::try_from(limbs[0]).ok()
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        let idx_var = self.emit_expr(index).ok()?;
                        self.extract_const_index(idx_var)
                    })
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "array index into `{array}` must be a compile-time constant"
                        ),
                        span: None,
                    })?;

                match self.env.get(array) {
                    Some(InstEnvValue::Array(elems)) => {
                        if idx >= elems.len() {
                            return Err(ProveIrError::IndexOutOfBounds {
                                name: array.clone(),
                                index: idx,
                                length: elems.len(),
                                span: None,
                            });
                        }
                        Ok(elems[idx])
                    }
                    _ => Err(ProveIrError::UnsupportedOperation {
                        description: format!("`{array}` is not an array"),
                        span: None,
                    }),
                }
            }
            CircuitExpr::ArrayLen(name) => {
                let len = match self.env.get(name) {
                    Some(InstEnvValue::Array(elems)) => elems.len(),
                    _ => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!("`{name}` is not an array"),
                            span: None,
                        });
                    }
                };
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Const {
                    result: v,
                    value: FieldElement::<F>::from_u64(len as u64),
                });
                Ok(v)
            }
            CircuitExpr::Pow { base, exp } => {
                let base_var = self.emit_expr(base)?;
                self.emit_pow(base_var, *exp)
            }
            CircuitExpr::IntDiv { lhs, rhs, max_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::IntDiv {
                    result: v,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits,
                });
                Ok(v)
            }
            CircuitExpr::IntMod { lhs, rhs, max_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.program.fresh_var();
                self.push_inst(Instruction::IntMod {
                    result: v,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits,
                });
                Ok(v)
            }

            // ── Bitwise operations (expanded via Decompose) ────────
            CircuitExpr::BitAnd { lhs, rhs, num_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, *num_bits, BitwiseOp::And)
            }
            CircuitExpr::BitOr { lhs, rhs, num_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, *num_bits, BitwiseOp::Or)
            }
            CircuitExpr::BitXor { lhs, rhs, num_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, *num_bits, BitwiseOp::Xor)
            }
            CircuitExpr::BitNot { operand, num_bits } => {
                let op = self.emit_expr(operand)?;
                self.emit_bitnot(op, *num_bits)
            }
            CircuitExpr::ShiftR {
                operand,
                shift,
                num_bits,
            } => {
                // If both operand and shift are compile-time constants, fold entirely
                if let Ok(fe) = self.eval_const_expr(expr) {
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: v,
                        value: fe,
                    });
                    return Ok(v);
                }
                let op = self.emit_expr(operand)?;
                let shift_val = self.resolve_const_u32(shift, "shift right amount")?;
                self.emit_shift_right(op, shift_val, *num_bits)
            }
            CircuitExpr::ShiftL {
                operand,
                shift,
                num_bits,
            } => {
                // If both operand and shift are compile-time constants, fold entirely
                if let Ok(fe) = self.eval_const_expr(expr) {
                    let v = self.program.fresh_var();
                    self.push_inst(Instruction::Const {
                        result: v,
                        value: fe,
                    });
                    return Ok(v);
                }
                let op = self.emit_expr(operand)?;
                let shift_val = self.resolve_const_u32(shift, "shift left amount")?;
                self.emit_shift_left(op, shift_val, *num_bits)
            }
        }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// Resolve a name to a scalar SsaVar from the environment.
    pub(super) fn resolve_scalar(&self, name: &str) -> Result<SsaVar, ProveIrError> {
        match self.env.get(name) {
            Some(InstEnvValue::Scalar(v)) => Ok(*v),
            Some(InstEnvValue::Array(_)) => Err(ProveIrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: None,
            }),
            None => Err(ProveIrError::UndeclaredVariable {
                name: name.into(),
                span: None,
                suggestion: None,
            }),
        }
    }

    /// Emit a power chain: base^exp as repeated multiplication.
    pub(super) fn emit_pow(&mut self, base: SsaVar, exp: u64) -> Result<SsaVar, ProveIrError> {
        if exp == 0 {
            let v = self.program.fresh_var();
            self.push_inst(Instruction::Const {
                result: v,
                value: FieldElement::<F>::one(),
            });
            return Ok(v);
        }

        // Square-and-multiply for efficiency
        let mut result = None;
        let mut current = base;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = Some(match result {
                    None => current,
                    Some(acc) => {
                        let v = self.program.fresh_var();
                        self.push_inst(Instruction::Mul {
                            result: v,
                            lhs: acc,
                            rhs: current,
                        });
                        v
                    }
                });
            }
            e >>= 1;
            if e > 0 {
                let v = self.program.fresh_var();
                self.push_inst(Instruction::Mul {
                    result: v,
                    lhs: current,
                    rhs: current,
                });
                current = v;
            }
        }

        Ok(result.unwrap_or(base))
    }

}
