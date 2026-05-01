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

use super::utils::fe_to_u64;
use super::{BitwiseOp, InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::extended::ShiftDirection;
use crate::types::*;
use ir_core::{Instruction, IrType, SsaVar};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn emit_expr(&mut self, expr: &CircuitExpr) -> Result<SsaVar, ProveIrError> {
        match expr {
            // R1″ contract: LoopVar must be substituted by the
            // for-loop unroller before reaching instantiation.
            // Reaching this arm means substitute_loop_var missed a
            // site or the placeholder leaked across a memoization
            // boundary.
            CircuitExpr::LoopVar(token) => Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "internal: CircuitExpr::LoopVar({token}) reached instantiation; \
                     for-loop body memoization failed to substitute the placeholder"
                ),
                span: None,
            }),
            CircuitExpr::Const(field_const) => {
                let fe = field_const.to_field::<F>().ok_or_else(|| {
                    ProveIrError::UnsupportedOperation {
                        description: format!(
                            "field constant {field_const:?} is not valid in the target field"
                        ),
                        span: None,
                    }
                })?;
                Ok(self.emit_const(fe))
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

                // Peephole const-fold: if both operands are known
                // constants, compute at emit time and emit a deduped
                // Const. If only one is a known identity/annihilator,
                // short-circuit to the other operand (or a zero const).
                // These rules mirror `ir::passes::const_fold` but run
                // *during* instantiate, keeping the instruction stream
                // small enough to survive large circuits (SHA-256).
                let lv = self.const_value_of(l);
                let rv = self.const_value_of(r);
                if let (Some(a), Some(b)) = (lv, rv) {
                    let folded = match op {
                        CircuitBinOp::Add => Some(a.add(&b)),
                        CircuitBinOp::Sub => Some(a.sub(&b)),
                        CircuitBinOp::Mul => Some(a.mul(&b)),
                        CircuitBinOp::Div => a.div(&b),
                    };
                    if let Some(fe) = folded {
                        return Ok(self.emit_const(fe));
                    }
                }
                match op {
                    CircuitBinOp::Add => {
                        if lv.map(|a| a.is_zero()).unwrap_or(false) {
                            return Ok(r);
                        }
                        if rv.map(|b| b.is_zero()).unwrap_or(false) {
                            return Ok(l);
                        }
                    }
                    CircuitBinOp::Sub => {
                        if rv.map(|b| b.is_zero()).unwrap_or(false) {
                            return Ok(l);
                        }
                    }
                    CircuitBinOp::Mul => {
                        if lv.map(|a| a.is_zero()).unwrap_or(false)
                            || rv.map(|b| b.is_zero()).unwrap_or(false)
                        {
                            return Ok(self.emit_const(FieldElement::<F>::zero()));
                        }
                        if lv.map(|a| a == FieldElement::<F>::one()).unwrap_or(false) {
                            return Ok(r);
                        }
                        if rv.map(|b| b == FieldElement::<F>::one()).unwrap_or(false) {
                            return Ok(l);
                        }
                    }
                    CircuitBinOp::Div => {
                        if rv.map(|b| b == FieldElement::<F>::one()).unwrap_or(false) {
                            return Ok(l);
                        }
                    }
                }

                let v = self.fresh_var();
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
                self.set_type(v, IrType::Field);
                Ok(v)
            }
            CircuitExpr::UnaryOp { op, operand } => {
                let inner = self.emit_expr(operand)?;

                // Peephole const-fold for unary operators.
                if let Some(a) = self.const_value_of(inner) {
                    let folded = match op {
                        CircuitUnaryOp::Neg => Some(a.neg()),
                        CircuitUnaryOp::Not => Some(if a.is_zero() {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        }),
                    };
                    if let Some(fe) = folded {
                        return Ok(self.emit_const(fe));
                    }
                }

                // Lower at emission time: Not / And / Or / IsNeq / IsLe
                // never appear in instantiate output. The Lysis lifter's
                // Walker desugars them to the same primitive forms (Sub,
                // Mul, Add+Mul-Sub, IsEq+Sub, IsLt+Sub) at lift time, so
                // emitting them here would make the legacy and Lysis
                // pipelines produce different R1CS multisets even though
                // they are semantically equivalent. See
                // `.claude/plans/lysis-phase-3c6.md` Stage-1 finding.
                match op {
                    CircuitUnaryOp::Neg => {
                        let v = self.fresh_var();
                        self.push_inst(Instruction::Neg {
                            result: v,
                            operand: inner,
                        });
                        self.set_type(v, IrType::Field);
                        Ok(v)
                    }
                    CircuitUnaryOp::Not => Ok(self.lower_not(inner)),
                }
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                // See "lower at emission time" note in UnaryOp branch.
                let v = match op {
                    CircuitCmpOp::Eq => {
                        let v = self.fresh_var();
                        self.push_inst(Instruction::IsEq {
                            result: v,
                            lhs: l,
                            rhs: r,
                        });
                        v
                    }
                    CircuitCmpOp::Lt => {
                        let v = self.fresh_var();
                        self.push_inst(Instruction::IsLt {
                            result: v,
                            lhs: l,
                            rhs: r,
                        });
                        v
                    }
                    CircuitCmpOp::Gt => {
                        // a > b → IsLt(b, a)
                        let v = self.fresh_var();
                        self.push_inst(Instruction::IsLt {
                            result: v,
                            lhs: r,
                            rhs: l,
                        });
                        v
                    }
                    CircuitCmpOp::Neq => {
                        // a != b → 1 - IsEq(a, b)
                        let eq = self.fresh_var();
                        self.push_inst(Instruction::IsEq {
                            result: eq,
                            lhs: l,
                            rhs: r,
                        });
                        self.set_type(eq, IrType::Bool);
                        self.lower_not(eq)
                    }
                    CircuitCmpOp::Le => {
                        // a <= b → 1 - IsLt(b, a)
                        let lt = self.fresh_var();
                        self.push_inst(Instruction::IsLt {
                            result: lt,
                            lhs: r,
                            rhs: l,
                        });
                        self.set_type(lt, IrType::Bool);
                        self.lower_not(lt)
                    }
                    CircuitCmpOp::Ge => {
                        // a >= b → 1 - IsLt(a, b)
                        let lt = self.fresh_var();
                        self.push_inst(Instruction::IsLt {
                            result: lt,
                            lhs: l,
                            rhs: r,
                        });
                        self.set_type(lt, IrType::Bool);
                        self.lower_not(lt)
                    }
                };
                self.set_type(v, IrType::Bool);
                Ok(v)
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                // See "lower at emission time" note in UnaryOp branch.
                let v = match op {
                    CircuitBoolOp::And => {
                        // x AND y → Mul(x, y) (boolean operands).
                        let v = self.fresh_var();
                        self.push_inst(Instruction::Mul {
                            result: v,
                            lhs: l,
                            rhs: r,
                        });
                        v
                    }
                    CircuitBoolOp::Or => {
                        // x OR y → Add(x, y) - Mul(x, y) (boolean operands).
                        let sum = self.fresh_var();
                        self.push_inst(Instruction::Add {
                            result: sum,
                            lhs: l,
                            rhs: r,
                        });
                        let prod = self.fresh_var();
                        self.push_inst(Instruction::Mul {
                            result: prod,
                            lhs: l,
                            rhs: r,
                        });
                        let v = self.fresh_var();
                        self.push_inst(Instruction::Sub {
                            result: v,
                            lhs: sum,
                            rhs: prod,
                        });
                        v
                    }
                };
                self.set_type(v, IrType::Bool);
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
                let v = self.fresh_var();
                self.push_inst(Instruction::Mux {
                    result: v,
                    cond: c,
                    if_true: t,
                    if_false: f,
                });
                // Propagate type if both branches agree
                if let (Some(tt), Some(ft)) = (self.get_type(t), self.get_type(f)) {
                    if tt == ft {
                        self.set_type(v, tt);
                    }
                }
                Ok(v)
            }
            CircuitExpr::PoseidonHash { left, right } => {
                let l = self.emit_expr(left)?;
                let r = self.emit_expr(right)?;
                let v = self.fresh_var();
                self.push_inst(Instruction::PoseidonHash {
                    result: v,
                    left: l,
                    right: r,
                });
                self.set_type(v, IrType::Field);
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
                    let zero = self.emit_const(FieldElement::<F>::zero());
                    let v = self.fresh_var();
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
                    let v = self.fresh_var();
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
                let v = self.fresh_var();
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
                    let left = self.fresh_var();
                    self.push_inst(Instruction::Mux {
                        result: left,
                        cond: *idx,
                        if_true: *sibling,
                        if_false: current,
                    });
                    let right = self.fresh_var();
                    self.push_inst(Instruction::Mux {
                        result: right,
                        cond: *idx,
                        if_true: current,
                        if_false: *sibling,
                    });
                    let v = self.fresh_var();
                    self.push_inst(Instruction::PoseidonHash {
                        result: v,
                        left,
                        right,
                    });
                    current = v;
                }

                // Assert computed root == expected root
                let v = self.fresh_var();
                self.push_inst(Instruction::AssertEq {
                    result: v,
                    lhs: current,
                    rhs: root_var,
                    message: None,
                });
                Ok(v)
            }
            CircuitExpr::ArrayIndex { array, index } => {
                // Fast path 1: index is a pure compile-time constant.
                // `eval_const_expr` is side-effect-free, so trying it
                // first costs nothing and avoids polluting the IR
                // stream with an emission we'd then discard.
                if let Some(idx) = self.eval_const_expr(index).ok().and_then(|fe| {
                    let limbs = fe.to_canonical();
                    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                        usize::try_from(limbs[0]).ok()
                    } else {
                        None
                    }
                }) {
                    return self.resolve_array_at(array, idx);
                }

                // Fast path 2: emit the index expression, then check
                // whether the emitted SsaVar reduces to a literal via
                // `extract_const_index` (handles linearised forms like
                // `i*2+j` after loop unroll). Match the original
                // surface error if `emit_expr` itself errors so callers
                // see a consistent "must be compile-time constant" hit.
                let idx_var = match self.emit_expr(index) {
                    Ok(v) => v,
                    Err(_) => {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "array index into `{array}` must be a compile-time constant"
                            ),
                            span: None,
                        });
                    }
                };

                if let Some(idx) = self.extract_const_index(idx_var) {
                    return self.resolve_array_at(array, idx);
                }

                // Truly symbolic index: emit a SymbolicArrayRead that
                // the walker resolves per-iteration to
                // `array_slots[idx]`.
                self.emit_array_index_symbolic(array, idx_var)
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
                Ok(self.emit_const(FieldElement::<F>::from_u64(len as u64)))
            }
            CircuitExpr::Pow { base, exp } => {
                let base_var = self.emit_expr(base)?;
                self.emit_pow(base_var, *exp)
            }
            CircuitExpr::IntDiv { lhs, rhs, max_bits } => {
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                let v = self.fresh_var();
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
                let v = self.fresh_var();
                self.push_inst(Instruction::IntMod {
                    result: v,
                    lhs: l,
                    rhs: r,
                    max_bits: *max_bits,
                });
                Ok(v)
            }

            // ── Bitwise operations (expanded via Decompose) ────────
            // The bitwise binop's `num_bits` is the **result width**
            // (= `min(lhs_w, rhs_w)` for AND, `max` for OR/XOR), but
            // each operand needs to be Decomposed at ITS OWN width
            // — using the result width for the wider operand trips a
            // range-check failure (e.g., `(64) & 1` would Decompose
            // 64 into 1 bit). Derive each operand's width
            // structurally so the two are plumbed separately into
            // [`emit_bitwise_binop`].
            CircuitExpr::BitAnd { lhs, rhs, .. } => {
                let lhs_w = structural_op_width(lhs);
                let rhs_w = structural_op_width(rhs);
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, lhs_w, rhs_w, BitwiseOp::And)
            }
            CircuitExpr::BitOr { lhs, rhs, .. } => {
                let lhs_w = structural_op_width(lhs);
                let rhs_w = structural_op_width(rhs);
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, lhs_w, rhs_w, BitwiseOp::Or)
            }
            CircuitExpr::BitXor { lhs, rhs, .. } => {
                let lhs_w = structural_op_width(lhs);
                let rhs_w = structural_op_width(rhs);
                let l = self.emit_expr(lhs)?;
                let r = self.emit_expr(rhs)?;
                self.emit_bitwise_binop(l, r, lhs_w, rhs_w, BitwiseOp::Xor)
            }
            CircuitExpr::BitNot { operand, num_bits } => {
                let op = self.emit_expr(operand)?;
                self.emit_bitnot(op, *num_bits)
            }
            CircuitExpr::ShiftR {
                operand,
                shift,
                num_bits,
            } => self.emit_shift_dispatch(expr, operand, shift, *num_bits, ShiftDirection::Right),
            CircuitExpr::ShiftL {
                operand,
                shift,
                num_bits,
            } => self.emit_shift_dispatch(expr, operand, shift, *num_bits, ShiftDirection::Left),
        }
    }

    /// Common path for `ShiftR` / `ShiftL`. Tries const-fold (entire
    /// expression, then shift amount only) before falling back to
    /// emit-then-extract; if the shift amount is still symbolic, emits
    /// an `ExtendedInstruction::SymbolicShift` for the walker to
    /// resolve per iteration via a Decompose + recompose chain.
    fn emit_shift_dispatch(
        &mut self,
        full_expr: &CircuitExpr,
        operand: &CircuitExpr,
        shift: &CircuitExpr,
        num_bits: u32,
        direction: ShiftDirection,
    ) -> Result<SsaVar, ProveIrError> {
        let context = match direction {
            ShiftDirection::Right => "shift right amount",
            ShiftDirection::Left => "shift left amount",
        };
        // Fast path 1: both operand and shift are compile-time
        // constants — fold the entire expression to a single Const.
        if let Ok(fe) = self.eval_const_expr(full_expr) {
            return Ok(self.emit_const(fe));
        }
        let op = self.emit_expr(operand)?;
        // Fast path 2: shift folds without emitting (handles captured
        // template params like `Sigma(7, 18, 3)` where 7/18/3 ride into
        // the body as captures).
        if let Ok(fe) = self.eval_const_expr(shift) {
            let val = fe_to_u64(&fe, context)?;
            let shift_val = u32::try_from(val).map_err(|_| ProveIrError::UnsupportedOperation {
                description: format!("{context} too large for u32"),
                span: None,
            })?;
            return self.emit_shift_op(op, shift_val, num_bits, direction);
        }
        // Fast path 3: emit shift; result may still resolve to a const
        // via `extract_const_index` (post-lowering const-prop). Mirrors
        // the historical `resolve_const_u32` fallback.
        let shift_var = self.emit_expr(shift)?;
        if let Some(n) = self.extract_const_index(shift_var) {
            if let Ok(shift_val) = u32::try_from(n) {
                return self.emit_shift_op(op, shift_val, num_bits, direction);
            }
        }
        // Truly symbolic shift amount: emit a SymbolicShift that the
        // walker resolves per-iteration via a Decompose + recompose
        // chain.
        let result_var = self.fresh_var();
        let span = self.current_span.clone();
        self.sink
            .push_symbolic_shift(result_var, op, shift_var, num_bits, direction, span);
        Ok(result_var)
    }

    /// Dispatch to `emit_shift_right` / `emit_shift_left` based on
    /// direction. Centralises the branch so [`Self::emit_shift_dispatch`]
    /// and any future const-shift call site share the same pivot.
    fn emit_shift_op(
        &mut self,
        operand: SsaVar,
        shift: u32,
        num_bits: u32,
        direction: ShiftDirection,
    ) -> Result<SsaVar, ProveIrError> {
        match direction {
            ShiftDirection::Right => self.emit_shift_right(operand, shift, num_bits),
            ShiftDirection::Left => self.emit_shift_left(operand, shift, num_bits),
        }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// Resolve `array[idx]` with bounds + array-shape checking. Both
    /// const-fold paths in [`Self::emit_expr`]'s `ArrayIndex` arm route
    /// through this so the env lookup, type assertion, and bounds
    /// error stay byte-identical.
    fn resolve_array_at(&self, array: &str, idx: usize) -> Result<SsaVar, ProveIrError> {
        match self.env.get(array) {
            Some(InstEnvValue::Array(elems)) => {
                if idx >= elems.len() {
                    return Err(ProveIrError::IndexOutOfBounds {
                        name: array.to_string(),
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

    /// Symbolic-index `ArrayIndex` — emits one
    /// [`crate::ExtendedInstruction::SymbolicArrayRead`] carrying the
    /// resolved `array_slots` snapshot for the walker. Mints a fresh
    /// `result_var` to hand back to the caller; the walker rebinds it
    /// to `array_slots[idx]`'s register per iteration. Mirror of
    /// `emit_let_indexed_symbolic` on the write side.
    fn emit_array_index_symbolic(
        &mut self,
        array: &str,
        index_var: SsaVar,
    ) -> Result<SsaVar, ProveIrError> {
        let array_slots = self.snapshot_array_slots(array)?;
        let result_var = self.fresh_var();
        let span = self.current_span.clone();
        self.sink
            .push_symbolic_array_read(result_var, array_slots, index_var, span);
        Ok(result_var)
    }

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
            return Ok(self.emit_const(FieldElement::<F>::one()));
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
                        let v = self.fresh_var();
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
                let v = self.fresh_var();
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

/// Conservative upper bound on a bitwise-operand's required Decompose
/// width, derived structurally from the [`CircuitExpr`] tree.
///
/// Bitwise lowering ([`Instantiator::emit_bitwise_binop`]) needs to
/// Decompose each operand at the **operand's own** width, not at the
/// op's result width. For variants that already carry an inferred
/// `num_bits` field (Shifts, BitAnd/Or/Xor/Not) we read it directly;
/// for [`CircuitExpr::Const`] we use the literal's bit count; for
/// 1-bit-shaped variants (Comparisons, BoolOps, logical Not) we
/// return 1; for everything else we conservatively return
/// `FIELD_WIDTH` (BN254 = 254 bits — soundly accommodates any value
/// the operand could carry, at the cost of a wider Decompose). The
/// fallback rarely fires in practice — circom's bit-width inference
/// pre-tightens the relevant operand variants.
fn structural_op_width(expr: &CircuitExpr) -> u32 {
    /// BN254 field width — conservative ceiling for unknown operands.
    /// Smaller fields (Goldilocks, BLS12-381 Fr) all fit under this
    /// bound, so the over-Decompose stays sound across backends.
    const FIELD_WIDTH: u32 = 254;

    match expr {
        CircuitExpr::Const(fc) => {
            // `bits` = position of the highest set bit + 1, scanning
            // the LE byte string from the high end down. Returns 0
            // for the zero constant.
            let bytes = fc.bytes();
            let mut w: u32 = 0;
            for (i, &b) in bytes.iter().enumerate() {
                if b != 0 {
                    let high = 8 - b.leading_zeros();
                    w = (i as u32) * 8 + high;
                }
            }
            w
        }
        CircuitExpr::ShiftR { num_bits, .. }
        | CircuitExpr::ShiftL { num_bits, .. }
        | CircuitExpr::BitAnd { num_bits, .. }
        | CircuitExpr::BitOr { num_bits, .. }
        | CircuitExpr::BitXor { num_bits, .. }
        | CircuitExpr::BitNot { num_bits, .. } => *num_bits,
        CircuitExpr::Comparison { .. } | CircuitExpr::BoolOp { .. } => 1,
        CircuitExpr::UnaryOp {
            op: CircuitUnaryOp::Not,
            ..
        } => 1,
        // Capture/Var/Input/Mux/BinOp/Pow/Hash/MerkleVerify/RangeCheck/
        // ArrayIndex/ArrayLen/IntDiv/IntMod/LoopVar — no inferred-width
        // field and no general structural answer that's tighter than
        // the field. The conservative fallback over-Decomposes but
        // stays sound.
        _ => FIELD_WIDTH,
    }
}
