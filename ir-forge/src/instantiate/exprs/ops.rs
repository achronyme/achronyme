use memory::{FieldBackend, FieldElement};

use super::super::Instantiator;
use crate::error::ProveIrError;
use crate::types::*;
use ir_core::{Instruction, IrType, SsaVar};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn emit_binop(
        &mut self,
        op: CircuitBinOp,
        lhs: &CircuitExpr,
        rhs: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
        let l = self.emit_expr(lhs)?;
        let r = self.emit_expr(rhs)?;

        // Peephole const-fold: if both operands are known constants,
        // compute at emit time and emit a deduped Const. If only one is a
        // known identity/annihilator, short-circuit to the other operand
        // (or a zero const). These rules mirror `ir::passes::const_fold`
        // but run *during* instantiate, keeping the instruction stream
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

    pub(super) fn emit_unary(
        &mut self,
        op: CircuitUnaryOp,
        operand: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
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

        // Lower at emission time: Not / And / Or / IsNeq / IsLe never
        // appear in instantiate output. The Lysis lifter's Walker
        // desugars them to the same primitive forms (Sub, Mul, Add and
        // Mul minus Sub, IsEq and Sub, IsLt and Sub) at lift time, so
        // emitting them here would make the legacy and Lysis pipelines
        // produce different R1CS multisets even though they are
        // semantically equivalent.
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

    pub(super) fn emit_comparison(
        &mut self,
        op: CircuitCmpOp,
        lhs: &CircuitExpr,
        rhs: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
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

    pub(super) fn emit_boolop(
        &mut self,
        op: CircuitBoolOp,
        lhs: &CircuitExpr,
        rhs: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
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

    pub(super) fn emit_mux(
        &mut self,
        cond: &CircuitExpr,
        if_true: &CircuitExpr,
        if_false: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
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
}
