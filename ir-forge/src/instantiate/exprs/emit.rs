use memory::FieldBackend;

use super::super::Instantiator;
use crate::error::ProveIrError;
use crate::extended::ShiftDirection;
use crate::types::*;
use ir_core::{Instruction, SsaVar};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(in super::super) fn emit_expr(
        &mut self,
        expr: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
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
            CircuitExpr::BinOp { op, lhs, rhs } => self.emit_binop(*op, lhs, rhs),
            CircuitExpr::UnaryOp { op, operand } => self.emit_unary(*op, operand),
            CircuitExpr::Comparison { op, lhs, rhs } => self.emit_comparison(*op, lhs, rhs),
            CircuitExpr::BoolOp { op, lhs, rhs } => self.emit_boolop(*op, lhs, rhs),
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => self.emit_mux(cond, if_true, if_false),
            CircuitExpr::PoseidonHash { left, right } => self.emit_poseidon_pair(left, right),
            CircuitExpr::PoseidonMany(args) => self.emit_poseidon_many(args),
            CircuitExpr::RangeCheck { value, bits } => self.emit_range_check(value, *bits),
            CircuitExpr::MerkleVerify {
                root,
                leaf,
                path,
                indices,
            } => self.emit_merkle_verify(root, leaf, path, indices),
            CircuitExpr::ArrayIndex { array, index } => self.emit_array_index(array, index),
            CircuitExpr::ArrayLen(name) => self.emit_array_len(name),
            CircuitExpr::Pow { base, exp } => {
                let base_var = self.emit_expr(base)?;
                self.emit_pow(base_var, *exp)
            }
            CircuitExpr::IntDiv { lhs, rhs, max_bits } => self.emit_int_div(lhs, rhs, *max_bits),
            CircuitExpr::IntMod { lhs, rhs, max_bits } => self.emit_int_mod(lhs, rhs, *max_bits),

            // ── Bitwise operations (expanded via Decompose) ────────
            // The bitwise binop's `num_bits` is the **result width**
            // (= `min(lhs_w, rhs_w)` for AND, `max` for OR/XOR), but
            // each operand needs to be Decomposed at ITS OWN width
            // — using the result width for the wider operand trips a
            // range-check failure (e.g., `(64) & 1` would Decompose
            // 64 into 1 bit). Derive each operand's width
            // structurally so the two are plumbed separately into
            // [`Instantiator::emit_bitwise_binop`].
            CircuitExpr::BitAnd { lhs, rhs, .. } => {
                self.emit_bitwise_binop_expr(expr, lhs, rhs, super::super::BitwiseOp::And)
            }
            CircuitExpr::BitOr { lhs, rhs, .. } => {
                self.emit_bitwise_binop_expr(expr, lhs, rhs, super::super::BitwiseOp::Or)
            }
            CircuitExpr::BitXor { lhs, rhs, .. } => {
                self.emit_bitwise_binop_expr(expr, lhs, rhs, super::super::BitwiseOp::Xor)
            }
            CircuitExpr::BitNot { operand, num_bits } => {
                self.emit_bitnot_expr(expr, operand, *num_bits)
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

    pub(super) fn emit_int_div(
        &mut self,
        lhs: &CircuitExpr,
        rhs: &CircuitExpr,
        max_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        let l = self.emit_expr(lhs)?;
        let r = self.emit_expr(rhs)?;
        let v = self.fresh_var();
        self.push_inst(Instruction::IntDiv {
            result: v,
            lhs: l,
            rhs: r,
            max_bits,
        });
        Ok(v)
    }

    pub(super) fn emit_int_mod(
        &mut self,
        lhs: &CircuitExpr,
        rhs: &CircuitExpr,
        max_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        let l = self.emit_expr(lhs)?;
        let r = self.emit_expr(rhs)?;
        let v = self.fresh_var();
        self.push_inst(Instruction::IntMod {
            result: v,
            lhs: l,
            rhs: r,
            max_bits,
        });
        Ok(v)
    }
}
