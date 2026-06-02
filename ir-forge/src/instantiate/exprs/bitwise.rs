use memory::FieldBackend;

use super::super::utils::fe_to_u64;
use super::super::{BitwiseOp, Instantiator};
use crate::error::ProveIrError;
use crate::extended::ShiftDirection;
use crate::types::*;
use ir_core::SsaVar;

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn emit_bitwise_binop_expr(
        &mut self,
        full_expr: &CircuitExpr,
        lhs: &CircuitExpr,
        rhs: &CircuitExpr,
        op: BitwiseOp,
    ) -> Result<SsaVar, ProveIrError> {
        // Fast path: full expression folds to a const (mirror of
        // `emit_shift_dispatch`'s fast path 1). Skips emitting the
        // Decompose chain for both operands when the result is statically
        // determined — typically fires inside an eager-unrolled loop where
        // the iter var is bound to a Const SSA, exposing the full
        // expression's constness.
        if let Ok(fe) = self.eval_const_expr(full_expr) {
            return Ok(self.emit_const(fe));
        }
        let lhs_w = structural_op_width(lhs);
        let rhs_w = structural_op_width(rhs);
        let l = self.emit_expr(lhs)?;
        let r = self.emit_expr(rhs)?;
        self.emit_bitwise_binop(l, r, lhs_w, rhs_w, op)
    }

    pub(super) fn emit_bitnot_expr(
        &mut self,
        full_expr: &CircuitExpr,
        operand: &CircuitExpr,
        num_bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        if let Ok(fe) = self.eval_const_expr(full_expr) {
            return Ok(self.emit_const(fe));
        }
        let op = self.emit_expr(operand)?;
        self.emit_bitnot(op, num_bits)
    }

    /// Common path for `ShiftR` / `ShiftL`. Tries const-fold (entire
    /// expression, then shift amount only) before falling back to
    /// emit-then-extract; if the shift amount is still symbolic, emits an
    /// `ExtendedInstruction::SymbolicShift` for the walker to resolve per
    /// iteration via a Decompose + recompose chain.
    pub(super) fn emit_shift_dispatch(
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
        // Fast path 1: both operand and shift are compile-time constants —
        // fold the entire expression to a single Const.
        if let Ok(fe) = self.eval_const_expr(full_expr) {
            return Ok(self.emit_const(fe));
        }
        let op = self.emit_expr(operand)?;
        // Fast path 2: shift folds without emitting (handles captured
        // template params like `Sigma(7, 18, 3)` where 7/18/3 ride into the
        // body as captures).
        if let Ok(fe) = self.eval_const_expr(shift) {
            let val = fe_to_u64(&fe, context)?;
            let shift_val = u32::try_from(val).map_err(|_| ProveIrError::UnsupportedOperation {
                description: format!("{context} too large for u32"),
                span: None,
            })?;
            return self.emit_shift_op(op, shift_val, num_bits, direction);
        }
        // Fast path 3: emit shift; result may still resolve to a const via
        // `extract_const_index` (post-lowering const-prop). Mirrors the
        // historical `resolve_const_u32` fallback.
        let shift_var = self.emit_expr(shift)?;
        if let Some(n) = self.extract_const_index(shift_var) {
            if let Ok(shift_val) = u32::try_from(n) {
                return self.emit_shift_op(op, shift_val, num_bits, direction);
            }
        }
        // Truly symbolic shift amount: emit a SymbolicShift that the walker
        // resolves per-iteration via a Decompose + recompose chain.
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
}

/// Conservative upper bound on a bitwise-operand's required Decompose
/// width, derived structurally from the [`CircuitExpr`] tree.
///
/// Bitwise lowering ([`Instantiator::emit_bitwise_binop`]) needs to
/// Decompose each operand at the **operand's own** width, not at the op's
/// result width. For variants that already carry an inferred `num_bits`
/// field (Shifts, BitAnd/Or/Xor/Not) we read it directly; for
/// [`CircuitExpr::Const`] we use the literal's bit count; for 1-bit-shaped
/// variants (Comparisons, BoolOps, logical Not) we return 1; for everything
/// else we conservatively return `FIELD_WIDTH` (BN254 = 254 bits — soundly
/// accommodates any value the operand could carry, at the cost of a wider
/// Decompose). The fallback rarely fires in practice — circom's bit-width
/// inference pre-tightens the relevant operand variants.
fn structural_op_width(expr: &CircuitExpr) -> u32 {
    /// BN254 field width — conservative ceiling for unknown operands. Smaller
    /// fields (Goldilocks, BLS12-381 Fr) all fit under this bound, so the
    /// over-Decompose stays sound across backends.
    const FIELD_WIDTH: u32 = 254;

    match expr {
        CircuitExpr::Const(fc) => {
            // `bits` = position of the highest set bit + 1, scanning the LE
            // byte string from the high end down. Returns 0 for the zero
            // constant.
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
        // field and no general structural answer that's tighter than the
        // field. The conservative fallback over-Decomposes but stays sound.
        _ => FIELD_WIDTH,
    }
}
