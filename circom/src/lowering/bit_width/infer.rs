use ir_forge::types::{CircuitBinOp, CircuitExpr, CircuitUnaryOp, FieldConst};

use super::{BitWidth, InferenceCtx, FIELD_BITS};

/// Bit-length of a `FieldConst` interpreted as an unsigned integer.
/// Returns `0` for the zero constant; `1` for `1`; `n` for a value in
/// `[2^(n-1), 2^n)`.
pub(super) fn bits_of_field_const(fc: &FieldConst) -> u32 {
    // FieldConst is stored as 32 little-endian bytes. Walk bytes
    // MSB-first to find the highest non-zero one.
    let bytes = fc.bytes();
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b != 0 {
            let byte_msb = 8 - b.leading_zeros();
            return byte_msb + (i as u32) * 8;
        }
    }
    0
}

/// Stage 1 inference for `CircuitExpr`. Returns a sound upper bound
/// on the runtime value's bit-width.
pub fn infer_expr(expr: &CircuitExpr, ctx: &InferenceCtx<'_>) -> BitWidth {
    match expr {
        // ---- Leaves ----
        CircuitExpr::Const(fc) => BitWidth::Exact(bits_of_field_const(fc)),
        // R1″ placeholder: at iter-0 capture time we have no bound on
        // the future iter value, so return Field. Once substituted to
        // Const(N) for a real iteration, this site re-runs (or the
        // captured IR is re-inferred) and tightens.
        CircuitExpr::LoopVar(_) => BitWidth::Field,
        CircuitExpr::Capture(name) | CircuitExpr::Var(name) => {
            // First try compile-time constant resolution via
            // param_values / known_constants — yields exact width.
            if let Some(fc) = ctx.lookup(name) {
                return BitWidth::Exact(bits_of_field_const(&fc));
            }
            // Stage 2: Var may also be a constrained signal whose
            // bit-width is recorded in the side-table (e.g., outputs
            // of an inlined Num2Bits(n)). Default to Field if absent.
            ctx.lookup_signal_width(name).unwrap_or(BitWidth::Field)
        }
        // Stage 2: Input signal — consult the constraint side-table
        // populated by the lowering pipeline. Each output bit of an
        // inlined `Num2Bits(n)` is registered as `Exact(1)`; signals
        // without provenance default to `Field`.
        CircuitExpr::Input(name) => ctx.lookup_signal_width(name).unwrap_or(BitWidth::Field),

        // ---- Predicate-shaped exprs always produce 0 or 1 ----
        CircuitExpr::Comparison { .. } | CircuitExpr::BoolOp { .. } => BitWidth::Exact(1),

        // ---- Bitwise ops ----
        CircuitExpr::BitAnd { lhs, rhs, .. } => {
            // AND can only narrow: result has at most min(lhs, rhs) bits.
            let l = infer_expr(lhs, ctx);
            let r = infer_expr(rhs, ctx);
            min_width(l, r)
        }
        CircuitExpr::BitOr { lhs, rhs, .. } | CircuitExpr::BitXor { lhs, rhs, .. } => {
            // OR/XOR cap at max(lhs, rhs) bits.
            let l = infer_expr(lhs, ctx);
            let r = infer_expr(rhs, ctx);
            max_width(l, r)
        }
        CircuitExpr::BitNot { num_bits, .. } => {
            // BitNot's width is the explicitly declared num_bits — the
            // result is the bitwise complement within that fixed
            // window. Inferring tighter would require knowing the
            // operand's width *and* trusting that all higher bits are
            // zero in the operand's range, which holds when the
            // operand inference is also bit-bounded. Stage 2 may
            // tighten this.
            BitWidth::widen(*num_bits)
        }

        // ---- Mux: branch join ----
        CircuitExpr::Mux {
            if_true, if_false, ..
        } => {
            let t = infer_expr(if_true, ctx);
            let f = infer_expr(if_false, ctx);
            t.join(f)
        }

        // ---- UnaryOp ----
        CircuitExpr::UnaryOp { op, operand: _ } => match op {
            // Logical Not produces 0 or 1.
            CircuitUnaryOp::Not => BitWidth::Exact(1),
            // Field negation maps `x` to `p - x` (or `0` if `x == 0`),
            // which spans the whole field. No width tightening
            // possible without a sign-bit model.
            CircuitUnaryOp::Neg => BitWidth::Field,
        },

        // ---- BinOp arithmetic propagation (Stage 2) ----
        // - Add: max(lhs, rhs) + 1 — accommodates carry. Saturates at
        //   FIELD_BITS via `widen`, so adding 32-bit values 224 times
        //   correctly degrades to `Field` instead of u32-wrapping.
        // - Mul: lhs + rhs — total bit-width.
        // - Sub / Div: `Field` — modular borrow / inverse can land
        //   anywhere in `[0, p)`.
        CircuitExpr::BinOp { op, lhs, rhs } => match op {
            CircuitBinOp::Add => {
                let l = infer_expr(lhs, ctx).to_num_bits();
                let r = infer_expr(rhs, ctx).to_num_bits();
                BitWidth::widen(l.max(r).saturating_add(1))
            }
            CircuitBinOp::Mul => {
                let l = infer_expr(lhs, ctx).to_num_bits();
                let r = infer_expr(rhs, ctx).to_num_bits();
                BitWidth::widen(l.saturating_add(r))
            }
            CircuitBinOp::Sub | CircuitBinOp::Div => BitWidth::Field,
        },

        // ---- Hashes / Merkle / RangeCheck ----
        CircuitExpr::PoseidonHash { .. } | CircuitExpr::PoseidonMany(_) => BitWidth::Field,
        CircuitExpr::MerkleVerify { .. } => BitWidth::Exact(1),
        CircuitExpr::RangeCheck { bits, .. } => {
            // RangeCheck is itself a typed bound — the inferred width
            // mirrors the constraint exactly. (RangeCheck appears
            // mid-expression rarely; usually it's a statement-level
            // assertion. Including it for completeness.)
            BitWidth::Exact(*bits)
        }

        // ---- Array / runtime-only nodes ----
        // Array indexing depends on element type, which Stage 1 has
        // no view into. Stage 2 will plumb the array-element-width
        // table.
        CircuitExpr::ArrayIndex { .. } | CircuitExpr::ArrayLen(_) => BitWidth::Field,

        // ---- Pow / IntDiv / IntMod ----
        CircuitExpr::Pow { .. } => BitWidth::Field,
        CircuitExpr::IntDiv { max_bits, .. } | CircuitExpr::IntMod { max_bits, .. } => {
            BitWidth::widen(*max_bits)
        }

        // ---- Shifts ----
        CircuitExpr::ShiftR { operand, shift, .. } => {
            // Right shift can only narrow: if the shift amount is a
            // compile-time constant, subtract it from the operand's
            // bit-width.
            let op_w = infer_expr(operand, ctx);
            if let Some(s) = const_eval_shift(shift, ctx) {
                shift_right_width(op_w, s)
            } else {
                // Symbolic shift — the result spans up to the operand's
                // full width.
                op_w
            }
        }
        CircuitExpr::ShiftL { operand, shift, .. } => {
            // Left shift widens by the shift amount, saturating at
            // field-width.
            let op_w = infer_expr(operand, ctx);
            if let Some(s) = const_eval_shift(shift, ctx) {
                shift_left_width(op_w, s)
            } else {
                BitWidth::Field
            }
        }
    }
}

/// `min` over `BitWidth`'s lattice. Used by `BitAnd`.
pub(super) fn min_width(a: BitWidth, b: BitWidth) -> BitWidth {
    match (a, b) {
        (BitWidth::Exact(x), BitWidth::Exact(y)) => BitWidth::Exact(x.min(y)),
        (BitWidth::Exact(x), BitWidth::AtMost(y))
        | (BitWidth::AtMost(x), BitWidth::Exact(y))
        | (BitWidth::AtMost(x), BitWidth::AtMost(y)) => BitWidth::AtMost(x.min(y)),
        (BitWidth::Exact(x), BitWidth::Field) | (BitWidth::AtMost(x), BitWidth::Field) => {
            BitWidth::AtMost(x)
        }
        (BitWidth::Field, BitWidth::Exact(y)) | (BitWidth::Field, BitWidth::AtMost(y)) => {
            BitWidth::AtMost(y)
        }
        (BitWidth::Field, BitWidth::Field) => BitWidth::Field,
    }
}

/// `max` over `BitWidth`'s lattice. Used by `BitOr` / `BitXor`.
pub(super) fn max_width(a: BitWidth, b: BitWidth) -> BitWidth {
    match (a, b) {
        (BitWidth::Field, _) | (_, BitWidth::Field) => BitWidth::Field,
        (BitWidth::Exact(x), BitWidth::Exact(y)) if x == y => BitWidth::Exact(x),
        (BitWidth::Exact(x), BitWidth::Exact(y))
        | (BitWidth::Exact(x), BitWidth::AtMost(y))
        | (BitWidth::AtMost(x), BitWidth::Exact(y))
        | (BitWidth::AtMost(x), BitWidth::AtMost(y)) => BitWidth::AtMost(x.max(y)),
    }
}

/// `ShiftR` width rule — narrows by `shift` bits, clamped to 0.
fn shift_right_width(op_w: BitWidth, shift: u32) -> BitWidth {
    match op_w {
        BitWidth::Exact(n) => BitWidth::AtMost(n.saturating_sub(shift)),
        BitWidth::AtMost(n) => BitWidth::AtMost(n.saturating_sub(shift)),
        BitWidth::Field => BitWidth::AtMost(FIELD_BITS.saturating_sub(shift)),
    }
}

/// `ShiftL` width rule — widens by `shift` bits, saturating at
/// `FIELD_BITS`.
fn shift_left_width(op_w: BitWidth, shift: u32) -> BitWidth {
    let n = op_w.to_num_bits();
    BitWidth::widen(n.saturating_add(shift))
}

/// Try to const-fold a shift expression to a concrete `u32` amount.
/// Stage 1 handles the simple cases: literal constants and captures
/// bound to literals. Anything more complex (e.g. arithmetic on
/// captures) falls through to `None`.
fn const_eval_shift(expr: &CircuitExpr, ctx: &InferenceCtx<'_>) -> Option<u32> {
    let fc = match expr {
        CircuitExpr::Const(fc) => *fc,
        CircuitExpr::Capture(name) | CircuitExpr::Var(name) => ctx.lookup(name)?,
        _ => return None,
    };
    let bits = bits_of_field_const(&fc);
    if bits > 32 {
        return None;
    }
    // Field constants are stored as 32 little-endian bytes; values
    // that fit in u32 occupy the first 4 bytes.
    fc.to_u64().and_then(|v| u32::try_from(v).ok())
}
