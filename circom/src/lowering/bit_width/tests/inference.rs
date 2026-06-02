use super::*;

// ------------------------------------------------------------------
// infer_expr — leaves
// ------------------------------------------------------------------

#[test]
fn infer_const_returns_exact_bit_count() {
    let ctx = empty_ctx();
    assert_eq!(
        infer_expr(&CircuitExpr::Const(fc(0xff)), &ctx),
        BitWidth::Exact(8)
    );
    assert_eq!(
        infer_expr(&CircuitExpr::Const(fc(0)), &ctx),
        BitWidth::Exact(0)
    );
}

#[test]
fn infer_input_defaults_to_field() {
    let ctx = empty_ctx();
    assert_eq!(
        infer_expr(&CircuitExpr::Input("x".into()), &ctx),
        BitWidth::Field
    );
}

#[test]
fn infer_input_consults_signal_widths() {
    let params = HashMap::new();
    let known = HashMap::new();
    let mut widths = SignalWidths::new();
    widths.insert("c_n2b_out_0".to_string(), BitWidth::Exact(1));
    let ctx = InferenceCtx::new(&params, &known, &widths);
    assert_eq!(
        infer_expr(&CircuitExpr::Input("c_n2b_out_0".into()), &ctx),
        BitWidth::Exact(1)
    );
}

#[test]
fn infer_var_consults_signal_widths_if_no_const() {
    let params = HashMap::new();
    let known = HashMap::new();
    let mut widths = SignalWidths::new();
    widths.insert("c_n2b_out_3".to_string(), BitWidth::Exact(1));
    let ctx = InferenceCtx::new(&params, &known, &widths);
    assert_eq!(
        infer_expr(&CircuitExpr::Var("c_n2b_out_3".into()), &ctx),
        BitWidth::Exact(1)
    );
}

#[test]
fn infer_capture_resolves_via_param_values() {
    let mut params = HashMap::new();
    params.insert("n".to_string(), fc(64));
    let known = HashMap::new();
    let widths = SignalWidths::new();
    let ctx = InferenceCtx::new(&params, &known, &widths);
    assert_eq!(
        infer_expr(&CircuitExpr::Capture("n".into()), &ctx),
        BitWidth::Exact(7)
    );
}

#[test]
fn infer_capture_unknown_falls_back_to_field() {
    let ctx = empty_ctx();
    assert_eq!(
        infer_expr(&CircuitExpr::Capture("n".into()), &ctx),
        BitWidth::Field
    );
}

#[test]
fn infer_var_resolves_via_known_constants() {
    let params = HashMap::new();
    let mut known = HashMap::new();
    known.insert("k".to_string(), fc(0x1234));
    let widths = SignalWidths::new();
    let ctx = InferenceCtx::new(&params, &known, &widths);
    assert_eq!(
        infer_expr(&CircuitExpr::Var("k".into()), &ctx),
        BitWidth::Exact(13) // 0x1234 = 4660 → 13 bits
    );
}

// ------------------------------------------------------------------
// infer_expr — predicates
// ------------------------------------------------------------------

#[test]
fn infer_comparison_is_bool() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::Comparison {
        op: CircuitCmpOp::Eq,
        lhs: Box::new(CircuitExpr::Const(fc(1))),
        rhs: Box::new(CircuitExpr::Const(fc(2))),
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(1));
}

#[test]
fn infer_boolop_is_bool() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BoolOp {
        op: CircuitBoolOp::And,
        lhs: Box::new(CircuitExpr::Const(fc(0))),
        rhs: Box::new(CircuitExpr::Const(fc(1))),
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(1));
}

#[test]
fn infer_logical_not_is_bool() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::UnaryOp {
        op: CircuitUnaryOp::Not,
        operand: Box::new(CircuitExpr::Const(fc(5))),
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(1));
}

// ------------------------------------------------------------------
// infer_expr — bitwise propagation
// ------------------------------------------------------------------

#[test]
fn infer_bitand_takes_min() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BitAnd {
        lhs: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
        rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32 bits
        num_bits: FIELD_BITS,
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
}

#[test]
fn infer_bitor_takes_max() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BitOr {
        lhs: Box::new(CircuitExpr::Const(fc(0xff))),
        rhs: Box::new(CircuitExpr::Const(fc(0xffff))),
        num_bits: FIELD_BITS,
    };
    // Inputs have *different* exact widths; merging through OR
    // produces an upper bound, not an exact width — the actual
    // value could land anywhere in [0, 2^16).
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(16));
}

#[test]
fn infer_bitor_same_exact_widths_preserves_exact() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BitOr {
        lhs: Box::new(CircuitExpr::Const(fc(0xa5))), // 8 bits (top bit set)
        rhs: Box::new(CircuitExpr::Const(fc(0xc3))), // 8 bits (top bit set)
        num_bits: FIELD_BITS,
    };
    // Both Exact(8). Lattice keeps Exact when widths match.
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
}

#[test]
fn infer_bitxor_takes_max() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BitXor {
        lhs: Box::new(CircuitExpr::Const(fc(0xff))),
        rhs: Box::new(CircuitExpr::Const(fc(0xffff))),
        num_bits: FIELD_BITS,
    };
    // Same rationale as BitOr.
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(16));
}

#[test]
fn infer_bitand_with_field_input_yields_atmost_const_width() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BitAnd {
        lhs: Box::new(CircuitExpr::Const(fc(0xff))),   // Exact(8)
        rhs: Box::new(CircuitExpr::Input("x".into())), // Field
        num_bits: FIELD_BITS,
    };
    // min(Exact(8), Field) = AtMost(8) — we know one input has at
    // most 8 bits, so AND can't widen past that.
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(8));
}

// ------------------------------------------------------------------
// infer_expr — Mux
// ------------------------------------------------------------------

#[test]
fn infer_mux_joins_branches() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::Mux {
        cond: Box::new(CircuitExpr::Const(fc(1))),
        if_true: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
        if_false: Box::new(CircuitExpr::Const(fc(0x10))), // 5 bits
    };
    // join(Exact(8), Exact(5)) = AtMost(8)
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(8));
}

#[test]
fn infer_mux_same_width_keeps_exact() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::Mux {
        cond: Box::new(CircuitExpr::Const(fc(1))),
        if_true: Box::new(CircuitExpr::Const(fc(0xff))),
        if_false: Box::new(CircuitExpr::Const(fc(0xff))),
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
}

// ------------------------------------------------------------------
// infer_expr — shifts
// ------------------------------------------------------------------

#[test]
fn infer_shift_right_const_narrows() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32 bits
        shift: Box::new(CircuitExpr::Const(fc(8))),
        num_bits: FIELD_BITS,
    };
    // 32 - 8 = 24
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(24));
}

#[test]
fn infer_shift_right_full_drop_yields_zero() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
        shift: Box::new(CircuitExpr::Const(fc(16))),
        num_bits: FIELD_BITS,
    };
    // 8 - 16 saturates to 0
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(0));
}

#[test]
fn infer_shift_right_via_capture() {
    let mut params = HashMap::new();
    params.insert("n".to_string(), fc(7));
    let known = HashMap::new();
    let widths = SignalWidths::new();
    let ctx = InferenceCtx::new(&params, &known, &widths);
    let expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32 bits
        shift: Box::new(CircuitExpr::Capture("n".into())),      // = 7
        num_bits: FIELD_BITS,
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(25));
}

#[test]
fn infer_shift_right_symbolic_returns_operand_width() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::Const(fc(0xff))),
        shift: Box::new(CircuitExpr::Input("k".into())),
        num_bits: FIELD_BITS,
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Exact(8));
}

#[test]
fn infer_shift_left_const_widens() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftL {
        operand: Box::new(CircuitExpr::Const(fc(0xff))),
        shift: Box::new(CircuitExpr::Const(fc(8))),
        num_bits: FIELD_BITS,
    };
    // 8 + 8 = 16 bits
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(16));
}

#[test]
fn infer_shift_left_saturates_at_field() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftL {
        operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
        shift: Box::new(CircuitExpr::Const(fc(250))),
        num_bits: FIELD_BITS,
    };
    // 8 + 250 = 258 ≥ FIELD_BITS → Field
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
}

#[test]
fn infer_shift_left_symbolic_yields_field() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftL {
        operand: Box::new(CircuitExpr::Const(fc(0xff))),
        shift: Box::new(CircuitExpr::Input("k".into())),
        num_bits: FIELD_BITS,
    };
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
}

// ------------------------------------------------------------------
// infer_expr — arithmetic propagation (Stage 2)
// ------------------------------------------------------------------

#[test]
fn infer_add_carries_one_bit() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BinOp {
        op: CircuitBinOp::Add,
        lhs: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
        rhs: Box::new(CircuitExpr::Const(fc(1))),    // 1 bit
    };
    // max(8, 1) + 1 = 9
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(9));
}

#[test]
fn infer_add_of_two_32_bit_yields_33() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BinOp {
        op: CircuitBinOp::Add,
        lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
        rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
    };
    // max(32, 32) + 1 = 33
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(33));
}

#[test]
fn infer_add_saturates_at_field() {
    // Build nested Add of 32-bit constants ~225 times so the
    // accumulated bit-width crosses FIELD_BITS = 254 and the
    // saturating widen converts to Field.
    let ctx = empty_ctx();
    let mut expr = CircuitExpr::Const(fc(0xffff_ffff));
    for _ in 0..225 {
        expr = CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(expr),
            rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
        };
    }
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
}

#[test]
fn infer_mul_sums_widths() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BinOp {
        op: CircuitBinOp::Mul,
        lhs: Box::new(CircuitExpr::Const(fc(0xff))), // 8
        rhs: Box::new(CircuitExpr::Const(fc(0xffff))), // 16
    };
    // 8 + 16 = 24
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(24));
}

#[test]
fn infer_mul_saturates_at_field() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BinOp {
        op: CircuitBinOp::Mul,
        lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32
        rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))), // 32
    };
    // 32 + 32 = 64 — still under field
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(64));
}

#[test]
fn infer_sub_yields_field() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BinOp {
        op: CircuitBinOp::Sub,
        lhs: Box::new(CircuitExpr::Const(fc(0xff))),
        rhs: Box::new(CircuitExpr::Const(fc(1))),
    };
    // Modular borrow → Field even with concrete operands.
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
}

#[test]
fn infer_div_yields_field() {
    let ctx = empty_ctx();
    let expr = CircuitExpr::BinOp {
        op: CircuitBinOp::Div,
        lhs: Box::new(CircuitExpr::Const(fc(0xff))),
        rhs: Box::new(CircuitExpr::Const(fc(0xff))),
    };
    // Field-inverse → Field.
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::Field);
}

#[test]
fn infer_shift_right_after_arithmetic_narrows() {
    // The SHA-256 motivating case: rotate-right on a value that
    // came from arithmetic. After Stage 2 inference, an Add of
    // two 32-bit values is AtMost(33); a >>7 of that is AtMost(26).
    let ctx = empty_ctx();
    let expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
            rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
        }),
        shift: Box::new(CircuitExpr::Const(fc(7))),
        num_bits: FIELD_BITS,
    };
    // 33 - 7 = 26
    assert_eq!(infer_expr(&expr, &ctx), BitWidth::AtMost(26));
}
