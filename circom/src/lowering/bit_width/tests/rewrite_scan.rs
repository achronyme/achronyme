use super::*;

// ------------------------------------------------------------------
// rewrite_num_bits_in_expr — IR mutation pass
// ------------------------------------------------------------------

#[test]
fn rewrite_tightens_shift_r_num_bits() {
    let ctx = empty_ctx();
    let mut expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
        shift: Box::new(CircuitExpr::Const(fc(3))),
        num_bits: FIELD_BITS, // 254
    };
    rewrite_num_bits_in_expr(&mut expr, &ctx);
    match &expr {
        CircuitExpr::ShiftR { num_bits, .. } => assert_eq!(*num_bits, 8),
        _ => panic!("expected ShiftR"),
    }
}

#[test]
fn rewrite_tightens_via_signal_widths() {
    // SHA-256 motivating case: signal `bit_0` is `Exact(1)` from
    // Num2Bits; a `BitOr(bit_0, bit_1)` should drop num_bits from
    // 254 to 1.
    let params = HashMap::new();
    let known = HashMap::new();
    let mut widths = SignalWidths::new();
    widths.insert("bit_0".to_string(), BitWidth::Exact(1));
    widths.insert("bit_1".to_string(), BitWidth::Exact(1));
    let ctx = InferenceCtx::new(&params, &known, &widths);
    let mut expr = CircuitExpr::BitOr {
        lhs: Box::new(CircuitExpr::Input("bit_0".into())),
        rhs: Box::new(CircuitExpr::Input("bit_1".into())),
        num_bits: FIELD_BITS,
    };
    rewrite_num_bits_in_expr(&mut expr, &ctx);
    match &expr {
        CircuitExpr::BitOr { num_bits, .. } => assert_eq!(*num_bits, 1),
        _ => panic!("expected BitOr"),
    }
}

#[test]
fn rewrite_does_not_loosen() {
    // num_bits already tighter than inferred — must not raise.
    let ctx = empty_ctx();
    let mut expr = CircuitExpr::BitAnd {
        lhs: Box::new(CircuitExpr::Const(fc(0xff_ffff))), // 24 bits
        rhs: Box::new(CircuitExpr::Const(fc(0xff_ffff))),
        num_bits: 8, // pre-tightened to 8 (would imply user intent)
    };
    rewrite_num_bits_in_expr(&mut expr, &ctx);
    match &expr {
        CircuitExpr::BitAnd { num_bits, .. } => {
            // Inferred would be Exact(24); we must NOT raise from 8.
            assert_eq!(*num_bits, 8);
        }
        _ => panic!("expected BitAnd"),
    }
}

#[test]
fn rewrite_recurses_into_nested() {
    let ctx = empty_ctx();
    let mut expr = CircuitExpr::Mux {
        cond: Box::new(CircuitExpr::Const(fc(1))),
        if_true: Box::new(CircuitExpr::ShiftR {
            operand: Box::new(CircuitExpr::Const(fc(0xff))), // 8 bits
            shift: Box::new(CircuitExpr::Const(fc(2))),
            num_bits: FIELD_BITS,
        }),
        if_false: Box::new(CircuitExpr::Const(fc(0))),
    };
    rewrite_num_bits_in_expr(&mut expr, &ctx);
    match &expr {
        CircuitExpr::Mux { if_true, .. } => match if_true.as_ref() {
            CircuitExpr::ShiftR { num_bits, .. } => assert_eq!(*num_bits, 8),
            _ => panic!("expected ShiftR inside Mux"),
        },
        _ => panic!("expected Mux"),
    }
}

// ------------------------------------------------------------------
// scan_bool_constraints — Num2Bits pattern detection
// ------------------------------------------------------------------

#[test]
fn scan_detects_bool_constraint() {
    let prove_ir = ir_forge::types::ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![make_bool_assertion("c_out_0")],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let widths = scan_bool_constraints(&prove_ir);
    assert_eq!(widths.get("c_out_0").copied(), Some(BitWidth::Exact(1)));
}

#[test]
fn scan_detects_swapped_assertion_sides() {
    // `0 === x * (x - 1)` (rhs is the Mul) should still match.
    let prove_ir = ir_forge::types::ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![ir_forge::types::CircuitNode::AssertEq {
            lhs: CircuitExpr::Const(FieldConst::zero()),
            rhs: CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(CircuitExpr::Var("bit".into())),
                rhs: Box::new(CircuitExpr::BinOp {
                    op: CircuitBinOp::Sub,
                    lhs: Box::new(CircuitExpr::Var("bit".into())),
                    rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                }),
            },
            message: None,
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let widths = scan_bool_constraints(&prove_ir);
    assert_eq!(widths.get("bit").copied(), Some(BitWidth::Exact(1)));
}

#[test]
fn scan_handles_commuted_mul_factors() {
    // `(x - 1) * x === 0` — Sub on lhs of Mul.
    let prove_ir = ir_forge::types::ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![ir_forge::types::CircuitNode::AssertEq {
            lhs: CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(CircuitExpr::BinOp {
                    op: CircuitBinOp::Sub,
                    lhs: Box::new(CircuitExpr::Var("b".into())),
                    rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                }),
                rhs: Box::new(CircuitExpr::Var("b".into())),
            },
            rhs: CircuitExpr::Const(FieldConst::zero()),
            message: None,
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let widths = scan_bool_constraints(&prove_ir);
    assert_eq!(widths.get("b").copied(), Some(BitWidth::Exact(1)));
}

#[test]
fn scan_recurses_into_for_loops() {
    let prove_ir = ir_forge::types::ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![ir_forge::types::CircuitNode::For {
            var: "i".to_string(),
            range: ir_forge::types::ForRange::Literal { start: 0, end: 8 },
            body: vec![make_bool_assertion("nested_bit")],
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let widths = scan_bool_constraints(&prove_ir);
    assert_eq!(widths.get("nested_bit").copied(), Some(BitWidth::Exact(1)));
}

#[test]
fn scan_ignores_non_bool_assertions() {
    let prove_ir = ir_forge::types::ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![ir_forge::types::CircuitNode::AssertEq {
            lhs: CircuitExpr::Var("x".into()),
            rhs: CircuitExpr::Var("y".into()),
            message: None,
            span: None,
        }],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let widths = scan_bool_constraints(&prove_ir);
    assert!(widths.is_empty());
}

#[test]
fn scan_pipeline_tightens_shift_via_bool_signals() {
    // End-to-end: build a tiny ProveIR with a bool-constrained
    // signal `b` and a `BitOr(b, b)`. After scan + rewrite, the
    // BitOr's num_bits should drop from 254 to 1.
    let mut prove_ir = ir_forge::types::ProveIR {
        name: None,
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![
            make_bool_assertion("b"),
            ir_forge::types::CircuitNode::Expr {
                expr: CircuitExpr::BitOr {
                    lhs: Box::new(CircuitExpr::Var("b".into())),
                    rhs: Box::new(CircuitExpr::Var("b".into())),
                    num_bits: FIELD_BITS,
                },
                span: None,
            },
        ],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let widths = scan_bool_constraints(&prove_ir);
    let ctx = InferenceCtx {
        param_values: None,
        known_constants: None,
        signal_widths: Some(&widths),
    };
    rewrite_num_bits_in_prove_ir(&mut prove_ir, &ctx);
    // Find the BitOr and check its num_bits.
    match &prove_ir.body[1] {
        ir_forge::types::CircuitNode::Expr { expr, .. } => match expr {
            CircuitExpr::BitOr { num_bits, .. } => assert_eq!(*num_bits, 1),
            _ => panic!("expected BitOr"),
        },
        _ => panic!("expected Expr node"),
    }
}

#[test]
fn rewrite_via_arithmetic_propagation() {
    // Add of two 32-bit consts → AtMost(33). Then a >>7 of that
    // → tighten to num_bits=33.
    let ctx = empty_ctx();
    let mut expr = CircuitExpr::ShiftR {
        operand: Box::new(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
            rhs: Box::new(CircuitExpr::Const(fc(0xffff_ffff))),
        }),
        shift: Box::new(CircuitExpr::Const(fc(7))),
        num_bits: FIELD_BITS,
    };
    rewrite_num_bits_in_expr(&mut expr, &ctx);
    match &expr {
        CircuitExpr::ShiftR { num_bits, .. } => assert_eq!(*num_bits, 33),
        _ => panic!("expected ShiftR"),
    }
}
