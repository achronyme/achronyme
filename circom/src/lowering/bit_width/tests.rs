use super::infer::bits_of_field_const;
use super::*;
use ir_forge::types::{
    CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitUnaryOp, FieldConst,
};
use std::collections::HashMap;

fn fc(value: u64) -> FieldConst {
    FieldConst::from_u64(value)
}

fn fc_from_limbs(limbs: [u64; 4]) -> FieldConst {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    FieldConst::from_le_bytes(bytes)
}

fn empty_ctx() -> InferenceCtx<'static> {
    InferenceCtx::default()
}

fn make_bool_assertion(name: &str) -> ir_forge::types::CircuitNode {
    // Build `x * (x - 1) === 0` with `x` named `name`.
    ir_forge::types::CircuitNode::AssertEq {
        lhs: CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: Box::new(CircuitExpr::Var(name.to_string())),
            rhs: Box::new(CircuitExpr::BinOp {
                op: CircuitBinOp::Sub,
                lhs: Box::new(CircuitExpr::Var(name.to_string())),
                rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
            }),
        },
        rhs: CircuitExpr::Const(FieldConst::zero()),
        message: None,
        span: None,
    }
}

mod core;
mod inference;
mod rewrite_scan;
