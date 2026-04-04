//! Binary and unary operator lowering.
//!
//! Maps Circom arithmetic, comparison, boolean, bitwise, and shift operators
//! to their ProveIR `CircuitExpr` equivalents.

use ir::prove_ir::types::{
    CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr,
};

use crate::ast;

use super::super::error::LoweringError;
use super::DEFAULT_MAX_BITS;

/// Lower a Circom binary operator to a `CircuitExpr`.
pub(super) fn lower_binop(
    op: ast::BinOp,
    lhs: CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let l = Box::new(lhs);
    let r = Box::new(rhs);

    match op {
        ast::BinOp::Add => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Sub => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Mul => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Div => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: l,
            rhs: r,
        }),

        ast::BinOp::IntDiv => Ok(CircuitExpr::IntDiv {
            lhs: l,
            rhs: r,
            max_bits: DEFAULT_MAX_BITS,
        }),
        ast::BinOp::Mod => Ok(CircuitExpr::IntMod {
            lhs: l,
            rhs: r,
            max_bits: DEFAULT_MAX_BITS,
        }),

        ast::BinOp::Pow => match const_eval_circuit_expr(&r) {
            Some(exp) => Ok(CircuitExpr::Pow { base: l, exp }),
            None => Err(LoweringError::new(
                "exponent in `**` must be a compile-time constant in circuit context",
                span,
            )),
        },

        ast::BinOp::Eq => Ok(CircuitExpr::Comparison {
            op: CircuitCmpOp::Eq,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Neq => Ok(CircuitExpr::Comparison {
            op: CircuitCmpOp::Neq,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Lt => Ok(CircuitExpr::Comparison {
            op: CircuitCmpOp::Lt,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Le => Ok(CircuitExpr::Comparison {
            op: CircuitCmpOp::Le,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Gt => Ok(CircuitExpr::Comparison {
            op: CircuitCmpOp::Gt,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Ge => Ok(CircuitExpr::Comparison {
            op: CircuitCmpOp::Ge,
            lhs: l,
            rhs: r,
        }),

        ast::BinOp::And => Ok(CircuitExpr::BoolOp {
            op: CircuitBoolOp::And,
            lhs: l,
            rhs: r,
        }),
        ast::BinOp::Or => Ok(CircuitExpr::BoolOp {
            op: CircuitBoolOp::Or,
            lhs: l,
            rhs: r,
        }),

        ast::BinOp::BitAnd => Ok(CircuitExpr::BitAnd {
            lhs: l,
            rhs: r,
            num_bits: DEFAULT_MAX_BITS,
        }),
        ast::BinOp::BitOr => Ok(CircuitExpr::BitOr {
            lhs: l,
            rhs: r,
            num_bits: DEFAULT_MAX_BITS,
        }),
        ast::BinOp::BitXor => Ok(CircuitExpr::BitXor {
            lhs: l,
            rhs: r,
            num_bits: DEFAULT_MAX_BITS,
        }),
        ast::BinOp::ShiftR => Ok(CircuitExpr::ShiftR {
            operand: l,
            shift: r,
            num_bits: DEFAULT_MAX_BITS,
        }),
        ast::BinOp::ShiftL => Ok(CircuitExpr::ShiftL {
            operand: l,
            shift: r,
            num_bits: DEFAULT_MAX_BITS,
        }),
    }
}

/// Try to extract a constant u64 from a lowered `CircuitExpr`.
fn const_eval_circuit_expr(expr: &CircuitExpr) -> Option<u64> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_u64(),
        _ => None,
    }
}
