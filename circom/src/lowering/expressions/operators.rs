//! Binary and unary operator lowering.
//!
//! Maps Circom arithmetic, comparison, boolean, bitwise, and shift operators
//! to their ProveIR `CircuitExpr` equivalents.

use ir::prove_ir::types::{CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr};

use crate::ast;

use super::super::const_fold::try_fold_const;
use super::super::error::LoweringError;
use super::DEFAULT_MAX_BITS;

/// Lower a Circom binary operator to a `CircuitExpr`.
///
/// When both operands are compile-time constants, field operations
/// (Add, Sub, Mul, Div) are folded using BN254 modular arithmetic.
pub(super) fn lower_binop(
    op: ast::BinOp,
    lhs: CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let l = Box::new(lhs);
    let r = Box::new(rhs);

    match op {
        ast::BinOp::Add => {
            let expr = CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: l,
                rhs: r,
            };
            Ok(try_fold_const(&expr)
                .map(CircuitExpr::Const)
                .unwrap_or(expr))
        }
        ast::BinOp::Sub => {
            let expr = CircuitExpr::BinOp {
                op: CircuitBinOp::Sub,
                lhs: l,
                rhs: r,
            };
            Ok(try_fold_const(&expr)
                .map(CircuitExpr::Const)
                .unwrap_or(expr))
        }
        ast::BinOp::Mul => {
            let expr = CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: l,
                rhs: r,
            };
            Ok(try_fold_const(&expr)
                .map(CircuitExpr::Const)
                .unwrap_or(expr))
        }
        ast::BinOp::Div => {
            let expr = CircuitExpr::BinOp {
                op: CircuitBinOp::Div,
                lhs: l,
                rhs: r,
            };
            Ok(try_fold_const(&expr)
                .map(CircuitExpr::Const)
                .unwrap_or(expr))
        }

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
        ast::BinOp::ShiftR => {
            let expr = CircuitExpr::ShiftR {
                operand: l,
                shift: r,
                num_bits: DEFAULT_MAX_BITS,
            };
            Ok(try_fold_const(&expr)
                .map(CircuitExpr::Const)
                .unwrap_or(expr))
        }
        ast::BinOp::ShiftL => {
            // Fold `Const << Const` into a concrete field element so
            // expressions like `(1 << n)` with a captured template
            // param `n = 64` don't leak into a runtime ShiftL whose
            // IR evaluator truncates via u64 (see `try_fold_const`
            // for the long story).
            let expr = CircuitExpr::ShiftL {
                operand: l,
                shift: r,
                num_bits: DEFAULT_MAX_BITS,
            };
            Ok(try_fold_const(&expr)
                .map(CircuitExpr::Const)
                .unwrap_or(expr))
        }
    }
}

/// Try to extract a constant u64 from a lowered `CircuitExpr`.
fn const_eval_circuit_expr(expr: &CircuitExpr) -> Option<u64> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_u64(),
        _ => None,
    }
}
