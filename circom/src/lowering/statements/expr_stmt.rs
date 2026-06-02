use diagnostics::SpanRange;
use ir_forge::types::{CircuitExpr, CircuitNode};

use crate::ast::{self, Expr};

use super::super::error::LoweringError;
use super::super::utils::extract_ident_name;

/// Lower a bare expression statement (i++, i--, etc).
pub(super) fn lower_expr_stmt(
    expr: &Expr,
    span: &diagnostics::Span,
    nodes: &mut Vec<CircuitNode>,
) -> Result<(), LoweringError> {
    match expr {
        Expr::PostfixOp {
            op: ast::PostfixOp::Increment,
            operand,
            ..
        }
        | Expr::PrefixOp {
            op: ast::PostfixOp::Increment,
            operand,
            ..
        } => {
            let name = extract_ident_name(operand).ok_or_else(|| {
                LoweringError::new("increment target must be an identifier", span)
            })?;
            let inc = CircuitExpr::BinOp {
                op: ir_forge::types::CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var(name.clone())),
                rhs: Box::new(CircuitExpr::Const(ir_forge::types::FieldConst::one())),
            };
            nodes.push(CircuitNode::Let {
                name,
                value: inc,
                span: Some(SpanRange::from_span(span)),
            });
        }
        Expr::PostfixOp {
            op: ast::PostfixOp::Decrement,
            operand,
            ..
        }
        | Expr::PrefixOp {
            op: ast::PostfixOp::Decrement,
            operand,
            ..
        } => {
            let name = extract_ident_name(operand).ok_or_else(|| {
                LoweringError::new("decrement target must be an identifier", span)
            })?;
            let dec = CircuitExpr::BinOp {
                op: ir_forge::types::CircuitBinOp::Sub,
                lhs: Box::new(CircuitExpr::Var(name.clone())),
                rhs: Box::new(CircuitExpr::Const(ir_forge::types::FieldConst::one())),
            };
            nodes.push(CircuitNode::Let {
                name,
                value: dec,
                span: Some(SpanRange::from_span(span)),
            });
        }
        _ => {
            // Other bare expressions are no-ops in circuit context.
        }
    }
    Ok(())
}
