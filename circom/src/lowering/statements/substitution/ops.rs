use super::*;

/// Convert a compound assignment operator to a CircuitExpr binary op.
pub(in crate::lowering::statements) fn compound_to_binop(
    op: CompoundOp,
    lhs: &CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let l = Box::new(lhs.clone());
    let r = Box::new(rhs);

    match op {
        CompoundOp::Add => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Add,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::Sub => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Sub,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::Mul => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Mul,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::Div => Ok(CircuitExpr::BinOp {
            op: CircuitBinOp::Div,
            lhs: l,
            rhs: r,
        }),
        CompoundOp::IntDiv => Ok(CircuitExpr::IntDiv {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        CompoundOp::Mod => Ok(CircuitExpr::IntMod {
            lhs: l,
            rhs: r,
            max_bits: 253,
        }),
        CompoundOp::Pow => {
            let exp = match r.as_ref() {
                CircuitExpr::Const(fc) => fc.to_u64().ok_or_else(|| {
                    LoweringError::new("power exponent must be a small constant", span)
                })?,
                _ => {
                    return Err(LoweringError::new(
                        "power exponent must be a compile-time constant",
                        span,
                    ));
                }
            };
            Ok(CircuitExpr::Pow { base: l, exp })
        }
        CompoundOp::ShiftL
        | CompoundOp::ShiftR
        | CompoundOp::BitAnd
        | CompoundOp::BitOr
        | CompoundOp::BitXor => Err(LoweringError::new(
            "bitwise compound assignment is not supported in circuit context",
            span,
        )),
    }
}
