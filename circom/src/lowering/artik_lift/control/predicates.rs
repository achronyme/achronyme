use crate::ast::{BinOp, Expr};

/// Detect `<expr> < 0` / `0 > <expr>` against a literal `0`. The
/// canonical residue of any field value is `>= 0`, so the comparison
/// is dead code in the witness program. Folding it here keeps the
/// surrounding `if` lift from having to emit a field-`<` op the VM
/// doesn't natively support.
pub(super) fn is_field_lt_zero_pattern(expr: &Expr) -> bool {
    match expr {
        Expr::BinOp {
            op: BinOp::Lt, rhs, ..
        } => is_literal_zero(rhs),
        Expr::BinOp {
            op: BinOp::Gt, lhs, ..
        } => is_literal_zero(lhs),
        _ => false,
    }
}

fn is_literal_zero(expr: &Expr) -> bool {
    match expr {
        Expr::Number { value, .. } => value == "0",
        Expr::HexNumber { value, .. } => {
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            trimmed.bytes().all(|b| b == b'0')
        }
        _ => false,
    }
}
