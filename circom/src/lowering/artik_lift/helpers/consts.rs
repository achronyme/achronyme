use std::collections::HashMap;

use crate::ast::{BinOp, Expr, PostfixOp, UnaryOp};

use super::super::ConstInt;

/// Evaluate an expression to a compile-time integer. Used for loop
/// bounds and step amounts. Looks up identifiers in the provided
/// `const_locals` map; signals / runtime-valued locals return `None`.
pub(in super::super) fn eval_const_expr(
    expr: &Expr,
    const_locals: &HashMap<String, ConstInt>,
) -> Option<ConstInt> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            ConstInt::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).ok()
        }
        Expr::Ident { name, .. } => const_locals.get(name).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let a = eval_const_expr(lhs, const_locals)?;
            let b = eval_const_expr(rhs, const_locals)?;
            match op {
                BinOp::Add => a.checked_add(b),
                BinOp::Sub => a.checked_sub(b),
                BinOp::Mul => a.checked_mul(b),
                // Comparisons return 1 / 0 so `if (i == 0) { ... }`
                // inside an unrolled loop folds correctly.
                BinOp::Eq => Some((a == b) as ConstInt),
                BinOp::Neq => Some((a != b) as ConstInt),
                BinOp::Lt => Some((a < b) as ConstInt),
                BinOp::Le => Some((a <= b) as ConstInt),
                BinOp::Gt => Some((a > b) as ConstInt),
                BinOp::Ge => Some((a >= b) as ConstInt),
                // Boolean connectives — both operands already folded to
                // ConstInt above (any non-zero value reads as true), so
                // the result is the usual integer logic-op. Circomlib's
                // shape-guard asserts like
                // `(n == 86 && k == 3) || (n == 64 && k == 4)` need
                // these to fold; without them the lift would treat the
                // predicate as runtime and bail.
                BinOp::And => Some(((a != 0) && (b != 0)) as ConstInt),
                BinOp::Or => Some(((a != 0) || (b != 0)) as ConstInt),
                _ => None,
            }
        }
        Expr::UnaryOp {
            op: UnaryOp::Neg,
            operand,
            ..
        } => eval_const_expr(operand, const_locals).and_then(ConstInt::checked_neg),
        _ => None,
    }
}

/// Extract the simple identifier from a call's `callee` expression.
/// Circom's function-call callees are always bare identifiers at the
/// lowering layer; anything more complex (method access, indexed
/// callable, etc.) bails out of the lift.
pub(in super::super) fn extract_call_name(callee: &Expr) -> Option<String> {
    match callee {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Whether `expr` is the integer literal `1`. The literal-`1` base is
/// the discriminator between circom's field-precision power-of-two
/// (`1 << n`, lowered to `FPow2`) and a fixed-width bit-packing shift
/// (a signal / limb base shifted by a small amount, e.g. SHA-256's
/// `hin[..] << j`), which stays on the width-masked integer path.
pub(in super::super) fn expr_is_one(expr: &Expr) -> bool {
    match expr {
        Expr::Number { value, .. } => value == "1",
        Expr::HexNumber { value, .. } => {
            let trimmed = value.strip_prefix("0x").unwrap_or(value);
            trimmed == "1"
        }
        _ => false,
    }
}

/// Recognize the shape `1 << <const k>` and return the shift amount
/// `k` if it fits in `0..=253`. Used by the IntDiv / Mod lift to detect
/// a compile-time-power-of-2 divisor without going through
/// `eval_const_expr` (which can't represent values exceeding `i64`,
/// such as `1 << 64`).
pub(in super::super) fn match_one_shl_const(
    expr: &Expr,
    const_locals: &HashMap<String, ConstInt>,
) -> Option<u32> {
    let Expr::BinOp {
        op: BinOp::ShiftL,
        lhs,
        rhs,
        ..
    } = expr
    else {
        return None;
    };
    if !expr_is_one(lhs.as_ref()) {
        return None;
    }
    let k = eval_const_expr(rhs, const_locals)?;
    if !(0..=253).contains(&k) {
        return None;
    }
    Some(k as u32)
}

/// Is `expr` an increment on the named variable (`name++` or `++name`)?
pub(in super::super) fn is_increment_on(expr: &Expr, name: &str) -> bool {
    let (op, operand) = match expr {
        Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => (op, operand),
        _ => return false,
    };
    if !matches!(op, PostfixOp::Increment) {
        return false;
    }
    matches!(operand.as_ref(), Expr::Ident { name: n, .. } if n == name)
}

/// Is `expr` a decrement on the named variable (`name--` or `--name`)?
pub(in super::super) fn is_decrement_on(expr: &Expr, name: &str) -> bool {
    let (op, operand) = match expr {
        Expr::PostfixOp { op, operand, .. } | Expr::PrefixOp { op, operand, .. } => (op, operand),
        _ => return false,
    };
    if !matches!(op, PostfixOp::Decrement) {
        return false;
    }
    matches!(operand.as_ref(), Expr::Ident { name: n, .. } if n == name)
}
