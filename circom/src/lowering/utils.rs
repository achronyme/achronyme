//! Shared lowering utilities.
//!
//! Helper functions used across multiple lowering modules (signals,
//! expressions, statements). These operate on the Circom AST and
//! don't depend on ProveIR types.

use std::collections::HashMap;

use crate::ast::{self, Expr};

/// Extract a simple identifier name from an expression.
///
/// Returns `Some("x")` for `Expr::Ident { name: "x" }`, `None` for
/// anything more complex (index, dot access, etc.).
pub fn extract_ident_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } => Some(name.clone()),
        _ => None,
    }
}

/// Try to evaluate a Circom AST expression as a constant u64.
///
/// Used for array dimensions, loop bounds, and power exponents that must
/// be compile-time constants.
pub fn const_eval_u64(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

/// Evaluate a Circom expression as u64 by substituting known parameter values.
///
/// Like `const_eval_u64` but also resolves identifiers from the param map.
/// Used for signal array dimensions and loop bounds that involve template params.
pub fn const_eval_with_params(expr: &Expr, params: &HashMap<String, u64>) -> Option<u64> {
    match expr {
        Expr::Number { value, .. } => value.parse().ok(),
        Expr::HexNumber { value, .. } => {
            let hex = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(hex, 16).ok()
        }
        Expr::Ident { name, .. } => params.get(name.as_str()).copied(),
        Expr::BinOp { op, lhs, rhs, .. } => {
            let l = const_eval_with_params(lhs, params)?;
            let r = const_eval_with_params(rhs, params)?;
            match op {
                ast::BinOp::Add => l.checked_add(r),
                ast::BinOp::Sub => l.checked_sub(r),
                ast::BinOp::Mul => l.checked_mul(r),
                ast::BinOp::Div | ast::BinOp::IntDiv => {
                    if r != 0 {
                        Some(l / r)
                    } else {
                        None
                    }
                }
                ast::BinOp::Mod => {
                    if r != 0 {
                        Some(l % r)
                    } else {
                        None
                    }
                }
                ast::BinOp::ShiftL => Some(l << (r & 63)),
                ast::BinOp::ShiftR => Some(l >> (r & 63)),
                ast::BinOp::Pow => Some(l.pow(r as u32)),
                _ => None,
            }
        }
        Expr::UnaryOp { op, operand, .. } => {
            let val = const_eval_with_params(operand, params)?;
            match op {
                ast::UnaryOp::Neg => Some(val.wrapping_neg()),
                _ => None,
            }
        }
        // Fall back to const_eval for literals
        _ => const_eval_u64(expr),
    }
}

/// Display symbol for a binary operator (for error messages).
pub fn binop_symbol(op: ast::BinOp) -> &'static str {
    match op {
        ast::BinOp::Add => "+",
        ast::BinOp::Sub => "-",
        ast::BinOp::Mul => "*",
        ast::BinOp::Div => "/",
        ast::BinOp::IntDiv => "\\",
        ast::BinOp::Mod => "%",
        ast::BinOp::Pow => "**",
        ast::BinOp::Eq => "==",
        ast::BinOp::Neq => "!=",
        ast::BinOp::Lt => "<",
        ast::BinOp::Le => "<=",
        ast::BinOp::Gt => ">",
        ast::BinOp::Ge => ">=",
        ast::BinOp::And => "&&",
        ast::BinOp::Or => "||",
        ast::BinOp::BitAnd => "&",
        ast::BinOp::BitOr => "|",
        ast::BinOp::BitXor => "^",
        ast::BinOp::ShiftL => "<<",
        ast::BinOp::ShiftR => ">>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;

    /// Parse a Circom expression inside a template var init.
    fn parse_expr(expr_src: &str) -> Expr {
        let src = format!("template T() {{ var _x = {expr_src}; }}");
        let (prog, errors) = parse_circom(&src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => match &t.body.stmts[0] {
                crate::ast::Stmt::VarDecl { init: Some(e), .. } => e.clone(),
                other => panic!("expected VarDecl, got {:?}", other),
            },
            _ => panic!("expected template"),
        }
    }

    #[test]
    fn const_eval_decimal() {
        assert_eq!(const_eval_u64(&parse_expr("42")), Some(42));
    }

    #[test]
    fn const_eval_hex() {
        assert_eq!(const_eval_u64(&parse_expr("0x10")), Some(16));
    }

    #[test]
    fn const_eval_non_const() {
        assert_eq!(const_eval_u64(&parse_expr("a + 1")), None);
    }

    #[test]
    fn extract_ident() {
        let expr = parse_expr("foo");
        assert_eq!(extract_ident_name(&expr), Some("foo".to_string()));
    }

    #[test]
    fn extract_ident_from_non_ident() {
        let expr = parse_expr("1 + 2");
        assert_eq!(extract_ident_name(&expr), None);
    }
}
