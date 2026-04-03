//! Expression lowering: Circom expressions → ProveIR `CircuitExpr`.
//!
//! Maps the Circom expression tree to ProveIR's circuit expression tree.
//! Key mappings:
//! - Number/HexNumber literals → `CircuitExpr::Const(FieldConst)`
//! - Identifiers → `Var`, `Input`, or `Capture` (resolved by environment)
//! - Arithmetic `+,-,*,/` → `CircuitExpr::BinOp`
//! - Integer division `\`, modulo `%` → `CircuitExpr::IntDiv`, `CircuitExpr::IntMod`
//! - Power `**` → `CircuitExpr::Pow`
//! - Comparisons → `CircuitExpr::Comparison`
//! - Boolean `&&, ||` → `CircuitExpr::BoolOp`
//! - Ternary `? :` → `CircuitExpr::Mux`
//! - Array index → `CircuitExpr::ArrayIndex`
//! - Unary `-`, `!` → `CircuitExpr::UnaryOp`

use ir::prove_ir::types::{
    CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitUnaryOp, FieldConst,
};

use crate::ast::{self, Expr};

use super::env::{LoweringEnv, VarKind};
use super::error::LoweringError;
use super::utils::{binop_symbol, extract_ident_name};

/// The default max bits for IntDiv/IntMod. Circom operates over BN254 (~254 bits).
const DEFAULT_MAX_BITS: u32 = 253;

/// Lower a Circom expression to a ProveIR `CircuitExpr`.
pub fn lower_expr(
    expr: &Expr,
    env: &LoweringEnv,
) -> Result<CircuitExpr, LoweringError> {
    match expr {
        // ── Literals ────────────────────────────────────────────────
        Expr::Number { value, span } => {
            let n: u64 = value.parse().map_err(|_| {
                LoweringError::new(
                    format!("number literal `{value}` is too large for u64, use field constant"),
                    span,
                )
            })?;
            Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
        }

        Expr::HexNumber { value, span } => {
            let hex_str = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
            let n = u64::from_str_radix(hex_str, 16).map_err(|_| {
                LoweringError::new(
                    format!("hex literal `{value}` is too large for u64"),
                    span,
                )
            })?;
            Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
        }

        // ── Identifiers ─────────────────────────────────────────────
        Expr::Ident { name, span } => match env.resolve(name) {
            Some(VarKind::Input) => Ok(CircuitExpr::Input(name.clone())),
            Some(VarKind::Local) => Ok(CircuitExpr::Var(name.clone())),
            Some(VarKind::Capture) => Ok(CircuitExpr::Capture(name.clone())),
            None => Err(LoweringError::new(
                format!("undefined variable `{name}` in circuit context"),
                span,
            )),
        },

        // ── Binary operations ───────────────────────────────────────
        Expr::BinOp { op, lhs, rhs, span } => {
            let l = lower_expr(lhs, env)?;
            let r = lower_expr(rhs, env)?;
            lower_binop(*op, l, r, span)
        }

        // ── Unary operations ────────────────────────────────────────
        Expr::UnaryOp { op, operand, span } => {
            let inner = lower_expr(operand, env)?;
            match op {
                ast::UnaryOp::Neg => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Neg,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::Not => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Not,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::BitNot => Err(LoweringError::new(
                    "bitwise NOT (`~`) is not supported in circuit context",
                    span,
                )),
            }
        }

        // ── Ternary → Mux ───────────────────────────────────────────
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let cond = lower_expr(condition, env)?;
            let t = lower_expr(if_true, env)?;
            let f = lower_expr(if_false, env)?;
            Ok(CircuitExpr::Mux {
                cond: Box::new(cond),
                if_true: Box::new(t),
                if_false: Box::new(f),
            })
        }

        // ── Array index ─────────────────────────────────────────────
        Expr::Index { object, index, span } => {
            let array_name = extract_ident_name(object).ok_or_else(|| {
                LoweringError::new(
                    "array index target must be a simple identifier in circuit context",
                    span,
                )
            })?;
            let idx = lower_expr(index, env)?;
            Ok(CircuitExpr::ArrayIndex {
                array: array_name,
                index: Box::new(idx),
            })
        }

        // ── Function calls ──────────────────────────────────────────
        Expr::Call { callee, args, span } => lower_call(callee, args, env, span),

        // ── Array literals ──────────────────────────────────────────
        Expr::ArrayLit { span, .. } => Err(LoweringError::new(
            "array literal is not supported as a circuit expression; \
             use signal array declarations instead",
            span,
        )),

        // ── Dot access (component output) ───────────────────────────
        Expr::DotAccess { object, field, span } => {
            let obj_name = extract_ident_name(object).ok_or_else(|| {
                LoweringError::new(
                    "dot access target must be a simple identifier",
                    span,
                )
            })?;
            let mangled = format!("{obj_name}_{field}");
            match env.resolve(&mangled) {
                Some(VarKind::Input) => Ok(CircuitExpr::Input(mangled)),
                Some(VarKind::Local) => Ok(CircuitExpr::Var(mangled)),
                Some(VarKind::Capture) => Ok(CircuitExpr::Capture(mangled)),
                None => Ok(CircuitExpr::Var(mangled)),
            }
        }

        // ── Unsupported in circuit context ──────────────────────────
        Expr::PostfixOp { span, .. } => Err(LoweringError::new(
            "postfix increment/decrement is not supported in circuit expressions",
            span,
        )),

        Expr::AnonComponent { span, .. } => Err(LoweringError::new(
            "anonymous component instantiation will be handled at statement level",
            span,
        )),

        Expr::Tuple { span, .. } => Err(LoweringError::new(
            "tuples are not supported in circuit expressions",
            span,
        )),

        Expr::ParallelOp { operand, .. } => {
            lower_expr(operand, env)
        }

        Expr::Underscore { span } => Err(LoweringError::new(
            "underscore `_` is not a valid circuit expression",
            span,
        )),

        Expr::Error { span } => Err(LoweringError::new(
            "cannot lower an error expression",
            span,
        )),
    }
}

/// Lower a Circom binary operator to a `CircuitExpr`.
fn lower_binop(
    op: ast::BinOp,
    lhs: CircuitExpr,
    rhs: CircuitExpr,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let l = Box::new(lhs);
    let r = Box::new(rhs);

    match op {
        ast::BinOp::Add => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Add, lhs: l, rhs: r }),
        ast::BinOp::Sub => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Sub, lhs: l, rhs: r }),
        ast::BinOp::Mul => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Mul, lhs: l, rhs: r }),
        ast::BinOp::Div => Ok(CircuitExpr::BinOp { op: CircuitBinOp::Div, lhs: l, rhs: r }),

        ast::BinOp::IntDiv => Ok(CircuitExpr::IntDiv {
            lhs: l, rhs: r, max_bits: DEFAULT_MAX_BITS,
        }),
        ast::BinOp::Mod => Ok(CircuitExpr::IntMod {
            lhs: l, rhs: r, max_bits: DEFAULT_MAX_BITS,
        }),

        ast::BinOp::Pow => {
            match const_eval_circuit_expr(&r) {
                Some(exp) => Ok(CircuitExpr::Pow { base: l, exp }),
                None => Err(LoweringError::new(
                    "exponent in `**` must be a compile-time constant in circuit context",
                    span,
                )),
            }
        }

        ast::BinOp::Eq  => Ok(CircuitExpr::Comparison { op: CircuitCmpOp::Eq, lhs: l, rhs: r }),
        ast::BinOp::Neq => Ok(CircuitExpr::Comparison { op: CircuitCmpOp::Neq, lhs: l, rhs: r }),
        ast::BinOp::Lt  => Ok(CircuitExpr::Comparison { op: CircuitCmpOp::Lt, lhs: l, rhs: r }),
        ast::BinOp::Le  => Ok(CircuitExpr::Comparison { op: CircuitCmpOp::Le, lhs: l, rhs: r }),
        ast::BinOp::Gt  => Ok(CircuitExpr::Comparison { op: CircuitCmpOp::Gt, lhs: l, rhs: r }),
        ast::BinOp::Ge  => Ok(CircuitExpr::Comparison { op: CircuitCmpOp::Ge, lhs: l, rhs: r }),

        ast::BinOp::And => Ok(CircuitExpr::BoolOp { op: CircuitBoolOp::And, lhs: l, rhs: r }),
        ast::BinOp::Or  => Ok(CircuitExpr::BoolOp { op: CircuitBoolOp::Or, lhs: l, rhs: r }),

        ast::BinOp::BitAnd | ast::BinOp::BitOr | ast::BinOp::BitXor
        | ast::BinOp::ShiftL | ast::BinOp::ShiftR => {
            Err(LoweringError::new(
                format!(
                    "bitwise operator `{}` requires bit decomposition; \
                     not yet supported in circuit lowering",
                    binop_symbol(op),
                ),
                span,
            ))
        }
    }
}

/// Lower a function call expression.
fn lower_call(
    callee: &Expr,
    _args: &[Expr],
    _env: &LoweringEnv,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let name = extract_ident_name(callee).ok_or_else(|| {
        LoweringError::new(
            "call target must be a simple identifier in circuit context",
            span,
        )
    })?;

    match name.as_str() {
        "log" => Ok(CircuitExpr::Const(FieldConst::zero())),
        "assert" => Err(LoweringError::new(
            "`assert` is a statement, not an expression in circuit context",
            span,
        )),
        _ => Err(LoweringError::new(
            format!(
                "function call `{name}(...)` cannot be lowered yet; \
                 function inlining will be implemented in a later phase"
            ),
            span,
        )),
    }
}

/// Try to extract a constant u64 from a lowered `CircuitExpr`.
fn const_eval_circuit_expr(expr: &CircuitExpr) -> Option<u64> {
    match expr {
        CircuitExpr::Const(fc) => fc.to_u64(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;
    use super::super::utils::const_eval_u64;

    /// Parse a Circom expression inside a template var init.
    fn parse_expr(expr_src: &str) -> Expr {
        let src = format!("template T() {{ var _x = {expr_src}; }}");
        let (prog, errors) = parse_circom(&src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => {
                match &t.body.stmts[0] {
                    crate::ast::Stmt::VarDecl { init: Some(e), .. } => e.clone(),
                    other => panic!("expected VarDecl, got {:?}", other),
                }
            }
            _ => panic!("expected template"),
        }
    }

    fn make_env() -> LoweringEnv {
        let mut env = LoweringEnv::new();
        env.inputs.insert("in".to_string());
        env.inputs.insert("a".to_string());
        env.inputs.insert("b".to_string());
        env.locals.insert("x".to_string());
        env.locals.insert("out".to_string());
        env.locals.insert("bits".to_string());
        env.captures.insert("n".to_string());
        env
    }

    // ── Literals ────────────────────────────────────────────────────

    #[test]
    fn lower_decimal_number() {
        let expr = parse_expr("42");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn lower_hex_number() {
        let expr = parse_expr("0xFF");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(255)));
    }

    #[test]
    fn lower_zero() {
        let expr = parse_expr("0");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::zero()));
    }

    // ── Identifiers ─────────────────────────────────────────────────

    #[test]
    fn lower_input_ident() {
        let expr = parse_expr("a");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert_eq!(result, CircuitExpr::Input("a".to_string()));
    }

    #[test]
    fn lower_local_ident() {
        let expr = parse_expr("x");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert_eq!(result, CircuitExpr::Var("x".to_string()));
    }

    #[test]
    fn lower_capture_ident() {
        let expr = parse_expr("n");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert_eq!(result, CircuitExpr::Capture("n".to_string()));
    }

    #[test]
    fn lower_undefined_ident_is_error() {
        let expr = parse_expr("unknown");
        let result = lower_expr(&expr, &make_env());
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("undefined variable"));
    }

    // ── Arithmetic ──────────────────────────────────────────────────

    #[test]
    fn lower_addition() {
        let expr = parse_expr("a + b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::BinOp { op: CircuitBinOp::Add, .. }));
    }

    #[test]
    fn lower_subtraction() {
        let expr = parse_expr("a - b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::BinOp { op: CircuitBinOp::Sub, .. }));
    }

    #[test]
    fn lower_multiplication() {
        let expr = parse_expr("a * b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::BinOp { op: CircuitBinOp::Mul, .. }));
    }

    #[test]
    fn lower_division() {
        let expr = parse_expr("a / b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::BinOp { op: CircuitBinOp::Div, .. }));
    }

    #[test]
    fn lower_int_div() {
        let expr = parse_expr(r"a \ b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::IntDiv { .. }));
    }

    #[test]
    fn lower_modulo() {
        let expr = parse_expr("a % b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::IntMod { .. }));
    }

    #[test]
    fn lower_power() {
        let expr = parse_expr("a ** 3");
        let result = lower_expr(&expr, &make_env()).unwrap();
        match result {
            CircuitExpr::Pow { exp, .. } => assert_eq!(exp, 3),
            other => panic!("expected Pow, got {:?}", other),
        }
    }

    #[test]
    fn lower_power_non_const_is_error() {
        let expr = parse_expr("a ** b");
        let result = lower_expr(&expr, &make_env());
        assert!(result.is_err());
    }

    // ── Comparisons ─────────────────────────────────────────────────

    #[test]
    fn lower_equality() {
        let expr = parse_expr("a == b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::Comparison { op: CircuitCmpOp::Eq, .. }));
    }

    #[test]
    fn lower_neq() {
        let expr = parse_expr("a != b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::Comparison { op: CircuitCmpOp::Neq, .. }));
    }

    #[test]
    fn lower_less_than() {
        let expr = parse_expr("a < b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::Comparison { op: CircuitCmpOp::Lt, .. }));
    }

    // ── Boolean ─────────────────────────────────────────────────────

    #[test]
    fn lower_and() {
        let expr = parse_expr("a && b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::BoolOp { op: CircuitBoolOp::And, .. }));
    }

    #[test]
    fn lower_or() {
        let expr = parse_expr("a || b");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::BoolOp { op: CircuitBoolOp::Or, .. }));
    }

    // ── Unary ───────────────────────────────────────────────────────

    #[test]
    fn lower_negation() {
        let expr = parse_expr("-a");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::UnaryOp { op: CircuitUnaryOp::Neg, .. }));
    }

    #[test]
    fn lower_not() {
        let expr = parse_expr("!a");
        let result = lower_expr(&expr, &make_env()).unwrap();
        assert!(matches!(result, CircuitExpr::UnaryOp { op: CircuitUnaryOp::Not, .. }));
    }

    #[test]
    fn lower_bitnot_is_error() {
        let expr = parse_expr("~a");
        assert!(lower_expr(&expr, &make_env()).is_err());
    }

    // ── Ternary → Mux ───────────────────────────────────────────────

    #[test]
    fn lower_ternary_to_mux() {
        let expr = parse_expr("a == 0 ? 1 : 0");
        assert!(matches!(lower_expr(&expr, &make_env()).unwrap(), CircuitExpr::Mux { .. }));
    }

    // ── Array index ─────────────────────────────────────────────────

    #[test]
    fn lower_array_index() {
        let expr = parse_expr("bits[0]");
        match lower_expr(&expr, &make_env()).unwrap() {
            CircuitExpr::ArrayIndex { array, .. } => assert_eq!(array, "bits"),
            other => panic!("expected ArrayIndex, got {:?}", other),
        }
    }

    // ── Nested expression ───────────────────────────────────────────

    #[test]
    fn lower_nested_arithmetic() {
        let expr = parse_expr("(a + b) * (a - b)");
        assert!(matches!(lower_expr(&expr, &make_env()).unwrap(), CircuitExpr::BinOp { op: CircuitBinOp::Mul, .. }));
    }

    #[test]
    fn lower_complex_iszero_pattern() {
        let expr = parse_expr("a != 0 ? 1 : 0");
        assert!(matches!(lower_expr(&expr, &make_env()).unwrap(), CircuitExpr::Mux { .. }));
    }

    // ── Bitwise errors ──────────────────────────────────────────────

    #[test]
    fn lower_bitwise_and_is_error() {
        let expr = parse_expr("a & b");
        let result = lower_expr(&expr, &make_env());
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("bitwise"));
    }

    #[test]
    fn lower_shift_is_error() {
        let expr = parse_expr("a << 1");
        assert!(lower_expr(&expr, &make_env()).is_err());
    }

    // ── Parallel is transparent ─────────────────────────────────────

    #[test]
    fn lower_parallel_is_transparent() {
        let expr = parse_expr("parallel a");
        assert_eq!(lower_expr(&expr, &make_env()).unwrap(), CircuitExpr::Input("a".to_string()));
    }

    // ── const_eval_u64 (moved to utils, verify still works) ─────────

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
}
