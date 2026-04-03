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

use super::context::LoweringContext;
use super::env::{LoweringEnv, VarKind};
use super::error::LoweringError;
use super::utils::{const_eval_u64, extract_ident_name};

/// The default max bits for IntDiv/IntMod. Circom operates over BN254 (~254 bits).
const DEFAULT_MAX_BITS: u32 = 253;

/// Lower a Circom expression to a ProveIR `CircuitExpr`.
pub fn lower_expr(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
) -> Result<CircuitExpr, LoweringError> {
    match expr {
        // ── Literals ────────────────────────────────────────────────
        Expr::Number { value, span } => {
            // Try u64 first (common case), fall back to big decimal string
            if let Ok(n) = value.parse::<u64>() {
                Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
            } else {
                FieldConst::from_decimal_str(value)
                    .map(CircuitExpr::Const)
                    .ok_or_else(|| {
                        LoweringError::new(
                            format!("number literal `{value}` exceeds 256-bit field range"),
                            span,
                        )
                    })
            }
        }

        Expr::HexNumber { value, span } => {
            let hex_str = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            // Try u64 first, fall back to big hex string
            if let Ok(n) = u64::from_str_radix(hex_str, 16) {
                Ok(CircuitExpr::Const(FieldConst::from_u64(n)))
            } else {
                FieldConst::from_hex_str(value)
                    .map(CircuitExpr::Const)
                    .ok_or_else(|| {
                        LoweringError::new(
                            format!("hex literal `{value}` exceeds 256-bit field range"),
                            span,
                        )
                    })
            }
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
            let l = lower_expr(lhs, env, ctx)?;
            let r = lower_expr(rhs, env, ctx)?;
            lower_binop(*op, l, r, span)
        }

        // ── Unary operations ────────────────────────────────────────
        Expr::UnaryOp { op, operand, .. } => {
            let inner = lower_expr(operand, env, ctx)?;
            match op {
                ast::UnaryOp::Neg => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Neg,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::Not => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Not,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::BitNot => Ok(CircuitExpr::BitNot {
                    operand: Box::new(inner),
                    num_bits: DEFAULT_MAX_BITS,
                }),
            }
        }

        // ── Ternary → Mux ───────────────────────────────────────────
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let cond = lower_expr(condition, env, ctx)?;
            let t = lower_expr(if_true, env, ctx)?;
            let f = lower_expr(if_false, env, ctx)?;
            Ok(CircuitExpr::Mux {
                cond: Box::new(cond),
                if_true: Box::new(t),
                if_false: Box::new(f),
            })
        }

        // ── Array index ─────────────────────────────────────────────
        Expr::Index {
            object,
            index,
            span,
        } => {
            // Support both `arr[i]` and `comp.signal[i]`
            let array_name = extract_ident_name(object)
                .or_else(|| {
                    // DotAccess: `comp.field[i]` → mangled name `comp.field`
                    if let Expr::DotAccess {
                        object: inner_obj,
                        field,
                        ..
                    } = object.as_ref()
                    {
                        extract_ident_name(inner_obj).map(|obj_name| format!("{obj_name}.{field}"))
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    LoweringError::new(
                        "array index target must be a simple identifier or \
                         component signal in circuit context",
                        span,
                    )
                })?;

            // If index is a constant and array is tracked, resolve to `arr_N` directly
            if let Some(idx_val) = const_eval_u64(index) {
                if let Some(elem_name) = env.resolve_array_element(&array_name, idx_val as usize) {
                    return Ok(CircuitExpr::Var(elem_name));
                }
            }

            let idx = lower_expr(index, env, ctx)?;
            Ok(CircuitExpr::ArrayIndex {
                array: array_name,
                index: Box::new(idx),
            })
        }

        // ── Function calls ──────────────────────────────────────────
        Expr::Call { callee, args, span } => lower_call(callee, args, env, ctx, span),

        // ── Array literals ──────────────────────────────────────────
        Expr::ArrayLit { span, .. } => Err(LoweringError::new(
            "array literal is not supported as a circuit expression; \
             use signal array declarations instead",
            span,
        )),

        // ── Dot access (component output) ───────────────────────────
        Expr::DotAccess {
            object,
            field,
            span,
        } => {
            let obj_name = extract_ident_name(object).ok_or_else(|| {
                LoweringError::new("dot access target must be a simple identifier", span)
            })?;
            let mangled = format!("{obj_name}.{field}");
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

        Expr::ParallelOp { operand, .. } => lower_expr(operand, env, ctx),

        Expr::Underscore { span } => Err(LoweringError::new(
            "underscore `_` is not a valid circuit expression",
            span,
        )),

        Expr::Error { span } => Err(LoweringError::new("cannot lower an error expression", span)),
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

/// Lower a function call expression.
///
/// Builtins (`log`, `assert`) are handled specially. User-defined functions
/// are inlined: the function body is lowered with parameters bound to
/// argument expressions. Only functions with a single `return expr;`
/// statement (after any `var` declarations) are supported for inlining.
fn lower_call(
    callee: &Expr,
    args: &[Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
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
        _ => inline_function_call(&name, args, env, ctx, span),
    }
}

/// Inline a user-defined Circom function call.
///
/// Looks up the function in the context, builds a local environment with
/// parameters bound to argument expressions, and extracts the return value.
fn inline_function_call(
    name: &str,
    args: &[Expr],
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
    span: &diagnostics::Span,
) -> Result<CircuitExpr, LoweringError> {
    let func = match ctx.functions.get(name) {
        Some(f) => *f,
        None => {
            return Err(LoweringError::new(
                format!("undefined function `{name}` in circuit context"),
                span,
            ));
        }
    };

    if ctx.inline_depth >= super::context::MAX_INLINE_DEPTH {
        return Err(LoweringError::new(
            format!(
                "function inlining depth limit ({}) exceeded — \
                 possible recursion via `{name}`",
                super::context::MAX_INLINE_DEPTH,
            ),
            span,
        ));
    }

    if args.len() != func.params.len() {
        return Err(LoweringError::new(
            format!(
                "function `{name}` expects {} arguments, got {}",
                func.params.len(),
                args.len(),
            ),
            span,
        ));
    }

    ctx.inline_depth += 1;

    // Build a local env with parameters bound to lowered argument expressions.
    // The function body shares the outer env's inputs/captures, but parameters
    // shadow as locals.
    let mut fn_env = env.clone();
    for (param, arg) in func.params.iter().zip(args) {
        // Lower argument in the CALLER's env
        let _lowered_arg = lower_expr(arg, env, ctx)?;
        fn_env.locals.insert(param.clone());
    }

    // Find the return expression in the function body.
    // We support two patterns:
    //   1. `return expr;` (single statement)
    //   2. `var x = expr; ... return result;` (var decls + final return)
    let body = &func.body.stmts;
    let return_expr = find_return_expr(body).ok_or_else(|| {
        LoweringError::new(
            format!(
                "function `{name}` must end with a `return` statement \
                 for circuit inlining"
            ),
            span,
        )
    })?;

    // Build parameter substitution: replace param references with arg expressions
    let mut param_env = env.clone();
    let mut param_map: std::collections::HashMap<String, CircuitExpr> =
        std::collections::HashMap::new();
    for (param, arg) in func.params.iter().zip(args) {
        let lowered_arg = lower_expr(arg, env, ctx)?;
        param_map.insert(param.clone(), lowered_arg);
        param_env.locals.insert(param.clone());
    }

    // Lower the return expression with parameter substitution
    let result = lower_expr_with_substitution(return_expr, &param_env, ctx, &param_map)?;

    ctx.inline_depth -= 1;
    Ok(result)
}

/// Find the return expression in a function body.
///
/// Returns the expression from the last `return` statement, or `None`
/// if the function doesn't end with a return.
fn find_return_expr(stmts: &[crate::ast::Stmt]) -> Option<&Expr> {
    for stmt in stmts.iter().rev() {
        if let crate::ast::Stmt::Return { value, .. } = stmt {
            return Some(value);
        }
    }
    None
}

/// Lower an expression, substituting parameter names with their values.
fn lower_expr_with_substitution(
    expr: &Expr,
    env: &LoweringEnv,
    ctx: &mut LoweringContext,
    subs: &std::collections::HashMap<String, CircuitExpr>,
) -> Result<CircuitExpr, LoweringError> {
    match expr {
        Expr::Ident { name, .. } => {
            if let Some(sub) = subs.get(name) {
                return Ok(sub.clone());
            }
            lower_expr(expr, env, ctx)
        }
        // For compound expressions, recursively substitute
        Expr::BinOp { op, lhs, rhs, span } => {
            let l = lower_expr_with_substitution(lhs, env, ctx, subs)?;
            let r = lower_expr_with_substitution(rhs, env, ctx, subs)?;
            lower_binop(*op, l, r, span)
        }
        Expr::UnaryOp { op, operand, .. } => {
            let inner = lower_expr_with_substitution(operand, env, ctx, subs)?;
            match op {
                ast::UnaryOp::Neg => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Neg,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::Not => Ok(CircuitExpr::UnaryOp {
                    op: CircuitUnaryOp::Not,
                    operand: Box::new(inner),
                }),
                ast::UnaryOp::BitNot => Ok(CircuitExpr::BitNot {
                    operand: Box::new(inner),
                    num_bits: DEFAULT_MAX_BITS,
                }),
            }
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            let cond = lower_expr_with_substitution(condition, env, ctx, subs)?;
            let t = lower_expr_with_substitution(if_true, env, ctx, subs)?;
            let f = lower_expr_with_substitution(if_false, env, ctx, subs)?;
            Ok(CircuitExpr::Mux {
                cond: Box::new(cond),
                if_true: Box::new(t),
                if_false: Box::new(f),
            })
        }
        // For anything else, fall through to normal lowering
        _ => lower_expr(expr, env, ctx),
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
    use super::super::utils::const_eval_u64;
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

    fn make_ctx() -> LoweringContext<'static> {
        LoweringContext {
            templates: std::collections::HashMap::new(),
            functions: std::collections::HashMap::new(),
            inline_depth: 0,
        }
    }

    // ── Literals ────────────────────────────────────────────────────

    #[test]
    fn lower_decimal_number() {
        let expr = parse_expr("42");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn lower_hex_number() {
        let expr = parse_expr("0xFF");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(255)));
    }

    #[test]
    fn lower_zero() {
        let expr = parse_expr("0");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Const(FieldConst::zero()));
    }

    // ── Identifiers ─────────────────────────────────────────────────

    #[test]
    fn lower_input_ident() {
        let expr = parse_expr("a");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Input("a".to_string()));
    }

    #[test]
    fn lower_local_ident() {
        let expr = parse_expr("x");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Var("x".to_string()));
    }

    #[test]
    fn lower_capture_ident() {
        let expr = parse_expr("n");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert_eq!(result, CircuitExpr::Capture("n".to_string()));
    }

    #[test]
    fn lower_undefined_ident_is_error() {
        let expr = parse_expr("unknown");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx());
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("undefined variable"));
    }

    // ── Arithmetic ──────────────────────────────────────────────────

    #[test]
    fn lower_addition() {
        let expr = parse_expr("a + b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                ..
            }
        ));
    }

    #[test]
    fn lower_subtraction() {
        let expr = parse_expr("a - b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Sub,
                ..
            }
        ));
    }

    #[test]
    fn lower_multiplication() {
        let expr = parse_expr("a * b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn lower_division() {
        let expr = parse_expr("a / b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Div,
                ..
            }
        ));
    }

    #[test]
    fn lower_int_div() {
        let expr = parse_expr(r"a \ b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::IntDiv { .. }));
    }

    #[test]
    fn lower_modulo() {
        let expr = parse_expr("a % b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::IntMod { .. }));
    }

    #[test]
    fn lower_power() {
        let expr = parse_expr("a ** 3");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        match result {
            CircuitExpr::Pow { exp, .. } => assert_eq!(exp, 3),
            other => panic!("expected Pow, got {:?}", other),
        }
    }

    #[test]
    fn lower_power_non_const_is_error() {
        let expr = parse_expr("a ** b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx());
        assert!(result.is_err());
    }

    // ── Comparisons ─────────────────────────────────────────────────

    #[test]
    fn lower_equality() {
        let expr = parse_expr("a == b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn lower_neq() {
        let expr = parse_expr("a != b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Neq,
                ..
            }
        ));
    }

    #[test]
    fn lower_less_than() {
        let expr = parse_expr("a < b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Lt,
                ..
            }
        ));
    }

    // ── Boolean ─────────────────────────────────────────────────────

    #[test]
    fn lower_and() {
        let expr = parse_expr("a && b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::And,
                ..
            }
        ));
    }

    #[test]
    fn lower_or() {
        let expr = parse_expr("a || b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::Or,
                ..
            }
        ));
    }

    // ── Unary ───────────────────────────────────────────────────────

    #[test]
    fn lower_negation() {
        let expr = parse_expr("-a");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                ..
            }
        ));
    }

    #[test]
    fn lower_not() {
        let expr = parse_expr("!a");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(
            result,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Not,
                ..
            }
        ));
    }

    #[test]
    fn lower_bitnot_via_unary() {
        let expr = parse_expr("~a");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::BitNot { num_bits: 253, .. }));
    }

    // ── Ternary → Mux ───────────────────────────────────────────────

    #[test]
    fn lower_ternary_to_mux() {
        let expr = parse_expr("a == 0 ? 1 : 0");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Mux { .. }
        ));
    }

    // ── Array index ─────────────────────────────────────────────────

    #[test]
    fn lower_array_index() {
        let expr = parse_expr("bits[0]");
        match lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap() {
            CircuitExpr::ArrayIndex { array, .. } => assert_eq!(array, "bits"),
            other => panic!("expected ArrayIndex, got {:?}", other),
        }
    }

    // ── Nested expression ───────────────────────────────────────────

    #[test]
    fn lower_nested_arithmetic() {
        let expr = parse_expr("(a + b) * (a - b)");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn lower_complex_iszero_pattern() {
        let expr = parse_expr("a != 0 ? 1 : 0");
        assert!(matches!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Mux { .. }
        ));
    }

    // ── Bitwise operations ────────────────────────────────────────

    #[test]
    fn lower_bitwise_and() {
        let expr = parse_expr("a & b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::BitAnd { num_bits: 253, .. }));
    }

    #[test]
    fn lower_bitwise_or() {
        let expr = parse_expr("a | b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::BitOr { num_bits: 253, .. }));
    }

    #[test]
    fn lower_bitwise_xor() {
        let expr = parse_expr("a ^ b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::BitXor { num_bits: 253, .. }));
    }

    #[test]
    fn lower_bitwise_not() {
        let expr = parse_expr("~a");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::BitNot { num_bits: 253, .. }));
    }

    #[test]
    fn lower_shift_right() {
        let expr = parse_expr("a >> 3");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        match result {
            CircuitExpr::ShiftR {
                shift, num_bits, ..
            } => {
                assert_eq!(*shift, CircuitExpr::Const(FieldConst::from_u64(3)));
                assert_eq!(num_bits, 253);
            }
            other => panic!("expected ShiftR, got {:?}", other),
        }
    }

    #[test]
    fn lower_shift_left() {
        let expr = parse_expr("a << 1");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        match result {
            CircuitExpr::ShiftL {
                shift, num_bits, ..
            } => {
                assert_eq!(*shift, CircuitExpr::Const(FieldConst::from_u64(1)));
                assert_eq!(num_bits, 253);
            }
            other => panic!("expected ShiftL, got {:?}", other),
        }
    }

    #[test]
    fn lower_shift_variable_amount() {
        // Shift by a variable (e.g., loop variable) should now work
        let expr = parse_expr("a >> b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        assert!(matches!(result, CircuitExpr::ShiftR { .. }));
    }

    #[test]
    fn lower_shift_non_const_is_now_ok() {
        // Variable shift amounts are now supported (needed for Circom `in >> i` in loops)
        let expr = parse_expr("a >> b");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx());
        assert!(result.is_ok());
    }

    // ── Parallel is transparent ─────────────────────────────────────

    #[test]
    fn lower_parallel_is_transparent() {
        let expr = parse_expr("parallel a");
        assert_eq!(
            lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap(),
            CircuitExpr::Input("a".to_string())
        );
    }

    // ── Large number literals ────────────────────────────────────────

    #[test]
    fn lower_large_decimal_number() {
        // BN254 field order - 1 (exceeds u64)
        let expr = parse_expr(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        );
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        match result {
            CircuitExpr::Const(fc) => {
                assert!(fc.to_u64().is_none(), "should not fit in u64");
                assert!(!fc.is_zero());
            }
            other => panic!("expected Const, got {:?}", other),
        }
    }

    #[test]
    fn lower_large_hex_number() {
        // 0x + 64 hex digits = 32 bytes
        let expr = parse_expr("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
        let result = lower_expr(&expr, &make_env(), &mut make_ctx()).unwrap();
        match result {
            CircuitExpr::Const(fc) => {
                assert!(fc.to_u64().is_none());
            }
            other => panic!("expected Const, got {:?}", other),
        }
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
