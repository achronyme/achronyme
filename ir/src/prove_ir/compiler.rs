//! ProveIR compiler: AST Block → ProveIR template.

use std::collections::{HashMap, HashSet};

use achronyme_parser::ast::*;
use achronyme_parser::diagnostic::SpanRange;
use memory::FieldElement;

use super::error::ProveIrError;
use super::types::*;
use crate::error::{span_box, OptSpan};

// ---------------------------------------------------------------------------
// Environment values
// ---------------------------------------------------------------------------

/// A value in the ProveIR compilation environment.
#[derive(Clone, Debug)]
enum CompEnvValue {
    /// A local scalar variable (let-binding or input).
    Scalar(String),
    /// A local array variable.
    Array(Vec<String>),
    /// A captured value from the outer scope.
    Capture(String),
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

/// Compiles an AST `Block` (from a prove block or circuit file) into a `ProveIR`.
pub struct ProveIrCompiler {
    /// Maps variable names → what they resolve to.
    env: HashMap<String, CompEnvValue>,
    /// Tracks which names are captured from the outer scope.
    captured_names: HashSet<String>,
}

impl ProveIrCompiler {
    fn new() -> Self {
        Self {
            env: HashMap::new(),
            captured_names: HashSet::new(),
        }
    }

    /// Compile an AST Block into a ProveIR template.
    ///
    /// `outer_scope`: names available in the enclosing scope (for prove blocks).
    /// Pass an empty set for `ach circuit` mode.
    pub fn compile(block: &Block, outer_scope: &HashSet<String>) -> Result<ProveIR, ProveIrError> {
        let mut compiler = Self::new();

        // Register outer scope names as potential captures
        for name in outer_scope {
            compiler
                .env
                .insert(name.clone(), CompEnvValue::Capture(name.clone()));
        }

        // TODO(step 5): collect public/witness declarations
        // TODO(step 5): compile block statements
        let _ = block;

        Ok(ProveIR {
            public_inputs: Vec::new(),
            witness_inputs: Vec::new(),
            captures: Vec::new(),
            body: Vec::new(),
        })
    }

    // -----------------------------------------------------------------------
    // Expression compilation
    // -----------------------------------------------------------------------

    /// Compile an AST expression into a `CircuitExpr`.
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<CircuitExpr, ProveIrError> {
        match expr {
            Expr::Number { value, span } => self.compile_number(value, span),
            Expr::FieldLit {
                value, radix, span, ..
            } => self.compile_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => Ok(CircuitExpr::Const(FieldElement::ONE)),
            Expr::Bool { value: false, .. } => Ok(CircuitExpr::Const(FieldElement::ZERO)),
            Expr::Ident { name, span } => self.compile_ident(name, span),

            Expr::BinOp { op, lhs, rhs, span } => self.compile_binop(op, lhs, rhs, span),
            Expr::UnaryOp { op, operand, span } => self.compile_unary(op, operand, span),

            // TODO(step 3): StaticAccess
            // TODO(step 4): DotAccess (method dispatch)
            // TODO(step 5): Call (builtins + user functions)
            // TODO(step 8): If, For, Block

            // --- Rejections (same as IrLowering, with better messages) ---
            Expr::While { span, .. } | Expr::Forever { span, .. } => {
                Err(ProveIrError::UnboundedLoop {
                    span: to_span(span),
                })
            }
            Expr::Prove { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "prove blocks cannot be nested inside circuits".into(),
                span: to_span(span),
            }),
            Expr::FnExpr { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "closures are not supported in circuits \
                              (use named fn declarations instead)"
                    .into(),
                span: to_span(span),
            }),
            Expr::StringLit { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "string".into(),
                span: to_span(span),
            }),
            Expr::Nil { span } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "nil".into(),
                span: to_span(span),
            }),
            Expr::Map { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "map".into(),
                span: to_span(span),
            }),
            Expr::BigIntLit { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            Expr::Array { span, .. } => Err(ProveIrError::TypeMismatch {
                expected: "scalar expression".into(),
                got: "array literal (use let binding for arrays)".into(),
                span: to_span(span),
            }),
            Expr::Error { span } => Err(ProveIrError::UnsupportedOperation {
                description: "cannot compile error placeholder (source has parse errors)".into(),
                span: to_span(span),
            }),

            // Catch-all for expressions not yet implemented
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "expression not yet supported in ProveIR".into(),
                span: None,
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Literals
    // -----------------------------------------------------------------------

    fn compile_number(&self, s: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        if s.contains('.') {
            return Err(ProveIrError::TypeNotConstrainable {
                type_name: "decimal number".into(),
                span: to_span(span),
            });
        }
        let (negative, digits) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };
        let fe = FieldElement::from_decimal_str(digits).ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!("invalid integer literal: {s}"),
                span: to_span(span),
            }
        })?;
        if negative {
            Ok(CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(fe)),
            })
        } else {
            Ok(CircuitExpr::Const(fe))
        }
    }

    fn compile_field_lit(
        &self,
        value: &str,
        radix: &FieldRadix,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let fe = match radix {
            FieldRadix::Decimal => FieldElement::from_decimal_str(value),
            FieldRadix::Hex => FieldElement::from_hex_str(value),
            FieldRadix::Binary => FieldElement::from_binary_str(value),
        }
        .ok_or_else(|| ProveIrError::UnsupportedOperation {
            description: format!("invalid field literal: {value}"),
            span: to_span(span),
        })?;
        Ok(CircuitExpr::Const(fe))
    }

    // -----------------------------------------------------------------------
    // Identifiers
    // -----------------------------------------------------------------------

    fn compile_ident(&mut self, name: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        match self.env.get(name) {
            Some(CompEnvValue::Scalar(resolved)) => Ok(CircuitExpr::Var(resolved.clone())),
            Some(CompEnvValue::Array(_)) => Err(ProveIrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: to_span(span),
            }),
            Some(CompEnvValue::Capture(cap_name)) => {
                self.captured_names.insert(cap_name.clone());
                Ok(CircuitExpr::Capture(cap_name.clone()))
            }
            None => Err(ProveIrError::UndeclaredVariable {
                name: name.into(),
                span: to_span(span),
                suggestion: None, // TODO: fuzzy match from env keys
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Binary operations
    // -----------------------------------------------------------------------

    fn compile_binop(
        &mut self,
        op: &BinOp,
        lhs: &Expr,
        rhs: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match op {
            // Arithmetic → CircuitBinOp
            BinOp::Add => self.compile_arith_binop(CircuitBinOp::Add, lhs, rhs),
            BinOp::Sub => self.compile_arith_binop(CircuitBinOp::Sub, lhs, rhs),
            BinOp::Mul => self.compile_arith_binop(CircuitBinOp::Mul, lhs, rhs),
            BinOp::Div => self.compile_arith_binop(CircuitBinOp::Div, lhs, rhs),

            // Comparisons → CircuitCmpOp
            BinOp::Eq => self.compile_comparison(CircuitCmpOp::Eq, lhs, rhs),
            BinOp::Neq => self.compile_comparison(CircuitCmpOp::Neq, lhs, rhs),
            BinOp::Lt => self.compile_comparison(CircuitCmpOp::Lt, lhs, rhs),
            BinOp::Le => self.compile_comparison(CircuitCmpOp::Le, lhs, rhs),
            BinOp::Gt => self.compile_comparison(CircuitCmpOp::Gt, lhs, rhs),
            BinOp::Ge => self.compile_comparison(CircuitCmpOp::Ge, lhs, rhs),

            // Boolean → CircuitBoolOp
            BinOp::And => self.compile_bool_binop(CircuitBoolOp::And, lhs, rhs),
            BinOp::Or => self.compile_bool_binop(CircuitBoolOp::Or, lhs, rhs),

            // Mod → error
            BinOp::Mod => Err(ProveIrError::UnsupportedOperation {
                description: "modulo (%) is not supported in circuits \
                              (no efficient field arithmetic equivalent — use range_check)"
                    .into(),
                span: to_span(span),
            }),

            // Pow → CircuitExpr::Pow (exponent must be a constant)
            BinOp::Pow => self.compile_pow(lhs, rhs, span),
        }
    }

    fn compile_arith_binop(
        &mut self,
        op: CircuitBinOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::BinOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    fn compile_comparison(
        &mut self,
        op: CircuitCmpOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::Comparison {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    fn compile_bool_binop(
        &mut self,
        op: CircuitBoolOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::BoolOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    fn compile_pow(
        &mut self,
        base_expr: &Expr,
        exp_expr: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let base = self.compile_expr(base_expr)?;
        let exp = self.extract_const_u64(exp_expr, span)?;
        Ok(CircuitExpr::Pow {
            base: Box::new(base),
            exp,
        })
    }

    /// Try to extract a constant u64 from an expression (for exponents, range_check bits, etc.)
    fn extract_const_u64(&self, expr: &Expr, span: &Span) -> Result<u64, ProveIrError> {
        match expr {
            Expr::Number { value, .. } => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "expected a non-negative integer constant, got `{value}`"
                        ),
                        span: to_span(span),
                    })?;
                Ok(n)
            }
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "exponent must be a constant integer in circuits \
                     (x^n is unrolled to n multiplications at compile time)"
                    .into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Unary operations
    // -----------------------------------------------------------------------

    fn compile_unary(
        &mut self,
        op: &UnaryOp,
        operand: &Expr,
        _span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Double negation / double NOT cancellation: --x → x, !!x → x
        if let Expr::UnaryOp {
            op: inner_op,
            operand: inner_operand,
            ..
        } = operand
        {
            if inner_op == op {
                return self.compile_expr(inner_operand);
            }
        }

        let inner = self.compile_expr(operand)?;
        let circuit_op = match op {
            UnaryOp::Neg => CircuitUnaryOp::Neg,
            UnaryOp::Not => CircuitUnaryOp::Not,
        };
        Ok(CircuitExpr::UnaryOp {
            op: circuit_op,
            operand: Box::new(inner),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert an AST Span to an OptSpan for error reporting.
fn to_span(span: &Span) -> OptSpan {
    span_box(Some(SpanRange::from(span)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use achronyme_parser::parse_program;

    /// Helper: parse source and compile the first expression to CircuitExpr.
    fn compile_single_expr(source: &str) -> Result<CircuitExpr, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let mut compiler = ProveIrCompiler::new();
        match &program.stmts[0] {
            Stmt::Expr(expr) => compiler.compile_expr(expr),
            _ => panic!("expected expression statement"),
        }
    }

    /// Helper: parse source with outer scope, compile an expression.
    fn compile_expr_with_scope(
        source: &str,
        scope: &[(&str, CompEnvValue)],
    ) -> Result<CircuitExpr, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let mut compiler = ProveIrCompiler::new();
        for (name, val) in scope {
            compiler.env.insert(name.to_string(), val.clone());
        }
        match &program.stmts[0] {
            Stmt::Expr(expr) => compiler.compile_expr(expr),
            _ => panic!("expected expression statement"),
        }
    }

    // --- Literals ---

    #[test]
    fn number_literal() {
        let expr = compile_single_expr("42").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::from_u64(42)));
    }

    #[test]
    fn negative_number() {
        let expr = compile_single_expr("-7").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(FieldElement::from_u64(7))),
            }
        );
    }

    #[test]
    fn field_literal_decimal() {
        let expr = compile_single_expr("0p42").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::from_u64(42)));
    }

    #[test]
    fn field_literal_hex() {
        let expr = compile_single_expr("0pxFF").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::from_u64(255)));
    }

    #[test]
    fn bool_true() {
        let expr = compile_single_expr("true").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::ONE));
    }

    #[test]
    fn bool_false() {
        let expr = compile_single_expr("false").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::ZERO));
    }

    #[test]
    fn negative_field_literal() {
        // Negative numbers go through UnaryOp(Neg, Number)
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("-0p42", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                ..
            }
        ));
    }

    // --- Identifiers ---

    #[test]
    fn ident_scalar() {
        let expr =
            compile_expr_with_scope("x", &[("x", CompEnvValue::Scalar("x".into()))]).unwrap();
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    #[test]
    fn ident_capture() {
        let expr =
            compile_expr_with_scope("n", &[("n", CompEnvValue::Capture("n".into()))]).unwrap();
        assert_eq!(expr, CircuitExpr::Capture("n".into()));
    }

    #[test]
    fn ident_array_as_scalar_errors() {
        let err =
            compile_expr_with_scope("arr", &[("arr", CompEnvValue::Array(vec!["arr_0".into()]))])
                .unwrap_err();
        assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
    }

    #[test]
    fn ident_undeclared_errors() {
        let err = compile_single_expr("unknown").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::UndeclaredVariable { name, .. } if name == "unknown"
        ));
    }

    // --- Binary operations ---

    #[test]
    fn binop_add() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a + b", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var("a".into())),
                rhs: Box::new(CircuitExpr::Var("b".into())),
            }
        );
    }

    #[test]
    fn binop_mul() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x * 2", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn binop_mod_rejected() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let err = compile_expr_with_scope("a % b", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Comparisons ---

    #[test]
    fn comparison_eq() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a == b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn comparison_gt() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x > 5", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Gt,
                ..
            }
        ));
    }

    // --- Boolean ops ---

    #[test]
    fn bool_and() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a && b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::And,
                ..
            }
        ));
    }

    #[test]
    fn bool_or() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a || b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::Or,
                ..
            }
        ));
    }

    // --- Unary ops ---

    #[test]
    fn unary_neg() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("-x", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Var("x".into())),
            }
        );
    }

    #[test]
    fn unary_not() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("!x", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Not,
                operand: Box::new(CircuitExpr::Var("x".into())),
            }
        );
    }

    #[test]
    fn double_negation_cancelled() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("--x", &scope).unwrap();
        // Double negation cancels to just x
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    // --- Power ---

    #[test]
    fn pow_constant_exponent() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x ^ 3", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Pow {
                base: Box::new(CircuitExpr::Var("x".into())),
                exp: 3,
            }
        );
    }

    #[test]
    fn pow_variable_exponent_rejected() {
        let scope = [
            ("x", CompEnvValue::Scalar("x".into())),
            ("n", CompEnvValue::Scalar("n".into())),
        ];
        let err = compile_expr_with_scope("x ^ n", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Rejections ---

    #[test]
    fn string_rejected() {
        let err = compile_single_expr("\"hello\"").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "string"
        ));
    }

    #[test]
    fn nil_rejected() {
        let err = compile_single_expr("nil").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "nil"
        ));
    }

    #[test]
    fn closure_rejected() {
        let err = compile_single_expr("fn(x) { x }").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Nested expressions ---

    #[test]
    fn nested_arithmetic() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
            ("c", CompEnvValue::Scalar("c".into())),
        ];
        let expr = compile_expr_with_scope("a * b + c", &scope).unwrap();
        // Should be Add(Mul(a, b), c)
        assert!(matches!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                ..
            }
        ));
    }
}
