//! Expression compilation on [`ProveIrCompiler`].
//!
//! The `compile_expr` dispatcher plus five per-concern submodules. Each
//! submodule owns one `impl<F: FieldBackend> ProveIrCompiler<F> { ... }`
//! block; cross-submodule calls go through `pub(super)` visibility,
//! which here resolves up to this `exprs` module.
//!
//! ## Submodules
//!
//! - [`atoms`] — literal + identifier compilation (`compile_number`,
//!   `compile_field_lit`, `compile_ident`).
//! - [`control`] — control-flow expressions (`compile_if_expr`,
//!   `compile_index`, `compile_block_as_expr`).
//! - [`for_loop`] — `compile_for_expr` plus its eager-unroll variants
//!   and the carry-set detection helpers.
//! - [`inline`] — user-fn inlining (`compile_user_fn_call`,
//!   `bind_array_fn_param`).
//! - [`ops`] — binary, unary, and constant-extraction helpers
//!   (`compile_binop`, `compile_arith_binop`, `compile_comparison`,
//!   `compile_bool_binop`, `compile_pow`, `compile_unary`,
//!   `extract_const_u64`).
//!
//! Statement-level compilation lives in [`super::stmts`]; call dispatch
//! and builtin lowering in [`super::calls`]; method lookups in
//! [`super::methods`].

use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::helpers::to_span;
use super::ProveIrCompiler;
use crate::error::ProveIrError;
use crate::types::*;

mod atoms;
mod control;
mod for_loop;
mod inline;
mod ops;

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Compile an AST expression into a `CircuitExpr`.
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<CircuitExpr, ProveIrError> {
        // Thread the current ExprId so the resolver-dispatch hooks in
        // `compile_ident` / `compile_named_call` can pair it with the
        // active resolver module to form the annotation lookup key.
        // Mirrors the VM compiler's pattern in
        // `compiler/src/expressions/mod.rs::compile_expr`. The
        // previous id never needs saving — `compile_expr` is the only
        // writer, and each recursive call re-overrides the field
        // before any hook reads it.
        self.current_expr_id = Some(expr.id());
        match expr {
            Expr::Number { value, span, .. } => self.compile_number(value, span),
            Expr::FieldLit {
                value, radix, span, ..
            } => self.compile_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => Ok(CircuitExpr::Const(FieldConst::one())),
            Expr::Bool { value: false, .. } => Ok(CircuitExpr::Const(FieldConst::zero())),
            Expr::Ident { name, span, .. } => self.compile_ident(name, span),

            Expr::BinOp {
                op, lhs, rhs, span, ..
            } => self.compile_binop(op, lhs, rhs, span),
            Expr::UnaryOp {
                op, operand, span, ..
            } => self.compile_unary(op, operand, span),

            Expr::StaticAccess {
                type_name,
                member,
                span,
                ..
            } => self.compile_static_access(type_name, member, span),

            Expr::Call {
                callee, args, span, ..
            } => {
                let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                self.compile_call(callee, &arg_vals, span)
            }

            Expr::DotAccess {
                object,
                field,
                span,
                ..
            } => self.compile_dot_access(object, field, span),

            Expr::If {
                condition,
                then_block,
                else_branch,
                span,
                ..
            } => self.compile_if_expr(condition, then_block, else_branch.as_ref(), span),

            Expr::For {
                var,
                iterable,
                body,
                span,
                ..
            } => self.compile_for_expr(var, iterable, body, span),

            Expr::Block { block, .. } => self.compile_block_as_expr(block),

            Expr::Index {
                object,
                index,
                span,
                ..
            } => self.compile_index(object, index, span),

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
            // CircuitCall removed — keyword-arg calls are now unified in Call
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
            Expr::Nil { span, .. } => Err(ProveIrError::TypeNotConstrainable {
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
            Expr::Error { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "cannot compile error placeholder (source has parse errors)".into(),
                span: to_span(span),
            }),
        }
    }
}
