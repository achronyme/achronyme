//! Literal and identifier compilation.
//!
//! Three methods that turn the simplest `Expr` shapes into a
//! `CircuitExpr`:
//!
//! - `compile_number` — integer literals (with sign), rejecting decimals.
//! - `compile_field_lit` — `0x…` / `0b…` / decimal field literals.
//! - `compile_ident` — environment lookup + capture tracking.

use achronyme_parser::ast::*;
use memory::{FieldBackend, FieldElement};

use super::super::helpers::to_span;
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(super) fn compile_number(&self, s: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
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
        let fe = FieldElement::<F>::from_decimal_str(digits).ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!("invalid integer literal: {s}"),
                span: to_span(span),
            }
        })?;
        let fc = FieldConst::from_field(fe);
        if negative {
            Ok(CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(fc)),
            })
        } else {
            Ok(CircuitExpr::Const(fc))
        }
    }

    pub(super) fn compile_field_lit(
        &self,
        value: &str,
        radix: &FieldRadix,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let fe = match radix {
            FieldRadix::Decimal => FieldElement::<F>::from_decimal_str(value),
            FieldRadix::Hex => FieldElement::<F>::from_hex_str(value),
            FieldRadix::Binary => FieldElement::<F>::from_binary_str(value),
        }
        .ok_or_else(|| ProveIrError::UnsupportedOperation {
            description: format!("invalid field literal: {value}"),
            span: to_span(span),
        })?;
        Ok(CircuitExpr::Const(FieldConst::from_field(fe)))
    }

    pub(super) fn compile_ident(
        &mut self,
        name: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Record a resolver hit for the current expression so the
        // annotation-driven dispatch trace stays observable here.
        // No-op when resolver state isn't installed, when
        // `current_expr_id` is unset, or when the annotation map has
        // no entry for the current `(module, expr_id)` key. Has no
        // effect on the env lookup that follows.
        self.record_resolver_hit();
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
}
