//! Dot access + method-call dispatch on [`ProveIrCompiler`].
//!
//! 11 methods that handle non-call DotAccess + every method-call
//! lookup, plus the small family of arity / message-extraction
//! helpers shared across method dispatch:
//!
//! - `compile_dot_access` — the standalone `obj.field` expression.
//! - `compile_method_call` — the `obj.method(args)` dispatch (the big
//!   per-method match). Includes the `len()` carve-out.
//! - `extract_array_ident`, `compile_len_call` — shared helpers used
//!   by the array `len()` method.
//! - `check_arity`, `check_assert_eq_arity`, `check_assert_arity`,
//!   `check_method_arity` — argument count enforcement with the
//!   "expected N got M" diagnostics.
//! - `extract_assert_message` — pulls the trailing string-literal arg
//!   from `assert(expr, "msg")` calls.
//! - `method_not_constrainable` — canonical `MethodNotConstrainable`
//!   error builder with span propagation.
//! - `has_function` — `fn_table` containment check (resolver fallback
//!   path).

use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::helpers::to_span;
use super::{CompEnvValue, ProveIrCompiler};
use crate::prove_ir::error::ProveIrError;
use crate::prove_ir::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(super) fn compile_dot_access(
        &mut self,
        object: &Expr,
        field: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // module.constant access
        if let Expr::Ident { name: module, .. } = object {
            // Module-level constants resolve through a `module::field`
            // env key.
            let qualified = format!("{module}::{field}");
            if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&qualified) {
                return Ok(CircuitExpr::Var(resolved.clone()));
            }
            // Circom template output fields: `let r = T()(x); r.out`
            // bound in compile_let_for_circom_call under the dotted
            // "<binding_name>.<output_name>" env key.
            let dotted = format!("{module}.{field}");
            if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&dotted) {
                return Ok(CircuitExpr::Var(resolved.clone()));
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "dot access is not supported in circuits \
                          (use methods like .len(), .abs(), etc. or arrays with indexing)"
                .into(),
            span: to_span(span),
        })
    }

    // -----------------------------------------------------------------------
    // Method desugaring
    // -----------------------------------------------------------------------

    pub(super) fn compile_method_call(
        &mut self,
        object: &Expr,
        method: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match method {
            // --- Universally supported ---
            "len" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "len".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                self.compile_len_call(object, span)
            }

            // --- Identity in circuit context ---
            "to_field" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "to_field".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                // All circuit values are field elements — identity
                self.compile_expr(object)
            }

            // --- Int methods desugared to circuit primitives ---
            // NOTE: abs/min/max use CircuitCmpOp::Lt which requires a signed-range
            // comparison gadget at instantiation time (Phase B). See CircuitCmpOp doc.
            "abs" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "abs".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                let x = self.compile_expr(object)?;
                let zero = CircuitExpr::Const(FieldConst::zero());
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(x.clone()),
                        rhs: Box::new(zero),
                    }),
                    if_true: Box::new(CircuitExpr::UnaryOp {
                        op: CircuitUnaryOp::Neg,
                        operand: Box::new(x.clone()),
                    }),
                    if_false: Box::new(x),
                })
            }
            "min" => {
                self.check_method_arity("min", 1, args.len(), span)?;
                let n = self.compile_expr(object)?;
                let m = self.compile_expr(args[0])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(n.clone()),
                        rhs: Box::new(m.clone()),
                    }),
                    if_true: Box::new(n),
                    if_false: Box::new(m),
                })
            }
            "max" => {
                self.check_method_arity("max", 1, args.len(), span)?;
                let n = self.compile_expr(object)?;
                let m = self.compile_expr(args[0])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(n.clone()),
                        rhs: Box::new(m.clone()),
                    }),
                    if_true: Box::new(m),
                    if_false: Box::new(n),
                })
            }
            "pow" => {
                self.check_method_arity("pow", 1, args.len(), span)?;
                let base = self.compile_expr(object)?;
                let exp = self.extract_const_u64(args[0], span)?;
                Ok(CircuitExpr::Pow {
                    base: Box::new(base),
                    exp,
                })
            }

            // --- Methods that cannot be compiled to constraints ---
            "to_string" => Err(self.method_not_constrainable(
                "to_string",
                "produces a string, which cannot be represented in circuits",
                span,
            )),
            "to_int" => Err(self.method_not_constrainable(
                "to_int",
                "type narrowing is not needed in circuits (all values are field elements)",
                span,
            )),
            "push" | "pop" => Err(self.method_not_constrainable(
                method,
                "mutation is not supported in circuits (arrays have fixed size)",
                span,
            )),
            "map" | "filter" | "reduce" | "for_each" | "find" | "any" | "all" | "sort"
            | "flat_map" | "zip" => Err(self.method_not_constrainable(
                method,
                "higher-order collection methods are not yet supported in circuits \
                 (use a for loop instead)",
                span,
            )),
            "keys" | "values" | "entries" | "contains_key" | "get" | "set" | "remove" => Err(self
                .method_not_constrainable(
                    method,
                    "map operations are not supported in circuits \
                     (maps cannot be represented as constraints)",
                    span,
                )),
            "split" | "trim" | "replace" | "to_upper" | "to_lower" | "chars" | "index_of"
            | "substring" | "repeat" | "starts_with" | "ends_with" | "contains" => Err(self
                .method_not_constrainable(
                    method,
                    "string operations are not supported in circuits",
                    span,
                )),
            "bit_and" | "bit_or" | "bit_xor" | "bit_not" | "bit_shl" | "bit_shr" | "to_bits" => {
                Err(self.method_not_constrainable(
                    method,
                    "BigInt operations are not supported in circuits",
                    span,
                ))
            }

            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("method `.{method}()` is not supported in circuits"),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers for call/method compilation
    // -----------------------------------------------------------------------

    /// Extract an array identifier name from an expression (for merkle_verify args).
    pub(super) fn extract_array_ident(&mut self, expr: &Expr, span: &Span) -> Result<String, ProveIrError> {
        if let Expr::Ident { name, .. } = expr {
            match self.env.get(name.as_str()) {
                Some(CompEnvValue::Array(elems)) => {
                    // Mark element names as captured (only if they ARE captures
                    // from the outer scope, not declared inputs within the circuit).
                    for elem in elems.clone() {
                        if matches!(self.env.get(&elem), Some(CompEnvValue::Capture(_))) {
                            self.captured_names.insert(elem);
                        }
                    }
                    return Ok(name.clone());
                }
                Some(CompEnvValue::Capture(_)) => {
                    return Ok(name.clone());
                }
                _ => {}
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "merkle_verify requires array identifiers for path and indices".into(),
            span: to_span(span),
        })
    }

    /// Compile `len(expr)` or `expr.len()` — resolve to ArrayLen.
    pub(super) fn compile_len_call(
        &mut self,
        object: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        if let Expr::Ident { name, .. } = object {
            if matches!(
                self.env.get(name.as_str()),
                Some(CompEnvValue::Array(_)) | Some(CompEnvValue::Capture(_))
            ) {
                return Ok(CircuitExpr::ArrayLen(name.clone()));
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "len() requires an array variable in circuits".into(),
            span: to_span(span),
        })
    }

    pub(super) fn check_arity(
        &self,
        name: &str,
        expected: usize,
        got: usize,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        if got != expected {
            return Err(ProveIrError::WrongArgumentCount {
                name: name.into(),
                expected,
                got,
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Validate assert_eq arity: 2 or 3 arguments.
    pub(super) fn check_assert_eq_arity(&self, got: usize, span: &Span) -> Result<(), ProveIrError> {
        if !(2..=3).contains(&got) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!("`assert_eq` expects 2 or 3 arguments, got {got}"),
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Validate assert arity: 1 or 2 arguments.
    pub(super) fn check_assert_arity(&self, got: usize, span: &Span) -> Result<(), ProveIrError> {
        if !(1..=2).contains(&got) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!("`assert` expects 1 or 2 arguments, got {got}"),
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Extract an optional string literal for assert_eq/assert messages.
    pub(super) fn extract_assert_message(
        &self,
        arg: Option<&&Expr>,
        span: &Span,
    ) -> Result<Option<String>, ProveIrError> {
        match arg {
            None => Ok(None),
            Some(Expr::StringLit { value, .. }) => Ok(Some(value.clone())),
            Some(_) => Err(ProveIrError::TypeMismatch {
                expected: "string literal".into(),
                got: "non-string expression (assert_eq message must be a string literal)".into(),
                span: to_span(span),
            }),
        }
    }

    pub(super) fn check_method_arity(
        &self,
        name: &str,
        expected: usize,
        got: usize,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        if got != expected {
            return Err(ProveIrError::WrongArgumentCount {
                name: format!(".{name}()"),
                expected,
                got,
                span: to_span(span),
            });
        }
        Ok(())
    }

    pub(super) fn method_not_constrainable(&self, method: &str, reason: &str, span: &Span) -> ProveIrError {
        ProveIrError::MethodNotConstrainable {
            method: method.into(),
            reason: reason.into(),
            span: to_span(span),
        }
    }

    /// Check if a function name exists in the fn_table.
    pub(super) fn has_function(&self, name: &str) -> bool {
        self.fn_table.contains_key(name)
    }
}
