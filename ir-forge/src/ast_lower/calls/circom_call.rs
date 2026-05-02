//! Circom template call entry points.
//!
//! Two complementary dispatchers that share
//! [`super::circom_instantiate`]:
//!
//! - [`compile_circom_template_call`](super::super::ProveIrCompiler::compile_circom_template_call)
//!   — expression-level call. Only single-scalar-output templates can
//!   be used as a value; multi- and array-output templates must be
//!   bound via `let r = T(...)(...)` so `r.field` / `r.elem_i`
//!   resolves through the let-bound path.
//! - [`compile_let_for_circom_call`](super::super::ProveIrCompiler::compile_let_for_circom_call)
//!   — let-binding form. Publishes every template output into the
//!   compiler env under "dotted" keys (`r.out` for scalars,
//!   `r.out_<i>` row-major for arrays) so subsequent `DotAccess`
//!   resolves to the correct mangled var. Single-scalar-output
//!   templates also bind `r` itself to the sole output for ergonomic
//!   use.

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::helpers::{flat_index_suffix, to_span};
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::{CircomDispatchErrorKind, ProveIrError};
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Expression-level circom template call. Only templates with a
    /// single scalar output are usable directly as a value — multi-
    /// output and array-output templates must be bound via `let r =
    /// T()(x)` so that `r.field` / `r.elem_i` can route through
    /// [`compile_let_for_circom_call`].
    pub(super) fn compile_circom_template_call(
        &mut self,
        key: &str,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let (outputs, signature) =
            self.instantiate_circom_template(key, template_args, signal_inputs, span)?;

        // Expression-level calls can only return a single scalar.
        // Multi-output and array-output templates need the let +
        // DotAccess machinery added in Phase 3.4.
        let template_name = self
            .circom_table
            .get(key)
            .map(|c| c.template_name.clone())
            .unwrap_or_default();
        if signature.output_signals.len() != 1 {
            return Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: template_name,
                    message: format!(
                        "template has {} outputs; bind the call with \
                         `let r = T(...)(...)` and select with `r.<output_name>`",
                        signature.output_signals.len()
                    ),
                },
                span: to_span(span),
            });
        }
        let out_name = &signature.output_signals[0];
        match outputs.get(out_name) {
            Some(crate::CircomTemplateOutput::Scalar(expr)) => Ok(expr.clone()),
            Some(crate::CircomTemplateOutput::Array { .. }) => Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::ArrayOutputRequiresIndex {
                    template: template_name,
                    signal: out_name.clone(),
                },
                span: to_span(span),
            }),
            None => Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: template_name,
                    message: format!("instantiation returned no entry for output `{out_name}`"),
                },
                span: to_span(span),
            }),
        }
    }

    /// Let-binding-aware circom template call.
    ///
    /// When the user writes `let r = T(args)(inputs)` the circom
    /// template's outputs are published into the compiler env under
    /// "dotted" keys so subsequent DotAccess resolves to each
    /// individual output:
    ///
    /// - Scalar output `out`   → env entry `"r.out"` = Scalar(mangled)
    /// - Array  output `out[N]` → env entries `"r.out_0"`..`"r.out_{N-1}"`
    ///
    /// For single-scalar-output templates the binding `r` itself is
    /// also registered (via a plain Let node) so `r` alone still
    /// evaluates to the single output — this keeps Phase 3.3 code
    /// that treats the call as a scalar expression working.
    ///
    /// Returns `Ok(true)` when the let value was a circom template
    /// call and binding succeeded; `Ok(false)` when the value did not
    /// match the circom curry shape so the caller should fall back to
    /// the normal let-compilation path.
    pub(in crate::ast_lower) fn compile_let_for_circom_call(
        &mut self,
        name: &str,
        value: &Expr,
        span: &Span,
    ) -> Result<bool, ProveIrError> {
        // Detect `Call { callee: Call { callee: <resolvable>, args: template_args }, args: signal_inputs }`.
        let Expr::Call {
            callee: outer_callee,
            args: outer_args,
            ..
        } = value
        else {
            return Ok(false);
        };
        let Expr::Call {
            callee: inner_callee,
            args: inner_args,
            ..
        } = outer_callee.as_ref()
        else {
            return Ok(false);
        };
        let Some(key) = self.try_resolve_circom_key(inner_callee) else {
            return Ok(false);
        };

        let template_arg_exprs: Vec<&Expr> = inner_args.iter().map(|a| &a.value).collect();
        let signal_input_exprs: Vec<&Expr> = outer_args.iter().map(|a| &a.value).collect();

        let (outputs, signature) =
            self.instantiate_circom_template(&key, &template_arg_exprs, &signal_input_exprs, span)?;

        // Bind every declared output under "<name>.<output>" (scalar)
        // or "<name>.<output>_<i>" (array). The mangled vars already
        // exist in self.body thanks to instantiate_circom_template;
        // the env entries just alias them so compile_dot_access can
        // resolve the user-facing `r.out` syntax.
        for sig_out in &signature.output_signals {
            match outputs.get(sig_out) {
                Some(crate::CircomTemplateOutput::Scalar(expr)) => {
                    let CircuitExpr::Var(mangled) = expr else {
                        // Defensive: library impls return Scalar(Var(...))
                        // today. If a non-Var expression ever appears we
                        // fall back to registering under the dotted name
                        // via a fresh Let binding.
                        let dotted = format!("{name}.{sig_out}");
                        self.body.push(CircuitNode::Let {
                            name: dotted.clone(),
                            value: expr.clone(),
                            span: Some(SpanRange::from(span)),
                        });
                        self.env
                            .insert(dotted.clone(), CompEnvValue::Scalar(dotted));
                        continue;
                    };
                    let dotted = format!("{name}.{sig_out}");
                    self.env
                        .insert(dotted, CompEnvValue::Scalar(mangled.clone()));
                }
                Some(crate::CircomTemplateOutput::Array { dims, values }) => {
                    // Row-major flatten: iterate every value and bind
                    // each under "<name>.<out>_<i>" / "<name>.<out>_<i>_<j>".
                    let total: u64 = dims.iter().product();
                    debug_assert_eq!(values.len() as u64, total);
                    for (linear_idx, value_expr) in values.iter().enumerate() {
                        let suffix = flat_index_suffix(dims, linear_idx);
                        let dotted = format!("{name}.{sig_out}_{suffix}");
                        match value_expr {
                            CircuitExpr::Var(mangled) => {
                                self.env
                                    .insert(dotted, CompEnvValue::Scalar(mangled.clone()));
                            }
                            other => {
                                self.body.push(CircuitNode::Let {
                                    name: dotted.clone(),
                                    value: other.clone(),
                                    span: Some(SpanRange::from(span)),
                                });
                                self.env
                                    .insert(dotted.clone(), CompEnvValue::Scalar(dotted));
                            }
                        }
                    }
                }
                None => {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "circom template declared output `{sig_out}` but instantiation \
                             returned no entry for it"
                        ),
                        span: to_span(span),
                    });
                }
            }
        }

        // Convenience: a single-scalar-output template also binds
        // `name` itself as a plain Let so existing users of
        // `let r = Square()(x); r` keep working unchanged.
        if signature.output_signals.len() == 1 {
            let sole = &signature.output_signals[0];
            if let Some(crate::CircomTemplateOutput::Scalar(expr)) = outputs.get(sole) {
                self.body.push(CircuitNode::Let {
                    name: name.to_string(),
                    value: expr.clone(),
                    span: Some(SpanRange::from(span)),
                });
                self.env
                    .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
            }
        }

        Ok(true)
    }
}
