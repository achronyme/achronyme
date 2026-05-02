//! Shared circom template instantiation.
//!
//! [`instantiate_circom_template`](super::super::ProveIrCompiler::instantiate_circom_template)
//! is the single body for compiling a resolved
//! `T(template_args)(signal_inputs)` invocation: validate arity,
//! evaluate template args to `FieldConst`, compile signal inputs
//! (scalar 1:1 or row-major flatten for arrays), allocate a
//! mangling prefix, dispatch to the library handle, and append the
//! returned body nodes to `self.body`. Returns the outputs map and
//! resolved signature so callers can project or re-bind however
//! the call context needs.
//!
//! Both circom call entry points in [`super::circom_call`] funnel
//! through this method.

use std::collections::HashMap;

use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::ProveIrCompiler;
use crate::error::{CircomDispatchErrorKind, ProveIrError};
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Core circom template instantiation path — shared by both the
    /// expression-level dispatcher and the let-binding dispatcher.
    ///
    /// Validates arity, evaluates template args to `FieldConst`,
    /// compiles signal inputs, allocates a fresh mangling prefix,
    /// dispatches to the library handle, and appends the returned
    /// body nodes to `self.body`.
    ///
    /// Returns the outputs map together with the resolved template
    /// signature so callers can project or re-bind however the
    /// caller context needs.
    pub(super) fn instantiate_circom_template(
        &mut self,
        key: &str,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
        span: &Span,
    ) -> Result<
        (
            HashMap<String, crate::CircomTemplateOutput>,
            crate::CircomTemplateSignature,
        ),
        ProveIrError,
    > {
        let callable = self
            .circom_table
            .get(key)
            .expect("try_resolve_circom_key validated the key")
            .clone();

        let signature = callable
            .library
            .template_signature(&callable.template_name)
            .ok_or_else(|| ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: callable.template_name.clone(),
                    message: "template disappeared from library after registration".into(),
                },
                span: to_span(span),
            })?;

        if template_args.len() != signature.params.len() {
            return Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::ParamCountMismatch {
                    template: callable.template_name.clone(),
                    expected: signature.params.len(),
                    got: template_args.len(),
                },
                span: to_span(span),
            });
        }

        let mut template_const_args: Vec<FieldConst> = Vec::with_capacity(template_args.len());
        for (i, arg) in template_args.iter().enumerate() {
            let compiled = self.compile_expr(arg)?;
            match compiled {
                CircuitExpr::Const(fc) => template_const_args.push(fc),
                _ => {
                    return Err(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::TemplateArgNotConst {
                            template: callable.template_name.clone(),
                            arg_index: i,
                        },
                        span: to_span(span),
                    });
                }
            }
        }

        if signal_inputs.len() != signature.input_signals.len() {
            return Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::SignalInputCountMismatch {
                    template: callable.template_name.clone(),
                    expected: signature.input_signals.len(),
                    got: signal_inputs.len(),
                },
                span: to_span(span),
            });
        }

        // Resolve the input layout against the concrete template
        // arguments so we know which signals are scalar vs array.
        // Array signals require the user-side expression to be an
        // `Expr::Array` literal; we expand each element into its own
        // `signal_name_<i>` entry so `instantiate_template_into` can
        // wire them individually.
        let input_layouts = callable
            .library
            .resolve_input_layout(&callable.template_name, &template_const_args)
            .ok_or_else(|| ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: callable.template_name.clone(),
                    message: "could not resolve input signal dimensions for the given \
                              template arguments (parametric sizes must collapse to \
                              concrete integers)"
                        .into(),
                },
                span: to_span(span),
            })?;

        let mut signal_input_map: HashMap<String, CircuitExpr> = HashMap::new();
        for (layout, sig_input_expr) in input_layouts.iter().zip(signal_inputs.iter()) {
            if layout.dims.is_empty() {
                // Scalar signal — single expression maps 1:1.
                let compiled = self.compile_expr(sig_input_expr)?;
                signal_input_map.insert(layout.name.clone(), compiled);
                continue;
            }

            // Array-valued signal — the user must pass an array literal
            // whose flattened length matches the signal's total size.
            let expected_len: u64 = layout.dims.iter().product();
            let Expr::Array { elements, .. } = sig_input_expr else {
                return Err(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::LoweringFailed {
                        template: callable.template_name.clone(),
                        message: format!(
                            "signal input `{}` is declared as an array of size {} \
                             but the caller passed a non-array expression; wrap the \
                             inputs in `[...]` (e.g. `T(...)([a, b])`)",
                            layout.name, expected_len
                        ),
                    },
                    span: to_span(span),
                });
            };
            if elements.len() as u64 != expected_len {
                return Err(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::LoweringFailed {
                        template: callable.template_name.clone(),
                        message: format!(
                            "signal input `{}` expects an array of {} element(s) but \
                             the caller passed {}",
                            layout.name,
                            expected_len,
                            elements.len()
                        ),
                    },
                    span: to_span(span),
                });
            }
            // Build row-major flat indices (e.g. `[n]` → `_0`..`_{n-1}`,
            // `[r, c]` → `_0_0`..`_{r-1}_{c-1}`) so the key layout
            // matches `instantiate_template_into`'s expectations.
            let indices = Self::flatten_row_major_indices(&layout.dims);
            for (elem, idx) in elements.iter().zip(indices.iter()) {
                let compiled = self.compile_expr(elem)?;
                let suffix = idx
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("_");
                signal_input_map.insert(format!("{}_{suffix}", layout.name), compiled);
            }
        }

        let prefix = self.next_circom_call_prefix();

        let instantiation = callable
            .library
            .instantiate_template(
                &callable.template_name,
                &template_const_args,
                &signal_input_map,
                &prefix,
                span,
            )
            .map_err(|e| {
                use crate::CircomDispatchError as CircomErr;
                let kind = match e {
                    CircomErr::UnknownTemplate { template, .. } => {
                        CircomDispatchErrorKind::LoweringFailed {
                            template,
                            message: "internal: template vanished mid-instantiation".into(),
                        }
                    }
                    CircomErr::ParamCountMismatch {
                        template,
                        expected,
                        got,
                    } => CircomDispatchErrorKind::ParamCountMismatch {
                        template,
                        expected,
                        got,
                    },
                    CircomErr::MissingSignalInput { template, signal } => {
                        CircomDispatchErrorKind::LoweringFailed {
                            template,
                            message: format!("missing signal input `{signal}`"),
                        }
                    }
                    CircomErr::UnsupportedArrayInput { template, signal } => {
                        CircomDispatchErrorKind::ArrayInputUnsupported { template, signal }
                    }
                    CircomErr::Lowering(msg) => CircomDispatchErrorKind::LoweringFailed {
                        template: callable.template_name.clone(),
                        message: msg,
                    },
                };
                ProveIrError::CircomDispatch {
                    kind,
                    span: to_span(span),
                }
            })?;

        self.body.extend(instantiation.body);
        Ok((instantiation.outputs, signature))
    }
}
