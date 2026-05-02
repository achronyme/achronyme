//! Top-level call dispatch on [`ProveIrCompiler`].
//!
//! Owns [`ProveIrCompiler::compile_call`], which inspects the
//! callee shape and routes to one of six cohesive submodules:
//!
//! - [`static_access`] — `T::MEMBER` namespace reads
//!   ([`compile_static_access`](ProveIrCompiler::compile_static_access)).
//! - [`circom_resolve`] — `circom_table` lookup helpers
//!   ([`try_resolve_circom_key`](ProveIrCompiler::try_resolve_circom_key),
//!   [`diagnose_unresolved_circom_curry`](ProveIrCompiler::diagnose_unresolved_circom_curry)).
//! - [`circom_instantiate`] — the shared
//!   [`instantiate_circom_template`](ProveIrCompiler::instantiate_circom_template)
//!   path used by both circom call entry points.
//! - [`circom_call`] — expression-level
//!   ([`compile_circom_template_call`](ProveIrCompiler::compile_circom_template_call))
//!   and let-bound
//!   ([`compile_let_for_circom_call`](ProveIrCompiler::compile_let_for_circom_call))
//!   circom template invocations.
//! - [`dispatch`] — annotation-driven and legacy named-call dispatch
//!   ([`try_annotation_dispatch`](ProveIrCompiler::try_annotation_dispatch),
//!   [`compile_named_call`](ProveIrCompiler::compile_named_call)).
//! - [`builtins`] — every per-builtin lowering, plus the registry
//!   lookup ([`lower_builtin`](ProveIrCompiler::lower_builtin)) and
//!   handle dispatch
//!   ([`dispatch_builtin_by_handle`](ProveIrCompiler::dispatch_builtin_by_handle)).
//!
//! Method-call lookups + dot access live in [`super::methods`].

use std::collections::HashMap;

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::{FieldBackend, FieldElement};

use super::helpers::{flat_index_suffix, to_span};
use super::{CompEnvValue, DispatchDecision, ProveIrCompiler};
use crate::error::{CircomDispatchErrorKind, ProveIrError};
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(super) fn compile_static_access(
        &self,
        type_name: &str,
        member: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match (type_name, member) {
            ("Field", "ZERO") => Ok(CircuitExpr::Const(FieldConst::zero())),
            ("Field", "ONE") => Ok(CircuitExpr::Const(FieldConst::one())),
            ("Field", "ORDER") => Err(ProveIrError::StaticAccessNotConstrainable {
                type_name: "Field".into(),
                member: "ORDER".into(),
                reason: "Field::ORDER is a string (the BN254 modulus) \
                         and strings cannot be used in circuits"
                    .into(),
                span: to_span(span),
            }),
            ("Int", "MAX") => Ok(CircuitExpr::Const(FieldConst::from_field(
                FieldElement::<F>::from_i64(memory::I60_MAX),
            ))),
            ("Int", "MIN") => Ok(CircuitExpr::Const(FieldConst::from_field(
                FieldElement::<F>::from_i64(memory::I60_MIN),
            ))),
            ("BigInt", _) => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            _ => {
                // Namespace lookup for `alias::const` where `alias` is an
                // `import "./foo.ach" as alias`-style module alias. The
                // fn_table already carries entries keyed `alias::name` for
                // every exported function, and the outer scope's
                // `CompEnvValue` map carries the same for exported
                // constants. Resolving here at compile time is the prove-
                // block sibling of the VM compiler's static-access fast
                // path: no HashMap lookup at proof time, no runtime map
                // object, just a direct value reference.
                let qualified = format!("{type_name}::{member}");
                if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&qualified) {
                    return Ok(CircuitExpr::Var(resolved.clone()));
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!("unknown static access `{type_name}::{member}`"),
                    span: to_span(span),
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Call dispatch
    // -----------------------------------------------------------------------

    pub(in crate::ast_lower) fn compile_call(
        &mut self,
        callee: &Expr,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Circom template atomic curry: T(template_args)(signal_inputs)
        // parses as Call { callee: Call { callee: Ident(T), args: template_args },
        // args: signal_inputs }. Intercept here before the standard
        // call-dispatch so a bare or namespaced circom template is
        // resolved against the compiler's circom_table.
        if let Expr::Call {
            callee: inner_callee,
            args: inner_args,
            ..
        } = callee
        {
            if let Some(key) = self.try_resolve_circom_key(inner_callee) {
                let template_arg_exprs: Vec<&Expr> = inner_args.iter().map(|a| &a.value).collect();
                return self.compile_circom_template_call(&key, &template_arg_exprs, args, span);
            }
            // Inner callee didn't resolve to a registered circom
            // template. Before falling through to the normal call
            // dispatch, check whether the user misspelled a
            // registered template / namespace and surface a clean
            // "did you mean" diagnostic.
            if let Some(err) = self.diagnose_unresolved_circom_curry(inner_callee, span) {
                return Err(err);
            }
        }

        // Bare call `Template(inputs)` against a registered circom
        // template: the user forgot the `()(...)` currying layer.
        if let Expr::Ident { name, .. } = callee {
            if !self.circom_table.is_empty() {
                // Exact match: user wrote `Square(x)` when they
                // needed `Square()(x)`.
                if let Some(callable) = self.circom_table.get(name).cloned() {
                    let expected_params = callable
                        .library
                        .template_signature(&callable.template_name)
                        .map(|s| s.params.len())
                        .unwrap_or(0);
                    return Err(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::MissingTemplateParams {
                            template: callable.template_name.clone(),
                            expected_params,
                        },
                        span: to_span(span),
                    });
                }
            }
        }

        match callee {
            // Module function call via compile-time `::` path:
            //   `alias::func(args)` parses as
            //   `Call { callee: StaticAccess { type_name: alias, member: func }, args }`.
            // The alias's exported functions live in `fn_table` under the
            // `{alias}::{func}` key (seeded by the module loader at
            // OuterScope build time), so this is a direct qualified
            // lookup — no runtime map dispatch, no hashmap per call,
            // fully constexpr. This is the new preferred syntax; the
            // older `alias.func()` DotAccess form is still accepted
            // below for a transition period.
            Expr::StaticAccess {
                type_name,
                member,
                id: static_id,
                ..
            } => {
                // Phase 3F: try annotation-driven dispatch first so
                // cross-module calls via `alias::name` also push
                // the definer's module onto the resolver stack via
                // `compile_user_fn_call` — this is what kills gap
                // 2.4 for the `a → b::middle → helper` scenario
                // (helper is a bare identifier inside middle's
                // inlined body and resolves against mod_B, not
                // against a's root module).
                //
                // `compile_expr` set `current_expr_id` to the
                // Call's id when it dispatched here; we temporarily
                // override it with the StaticAccess's own id so
                // the annotation lookup keys correctly, then
                // restore it afterwards.
                let saved_expr_id = self.current_expr_id;
                self.current_expr_id = Some(*static_id);
                let annotation_result = self.try_annotation_dispatch(*static_id, args, span);
                self.current_expr_id = saved_expr_id;
                match annotation_result {
                    Ok(Some(expr)) => return Ok(expr),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }

                // Legacy name-based lookup. `compile_user_fn_call`
                // still maintains the resolver module stack via
                // `resolver_module_by_key`, so the stack discipline
                // holds even on this fallback path.
                let qualified = format!("{type_name}::{member}");
                if self.has_function(&qualified) {
                    return self.compile_user_fn_call(&qualified, args, span);
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "unknown function `{type_name}::{member}` — is the alias \
                         imported with `import \"./...\" as {type_name}` and the \
                         function exported?"
                    ),
                    span: to_span(span),
                })
            }

            // Method call: expr.method(args).
            //
            // `alias.func(...)` where `alias` is a module namespace
            // import is no longer the canonical syntax — use
            // `alias::func(...)` (handled by the `StaticAccess` arm
            // above). Emit a migration error instead of silently
            // falling through so the old syntax becomes a hard
            // compile-time failure with a clean "did you mean" hint.
            Expr::DotAccess {
                object,
                field,
                span: dot_span,
                ..
            } => {
                if let Expr::Ident { name: module, .. } = object.as_ref() {
                    let qualified = format!("{module}::{field}");
                    if self.has_function(&qualified) || self.circom_table.contains_key(&qualified) {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "use `{module}::{field}(...)` instead of \
                                 `{module}.{field}(...)` — module-qualified calls \
                                 are now compile-time paths, not dynamic method \
                                 dispatch"
                            ),
                            span: to_span(span),
                        });
                    }
                }
                self.compile_method_call(object, field, args, dot_span)
            }

            // Named function/builtin call: name(args)
            //
            // Phase 3E.1: the resolver's annotate_program walker
            // annotates the callee Ident (not the enclosing Call),
            // so we need the Ident's own ExprId to consult the
            // annotation table. `compile_expr` has stashed the Call's
            // id in `self.current_expr_id` by now — re-override it
            // with the Ident's id so the shadow hook in
            // `compile_named_call` reads the correct annotation key.
            // This is cheap and localized; the alternative of
            // threading the id through `compile_named_call`'s
            // signature would touch many test call sites.
            Expr::Ident { name, id, .. } => {
                self.current_expr_id = Some(*id);
                self.compile_named_call(name, args, span)
            }

            // Dynamic dispatch not supported
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "only named function calls are supported in circuits \
                              (dynamic dispatch cannot be compiled to constraints)"
                    .into(),
                span: to_span(span),
            }),
        }
    }

    /// When a `T(args)(inputs)` shape fails to resolve against the
    /// circom_table, try to produce a clean "did you mean?" diagnostic
    /// that points at the inner callee. Returns `Some(err)` only if
    /// the user appears to have *meant* a circom template — otherwise
    /// returns `None` so the caller falls through to the normal
    /// function dispatch.
    pub(super) fn diagnose_unresolved_circom_curry(
        &self,
        inner_callee: &Expr,
        span: &Span,
    ) -> Option<ProveIrError> {
        if self.circom_table.is_empty() {
            return None;
        }
        match inner_callee {
            // Bare `Template(args)(inputs)` with a misspelled name.
            Expr::Ident { name, .. } => {
                // Only produce a suggestion if we have at least one
                // selective (non-namespaced) entry — otherwise this
                // is almost certainly a regular function call typo.
                let flat_keys: Vec<&str> = self
                    .circom_table
                    .keys()
                    .filter(|k| !k.contains("::"))
                    .map(String::as_str)
                    .collect();
                if flat_keys.is_empty() {
                    return None;
                }
                let did_you_mean = crate::suggest::find_similar_ir(name, flat_keys.into_iter());
                // Only emit the diagnostic if we actually found a
                // similar registered name — otherwise the user's
                // call is probably a regular function call and we
                // shouldn't assume circom intent.
                did_you_mean.map(|suggestion| ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateNotFoundSelective {
                        template: name.clone(),
                        did_you_mean: Some(suggestion),
                    },
                    span: to_span(span),
                })
            }
            // `P.Template(args)(inputs)` — namespace or template typo.
            Expr::DotAccess { object, field, .. } => {
                let Expr::Ident { name: alias, .. } = object.as_ref() else {
                    return None;
                };
                // Collect registered namespace prefixes (everything
                // before "::" in circom_table keys).
                let mut namespaces: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for k in self.circom_table.keys() {
                    if let Some((ns, _)) = k.split_once("::") {
                        namespaces.insert(ns.to_string());
                    }
                }
                if !namespaces.contains(alias) {
                    // Alias itself is unknown — suggest a namespace.
                    let suggestion = crate::suggest::find_similar_ir(
                        alias,
                        namespaces.iter().map(String::as_str),
                    );
                    return Some(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::NamespaceNotFound {
                            alias: alias.clone(),
                            did_you_mean: suggestion,
                        },
                        span: to_span(span),
                    });
                }
                // Alias is valid; the template name is wrong.
                let expected_prefix = format!("{alias}::");
                let templates_in_ns: Vec<String> = self
                    .circom_table
                    .keys()
                    .filter_map(|k| k.strip_prefix(&expected_prefix).map(String::from))
                    .collect();
                let suggestion = crate::suggest::find_similar_ir(
                    field,
                    templates_in_ns.iter().map(String::as_str),
                );
                Some(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateNotFoundInNamespace {
                        alias: alias.clone(),
                        template: field.clone(),
                        did_you_mean: suggestion,
                    },
                    span: to_span(span),
                })
            }
            _ => None,
        }
    }

    /// Try to resolve an expression used as the inner callee of a
    /// `T(...)(...)` atomic curry to a key in `circom_table`.
    ///
    /// Returns `Some(key)` when the expression is either:
    /// - `Expr::Ident { name }` and `name` is a registered selective
    ///   import (bare template name key), or
    /// - `Expr::DotAccess { object: Ident(P), field: T }` and
    ///   `"P::T"` is registered as a namespace entry (Phase 3.4).
    ///
    /// Returns `None` for every other shape so the caller falls
    /// through to the normal call dispatch without regression.
    pub(super) fn try_resolve_circom_key(&self, callee: &Expr) -> Option<String> {
        match callee {
            Expr::Ident { name, .. } => {
                if self.circom_table.contains_key(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            // Namespaced circom template via the compile-time `::` path:
            // `P::Poseidon(2)([a, b])` parses as
            //   Call { Call { StaticAccess { P, Poseidon }, [2] }, [arr] }
            // so the inner callee is a `StaticAccess` whose `type_name`
            // is the import alias. Match the same `{alias}::{template}`
            // key format the circom dispatch table uses for namespace
            // imports.
            Expr::StaticAccess {
                type_name, member, ..
            } => {
                let key = format!("{type_name}::{member}");
                if self.circom_table.contains_key(&key) {
                    Some(key)
                } else {
                    None
                }
            }
            Expr::DotAccess { object, field, .. } => {
                if let Expr::Ident { name: alias, .. } = object.as_ref() {
                    let key = format!("{alias}::{field}");
                    if self.circom_table.contains_key(&key) {
                        return Some(key);
                    }
                }
                None
            }
            _ => None,
        }
    }

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
    pub(super) fn compile_let_for_circom_call(
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

    /// Attempt annotation-driven dispatch for a call site.
    ///
    /// Shared helper consumed by both [`compile_named_call`] (for
    /// bare-ident callees) and the `StaticAccess` arm of
    /// [`compile_call`] (for `alias::name` callees). Returns:
    ///
    /// - `Ok(Some(expr))` — the annotation path handled the call
    ///   fully and produced a [`CircuitExpr`]. The caller returns
    ///   this immediately.
    /// - `Ok(None)` — the annotation path declined (no annotation,
    ///   unresolved dispatch map, or the annotated fn_table key
    ///   isn't in `fn_table`). The caller falls through to the
    ///   legacy name-based dispatch.
    /// - `Err(e)` — the annotation path matched a dispatch site but
    ///   the downstream compile errored (builtin arity mismatch,
    ///   fn body compile failure, etc.).
    ///
    /// Module-stack push/pop for inlined user fn bodies lives in
    /// [`compile_user_fn_call`] itself — this helper only selects
    /// the dispatch arm.
    pub(super) fn try_annotation_dispatch(
        &mut self,
        callee_expr_id: ExprId,
        args: &[&Expr],
        span: &Span,
    ) -> Result<Option<CircuitExpr>, ProveIrError> {
        match self.resolve_dispatch_via_annotation(callee_expr_id) {
            DispatchDecision::Builtin { handle } => self
                .dispatch_builtin_by_handle(handle, args, span)
                .map(Some),
            DispatchDecision::UserFn { qualified_name } => {
                // Phase 3F: the dispatch map already translated the
                // SymbolId to the correct fn_table key. If the key
                // isn't in `fn_table` we fall through to legacy —
                // happens when a symbol is known to the resolver
                // but not registered in this specific prove block's
                // OuterScope (e.g. prove-block-local imports that
                // the auto-build never saw).
                if !self.has_function(&qualified_name) {
                    return Ok(None);
                }
                // Stack push/pop for the inlined body lives inside
                // `compile_user_fn_call` — it consults
                // `resolver_module_by_key` to discover the definer's
                // module, so both the annotation path and the
                // legacy path maintain the stack uniformly.
                self.compile_user_fn_call(&qualified_name, args, span)
                    .map(Some)
            }
            DispatchDecision::NoAnnotation => {
                // Record a shadow hit for symmetry with Phase 3E.1
                // — the annotation map may still have an entry
                // (Constant in call position, etc.) that the
                // dispatch helper rejected. The hit trace still
                // reflects what the resolver saw at this call site.
                self.record_resolver_hit_for(callee_expr_id);
                Ok(None)
            }
        }
    }

    /// Compile a named function or builtin call.
    ///
    /// Movimiento 2 Phase 3E.2 / 3F — annotation-driven dispatch
    /// delegates to [`try_annotation_dispatch`] and falls back to
    /// the legacy name-based path if the annotation path declines.
    pub(super) fn compile_named_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Phase 3E.2: consult the annotation table for the current
        // callee Ident. `current_expr_id` was overridden with the
        // Ident's ExprId by `compile_call`'s Ident arm.
        if let Some(expr_id) = self.current_expr_id {
            if let Some(expr) = self.try_annotation_dispatch(expr_id, args, span)? {
                return Ok(expr);
            }
        } else {
            // No current_expr_id — synthetic call or similar. The
            // shadow hook keys off current_expr_id internally, so
            // this is a no-op in practice; the call records
            // nothing for synthetic invocations.
            self.record_resolver_hit();
        }

        // Legacy dispatch path. `lower_builtin` returning `Ok(None)`
        // means the name isn't a recognised builtin; fall through
        // to user-fn inlining exactly as before.
        if let Some(expr) = self.lower_builtin(name, args, span)? {
            return Ok(expr);
        }
        self.compile_user_fn_call(name, args, span)
    }

    /// Dispatch a builtin by name. Returns:
    /// - `Ok(Some(expr))` — handled as a builtin, evaluation succeeded.
    /// - `Ok(None)` — `name` is not a recognised builtin; the caller
    ///   should fall through to user-function dispatch.
    /// - `Err(e)` — handled as a builtin but the arguments were malformed
    ///   (wrong arity, unsupported shape, etc.).
    ///
    /// Dispatch is driven by [`resolve::BuiltinRegistry`]: the name is
    /// looked up in the registry, and if a ProveIR-available entry
    /// exists, its [`ProveIrLowerHandle`] indexes into the lowering
    /// dispatch table. Names not in the registry return `Ok(None)`.
    pub(super) fn lower_builtin(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<Option<CircuitExpr>, ProveIrError> {
        use std::sync::OnceLock;
        static REGISTRY: OnceLock<resolve::BuiltinRegistry> = OnceLock::new();
        let registry = REGISTRY.get_or_init(resolve::BuiltinRegistry::default);

        let handle = match registry.lookup(name) {
            Some(entry) => match entry.prove_ir_lower {
                Some(h) => h,
                None => return Ok(None),
            },
            None => return Ok(None),
        };
        self.dispatch_builtin_by_handle(handle, args, span)
            .map(Some)
    }

    /// Dispatch a ProveIR builtin by its [`ProveIrLowerHandle`].
    ///
    /// The handle indexes into a function-pointer table whose slots
    /// correspond 1:1 with the `ProveIrLowerHandle` values declared in
    /// [`resolve::BuiltinRegistry::default()`]. Adding a new ProveIR
    /// builtin requires:
    /// 1. A new `ProveIrLowerHandle(N)` in the registry.
    /// 2. A new `lower_*` method below.
    /// 3. Slot `N` in the `LOWERINGS` table pointing to that method.
    pub(super) fn dispatch_builtin_by_handle(
        &mut self,
        handle: resolve::builtins::ProveIrLowerHandle,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        type LowerFn<F> =
            fn(&mut ProveIrCompiler<F>, &[&Expr], &Span) -> Result<CircuitExpr, ProveIrError>;

        const LOWERING_COUNT: usize = 10;
        let lowerings: [LowerFn<F>; LOWERING_COUNT] = [
            Self::lower_poseidon,      // 0
            Self::lower_poseidon_many, // 1
            Self::lower_mux,           // 2
            Self::lower_range_check,   // 3
            Self::lower_merkle_verify, // 4
            Self::lower_len,           // 5
            Self::lower_assert_eq,     // 6
            Self::lower_assert,        // 7
            Self::lower_int_div,       // 8
            Self::lower_int_mod,       // 9
        ];

        let idx = handle.as_u32() as usize;
        assert!(
            idx < LOWERING_COUNT,
            "ProveIrLowerHandle({idx}) out of range — \
             add the lowering function to dispatch_builtin_by_handle"
        );
        lowerings[idx](self, args, span)
    }

    // -- Individual builtin lowering functions --------------------------------

    pub(super) fn lower_poseidon(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("poseidon", 2, args.len(), span)?;
        let left = self.compile_expr(args[0])?;
        let right = self.compile_expr(args[1])?;
        Ok(CircuitExpr::PoseidonHash {
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    pub(super) fn lower_poseidon_many(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        if args.len() < 2 {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "`poseidon_many` requires at least 2 arguments, got {}",
                    args.len()
                ),
                span: to_span(span),
            });
        }
        let compiled: Result<Vec<_>, _> = args.iter().map(|a| self.compile_expr(a)).collect();
        Ok(CircuitExpr::PoseidonMany(compiled?))
    }

    pub(super) fn lower_mux(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("mux", 3, args.len(), span)?;
        let cond = self.compile_expr(args[0])?;
        let if_true = self.compile_expr(args[1])?;
        let if_false = self.compile_expr(args[2])?;
        Ok(CircuitExpr::Mux {
            cond: Box::new(cond),
            if_true: Box::new(if_true),
            if_false: Box::new(if_false),
        })
    }

    pub(super) fn lower_range_check(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("range_check", 2, args.len(), span)?;
        let value = self.compile_expr(args[0])?;
        let bits_u64 = self.extract_const_u64(args[1], span)?;
        if bits_u64 > u32::MAX as u64 {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "range_check bit count {bits_u64} exceeds maximum ({})",
                    u32::MAX
                ),
                span: to_span(span),
            });
        }
        let bits = bits_u64 as u32;
        Ok(CircuitExpr::RangeCheck {
            value: Box::new(value),
            bits,
        })
    }

    pub(super) fn lower_merkle_verify(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("merkle_verify", 4, args.len(), span)?;
        let root = self.compile_expr(args[0])?;
        let leaf = self.compile_expr(args[1])?;
        let path = self.extract_array_ident(args[2], span)?;
        let indices = self.extract_array_ident(args[3], span)?;
        Ok(CircuitExpr::MerkleVerify {
            root: Box::new(root),
            leaf: Box::new(leaf),
            path,
            indices,
        })
    }

    pub(super) fn lower_len(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("len", 1, args.len(), span)?;
        self.compile_len_call(args[0], span)
    }

    pub(super) fn lower_assert_eq(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_assert_eq_arity(args.len(), span)?;
        let lhs = self.compile_expr(args[0])?;
        let rhs = self.compile_expr(args[1])?;
        let message = self.extract_assert_message(args.get(2), span)?;
        self.body.push(CircuitNode::AssertEq {
            lhs,
            rhs,
            message,
            span: Some(SpanRange::from(span)),
        });
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    pub(super) fn lower_assert(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_assert_arity(args.len(), span)?;
        let cond = self.compile_expr(args[0])?;
        let message = self.extract_assert_message(args.get(1), span)?;
        self.body.push(CircuitNode::Assert {
            expr: cond,
            message,
            span: Some(SpanRange::from(span)),
        });
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    pub(super) fn lower_int_div(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("int_div", 3, args.len(), span)?;
        let lhs = self.compile_expr(args[0])?;
        let rhs = self.compile_expr(args[1])?;
        let max_bits = self.extract_const_u64(args[2], span)? as u32;
        Ok(CircuitExpr::IntDiv {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            max_bits,
        })
    }

    pub(super) fn lower_int_mod(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("int_mod", 3, args.len(), span)?;
        let lhs = self.compile_expr(args[0])?;
        let rhs = self.compile_expr(args[1])?;
        let max_bits = self.extract_const_u64(args[2], span)? as u32;
        Ok(CircuitExpr::IntMod {
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            max_bits,
        })
    }
}
