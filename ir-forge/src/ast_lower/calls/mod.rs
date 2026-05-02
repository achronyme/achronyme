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

use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::helpers::to_span;
use super::ProveIrCompiler;
use crate::error::{CircomDispatchErrorKind, ProveIrError};
use crate::types::*;

mod builtins;
mod circom_call;
mod circom_instantiate;
mod circom_resolve;
mod dispatch;
mod static_access;

impl<F: FieldBackend> ProveIrCompiler<F> {
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
            // The alias's exported functions live in `fn_table` under
            // the `{alias}::{func}` key (seeded by the module loader
            // at OuterScope build time), so this is a direct
            // qualified lookup — no runtime map dispatch, no hashmap
            // per call, fully constexpr. This is the canonical syntax
            // for module-qualified calls; the `alias.func()`
            // DotAccess shape is rejected with a migration diagnostic
            // in the arm below.
            Expr::StaticAccess {
                type_name,
                member,
                id: static_id,
                ..
            } => {
                // Try annotation-driven dispatch first so cross-module
                // calls via `alias::name` push the definer's module
                // onto the resolver stack via `compile_user_fn_call`.
                // That stack push is what makes the
                // `a → b::middle → helper` scenario resolve correctly:
                // `helper` is a bare identifier inside middle's
                // inlined body and must resolve against mod_B, not
                // against a's root module.
                //
                // `compile_expr` set `current_expr_id` to the Call's
                // id when it dispatched here; we temporarily override
                // it with the StaticAccess's own id so the annotation
                // lookup keys correctly, then restore it afterwards.
                let saved_expr_id = self.current_expr_id;
                self.current_expr_id = Some(*static_id);
                let annotation_result = self.try_annotation_dispatch(*static_id, args, span);
                self.current_expr_id = saved_expr_id;
                match annotation_result {
                    Ok(Some(expr)) => return Ok(expr),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }

                // Name-based fallback when no annotation matched.
                // `compile_user_fn_call` maintains the resolver module
                // stack via `resolver_module_by_key`, so the stack
                // discipline holds on this path as well.
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
            // import is not a valid call shape — the canonical form
            // is `alias::func(...)` (handled by the `StaticAccess`
            // arm above). Emit a migration error instead of silently
            // falling through so this shape is a hard compile-time
            // failure with a clean "did you mean" hint.
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
            // The resolver's `annotate_program` walker annotates the
            // callee Ident (not the enclosing Call), so we need the
            // Ident's own ExprId to consult the annotation table.
            // `compile_expr` has stashed the Call's id in
            // `self.current_expr_id` by now — re-override it with the
            // Ident's id so the shadow hook in `compile_named_call`
            // reads the correct annotation key. This is cheap and
            // localized; the alternative of threading the id through
            // `compile_named_call`'s signature would touch many test
            // call sites.
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

}
