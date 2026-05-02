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
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::helpers::to_span;
use super::ProveIrCompiler;
use crate::error::{CircomDispatchErrorKind, ProveIrError};
use crate::types::*;

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
