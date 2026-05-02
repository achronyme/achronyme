//! Annotation-driven and legacy named-call dispatch.
//!
//! [`try_annotation_dispatch`](super::super::ProveIrCompiler::try_annotation_dispatch)
//! is the shared entry consulted by both the bare-ident path
//! ([`compile_named_call`](super::super::ProveIrCompiler::compile_named_call))
//! and the `alias::name` `StaticAccess` arm of
//! [`compile_call`](super::super::ProveIrCompiler::compile_call). It
//! consults the resolver-annotated dispatch decision and routes to
//! either [`super::builtins`] (when annotated `Builtin`) or to
//! `compile_user_fn_call` (when annotated `UserFn`).
//!
//! [`compile_named_call`](super::super::ProveIrCompiler::compile_named_call)
//! tries the annotation path first and falls back to the legacy
//! name-based path (builtin registry then user-fn inlining) when no
//! annotation is available — this is the path bare-ident calls in
//! prove blocks travel through.

use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::super::{DispatchDecision, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
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
                // The dispatch map has already translated the SymbolId
                // to the correct fn_table key. If the key isn't in
                // `fn_table` we fall through to the name-based path —
                // happens when a symbol is known to the resolver but
                // not registered in this specific prove block's
                // OuterScope (e.g. prove-block-local imports that the
                // auto-build never saw).
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
                // Record a shadow hit so the trace mirrors the
                // bare-ident path in `compile_named_call`. The
                // annotation map may still hold an entry (Constant in
                // call position, etc.) that the dispatch helper
                // rejected; the hit trace still reflects what the
                // resolver saw at this call site.
                self.record_resolver_hit_for(callee_expr_id);
                Ok(None)
            }
        }
    }

    /// Compile a named function or builtin call.
    ///
    /// Tries annotation-driven dispatch via
    /// [`try_annotation_dispatch`] first, then falls back to the
    /// name-based path (builtin registry then user-fn inlining) if
    /// the annotation path declines.
    pub(super) fn compile_named_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Consult the annotation table for the current callee Ident.
        // `current_expr_id` was overridden with the Ident's ExprId by
        // `compile_call`'s Ident arm.
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

        // Name-based dispatch path. `lower_builtin` returning
        // `Ok(None)` means the name isn't a recognised builtin; fall
        // through to user-fn inlining.
        if let Some(expr) = self.lower_builtin(name, args, span)? {
            return Ok(expr);
        }
        self.compile_user_fn_call(name, args, span)
    }
}
