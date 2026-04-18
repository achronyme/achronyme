//! State management on [`ProveIrCompiler`]: constructor, resolver-hit
//! tracking, annotation-driven dispatch resolution, Circom template
//! registration.
//!
//! These are the methods that build up or query the compiler's
//! internal state without compiling any AST node themselves. The
//! actual compilation pipeline lives in [`super::api`] (entry points),
//! [`super::stmts`] (statement walker), [`super::exprs`] (expression
//! walker), [`super::calls`] (call dispatch + builtins), and
//! [`super::methods`] (dot/method lookups).

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use achronyme_parser::ast::ExprId;
use memory::FieldBackend;

use super::{DispatchDecision, ProveIrCompiler};
use crate::prove_ir::circom_interop::CircomCallable;
use resolve::{AnnotationKey, CallableKind, ModuleId, SymbolId};

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(super) fn new() -> Self {
        Self {
            env: HashMap::new(),
            ssa_versions: HashMap::new(),
            captured_names: HashSet::new(),
            fn_table: HashMap::new(),
            call_stack: HashSet::new(),
            inline_counter: 0,
            body: Vec::new(),
            public_inputs: Vec::new(),
            witness_inputs: Vec::new(),
            source_dir: None,
            module_loader: crate::module_loader::ModuleLoader::new(),
            compiling_modules: HashSet::new(),
            circom_table: HashMap::new(),
            circom_call_counter: 0,
            resolver_table: None,
            resolver_resolved: None,
            resolver_root_module: None,
            resolver_module_stack: Vec::new(),
            fn_symbol_index: HashMap::new(),
            resolver_hits: Vec::new(),
            current_expr_id: None,
            _field: PhantomData,
        }
    }

    /// Borrow the shadow hit trace. Populated during compile by
    /// [`record_resolver_hit`]; consumers are integration tests
    /// asserting that the annotation-driven dispatch agrees with
    /// the legacy path.
    pub fn resolver_hits(&self) -> &[(AnnotationKey, SymbolId)] {
        &self.resolver_hits
    }

    /// Record a shadow resolver hit for the current expression, if
    /// any. No-op when the resolver state isn't installed, when
    /// `current_expr_id` is unset, or when the annotation table has
    /// no entry for this key. Phase 3E.1 only records — Phase 3E.2
    /// flips dispatch.
    pub(super) fn record_resolver_hit(&mut self) {
        let Some(expr_id) = self.current_expr_id else {
            return;
        };
        self.record_resolver_hit_for(expr_id);
    }

    /// Record a shadow resolver hit for an explicit [`ExprId`],
    /// bypassing `self.current_expr_id`. Needed for `Call` sites
    /// where the enclosing `compile_expr` set `current_expr_id` to
    /// the Call's id, but the annotation (from the resolver's
    /// `annotate_program`) is actually keyed by the **callee
    /// Ident's** id — ProveIR never recurses into the callee
    /// expression, so the callee's id must be threaded through
    /// explicitly.
    pub(super) fn record_resolver_hit_for(&mut self, expr_id: ExprId) {
        let Some(module_id) = self.current_resolver_module() else {
            return;
        };
        let Some(resolved) = self.resolver_resolved.as_ref() else {
            return;
        };
        let key = (module_id, expr_id);
        if let Some(&sid) = resolved.annotations.get(&key) {
            self.resolver_hits.push((key, sid));
        }
    }

    /// Which module the resolver-shadow hooks should consult.
    ///
    /// Phase 3E.1 used [`resolver_root_module`] directly — every
    /// annotation was keyed by `(root_module, expr_id)`. Phase 3E.3
    /// maintains a stack of active module ids so that when
    /// [`compile_user_fn_call`] inlines a user fn defined in another
    /// module, the annotations for [`Expr`]s inside the inlined body
    /// are keyed by the **definer's** module, not the caller's. This
    /// is the structural fix for gap 2.4 (transitive name
    /// resolution inside inlined prove-block helpers).
    ///
    /// When the stack is empty, falls back to the root module
    /// installed at OuterScope handoff.
    pub(super) fn current_resolver_module(&self) -> Option<ModuleId> {
        self.resolver_module_stack
            .last()
            .copied()
            .or(self.resolver_root_module)
    }

    /// Dispatch outcome the annotation table can drive.
    ///
    /// - `Builtin(name)` — the annotation (possibly through a
    ///   [`CallableKind::FnAlias`] chain) points at a registered
    ///   [`CallableKind::Builtin`]; the returned name is the
    ///   builtin's canonical name from the [`BuiltinRegistry`] and
    ///   should be passed straight to [`lower_builtin`].
    /// - `UserFn { qualified_name, module }` — a
    ///   [`CallableKind::UserFn`] entry; the caller should invoke
    ///   [`compile_user_fn_call`] with `qualified_name` and push
    ///   `module` onto the resolver module stack for the duration
    ///   of the inlined body so that nested annotations resolve
    ///   against the definer's scope.
    /// - `NoAnnotation` — resolver state absent, annotation map
    ///   empty for this key, or the [`CallableKind`] isn't
    ///   dispatchable from a call site (constants, circom
    ///   templates). Caller falls through to the legacy
    ///   lookup-by-name path.
    pub(super) fn resolve_dispatch_via_annotation(&mut self, callee_expr_id: ExprId) -> DispatchDecision {
        let (Some(table), Some(resolved), Some(module_id)) = (
            self.resolver_table.as_ref(),
            self.resolver_resolved.as_ref(),
            self.current_resolver_module(),
        ) else {
            return DispatchDecision::NoAnnotation;
        };
        let key = (module_id, callee_expr_id);
        let Some(&start) = resolved.annotations.get(&key) else {
            return DispatchDecision::NoAnnotation;
        };
        // Follow FnAlias chain. A malformed alias cycle is
        // impossible in a well-formed SymbolTable (Phase 3C caps
        // depth via FN_ALIAS_MAX_DEPTH), but we still swallow the
        // error and fall back to legacy dispatch — defensive,
        // since Phase 3E is an extension path, not a hard cutover.
        let Ok(sid) = table.resolve_alias(start) else {
            return DispatchDecision::NoAnnotation;
        };
        // Record the hit for the shadow trace — both the
        // annotation path AND the legacy path land here, so the
        // hit trace remains observable-equivalent to Phase 3E.1.
        self.resolver_hits.push((key, sid));
        match table.get(sid) {
            CallableKind::Builtin { entry_index } => table
                .builtin_registry()
                .get(*entry_index)
                .and_then(|entry| entry.prove_ir_lower)
                .map(|handle| DispatchDecision::Builtin { handle })
                .unwrap_or(DispatchDecision::NoAnnotation),
            CallableKind::UserFn { .. } => {
                // Translate SymbolId → fn_table key via the index
                // built during fn_table registration. Missing
                // entries fall through to legacy dispatch.
                match self.fn_symbol_index.get(&sid).cloned() {
                    Some(qualified_name) => DispatchDecision::UserFn { qualified_name },
                    None => DispatchDecision::NoAnnotation,
                }
            }
            // Constants, circom templates, and stray FnAlias (can't
            // happen after `resolve_alias` — it either terminates at
            // a non-alias or errors out) are not dispatchable from a
            // Call site in Phase 3E/3F. Fall back to legacy so the
            // compiler's existing error paths run.
            _ => DispatchDecision::NoAnnotation,
        }
    }

    /// Register a circom template under `key`.
    ///
    /// `key` is the name the dispatcher will look up at Call time —
    /// typically either the bare template name (selective import) or
    /// `"P::T"` (namespace import). `template_name` is the resolved
    /// name inside `library`. Duplicate keys are overwritten — the
    /// compiler-side import dispatcher is responsible for rejecting
    /// conflicts before reaching this point.
    ///
    /// Does NOT bump [`circom_call_counter`]; that counter tracks
    /// instantiation sites, not registrations.
    pub fn register_circom_template(
        &mut self,
        key: String,
        library: std::sync::Arc<dyn crate::prove_ir::circom_interop::CircomLibraryHandle>,
        template_name: String,
    ) {
        self.circom_table.insert(
            key,
            CircomCallable {
                library,
                template_name,
            },
        );
    }

    /// Allocate a unique mangling prefix for the next circom template
    /// instantiation (`circom_call_0`, `circom_call_1`, ...). Bumps
    /// [`circom_call_counter`] so subsequent calls get fresh prefixes.
    #[allow(dead_code)]
    pub(super) fn next_circom_call_prefix(&mut self) -> String {
        let prefix = format!("circom_call_{}", self.circom_call_counter);
        self.circom_call_counter += 1;
        prefix
    }

    /// Build the row-major list of multi-dimensional indices for a
    /// shape. For `dims = [2, 3]` returns
    /// `[[0,0], [0,1], [0,2], [1,0], [1,1], [1,2]]`. Used to map each
    /// element of an `Expr::Array` literal onto its expanded
    /// `name_i[_j…]` key in the circom signal-input map.
    pub(super) fn flatten_row_major_indices(dims: &[u64]) -> Vec<Vec<u64>> {
        let mut result = vec![Vec::new()];
        for &d in dims {
            let mut next = Vec::with_capacity(result.len() * d as usize);
            for prefix in &result {
                for i in 0..d {
                    let mut p = prefix.clone();
                    p.push(i);
                    next.push(p);
                }
            }
            result = next;
        }
        result
    }

    /// Look up a registered circom template by its dispatch key.
    #[allow(dead_code)]
    pub(super) fn lookup_circom_template(&self, key: &str) -> Option<&CircomCallable> {
        self.circom_table.get(key)
    }
}
