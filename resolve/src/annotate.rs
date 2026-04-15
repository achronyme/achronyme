//! Annotate pass — Movimiento 2 Phase 3C.
//!
//! The resolver pass proper: walks every [`ModuleNode`] in a
//! [`ModuleGraph`] and populates the [`SymbolTable`] with one
//! [`CallableKind::UserFn`] per top-level `fn` declaration and one
//! [`CallableKind::Constant`] per exported `let` declaration. The AST
//! itself is *not* annotated yet — that lands in Phase 3C.2 alongside
//! the per-expression walk that fills the `HashMap<ExprId, SymbolId>`
//! side table.
//!
//! ## What 3C.1 deliberately skips
//!
//! - Per-`Expr` annotation. No `HashMap<ExprId, SymbolId>` yet.
//! - `FnAlias` resolution (`let a = p::fn`).
//! - `ProveBlockUnsupportedShape` diagnostics.
//! - Availability inference (still defaults to
//!   [`Availability::Both`]). Phase 4 walks the call graph.
//! - Cross-module name collision checks. Phase 3E will catch them
//!   when the importer's namespace merges with imported names.
//!
//! This split exists so every sub-commit inside Phase 3 stays green
//! against the workspace test baseline. See
//! `.claude/plans/movimiento-2-unified-dispatch.md` §4 Phase 3 for
//! the full decomposition.

use std::collections::HashMap;

use achronyme_parser::ast::{Block, ElseBranch, Expr, ExprId, ForIterable, Span, Stmt};

use crate::error::{ResolveError, UnsupportedShape};
use crate::module_graph::{ImportEdgeKind, ModuleGraph, ModuleId, ModuleNode};
use crate::symbol::{Availability, CallableKind, ConstKind, SymbolId};
use crate::table::SymbolTable;

/// Walk every top-level statement in the given module and register
/// every `fn` and (exported) `let` into the table.
///
/// The symbol key is `"{alias}::{name}"` for non-root modules — where
/// `alias` is the *canonical* module identifier, not the per-importer
/// alias — and plain `"{name}"` for the root module. Phase 3E's
/// annotate pass maps per-importer aliases onto these canonical keys.
///
/// ## Key choice
///
/// Phase 3C.1 uses `"modN::{name}"` (where `N = module.as_u32()`) for
/// the non-root prefix because there is no single "canonical alias"
/// yet — a module may be imported under many different aliases across
/// the graph. The key just has to be unique per symbol; 3C.2 overlays
/// a per-importer resolution map on top without needing this key to
/// match anything user-facing.
pub fn register_module(
    table: &mut SymbolTable,
    graph: &ModuleGraph,
    module_id: ModuleId,
) -> Result<(), ResolveError> {
    let node = graph.get(module_id);
    let prefix = module_prefix(module_id, graph);

    // Track which names have been claimed inside this module so we
    // can return `DuplicateModuleSymbol` instead of letting
    // `SymbolTable::insert` panic.
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for (idx, stmt) in node.program.stmts.iter().enumerate() {
        match unwrap_exported(stmt) {
            Some(Stmt::FnDecl { name, .. }) => {
                if !seen.insert(name.as_str()) {
                    return Err(ResolveError::DuplicateModuleSymbol {
                        name: name.clone(),
                        module: module_id.as_u32(),
                    });
                }
                let qualified = qualify(&prefix, name);
                table.insert(
                    qualified.clone(),
                    CallableKind::UserFn {
                        qualified_name: qualified,
                        module: module_id,
                        stmt_index: idx as u32,
                        // Phase 4 availability inference fills this in;
                        // Phase 3C defaults to Both so both compilers
                        // see every fn as a candidate.
                        availability: Availability::Both,
                    },
                );
            }
            Some(Stmt::LetDecl { name, .. }) => {
                if !seen.insert(name.as_str()) {
                    return Err(ResolveError::DuplicateModuleSymbol {
                        name: name.clone(),
                        module: module_id.as_u32(),
                    });
                }
                // Only *exported* lets become module-level
                // `Constant` symbols. Private lets are local to the
                // module body and don't need a SymbolTable entry
                // (Phase 3C.2's per-expression walker handles them
                // via its lexical scope).
                if !is_exported(stmt) {
                    continue;
                }
                let qualified = qualify(&prefix, name);
                table.insert(
                    qualified.clone(),
                    CallableKind::Constant {
                        qualified_name: qualified,
                        // Phase 3C.1 can't infer the const kind without
                        // evaluating the RHS; default to Field and
                        // leave a TODO for Phase 6 when the constant
                        // store lands.
                        const_kind: ConstKind::Field,
                        value_handle: 0,
                    },
                );
            }
            _ => {}
        }
    }

    Ok(())
}

/// Convenience wrapper: register every module in the graph in
/// reverse-topological order (the order [`ModuleGraph::iter_ids`]
/// yields). Dependencies always register before dependents, so a
/// Phase 3C.2 annotate pass can already see its imports in the table
/// by the time it walks its own module.
pub fn register_all(table: &mut SymbolTable, graph: &ModuleGraph) -> Result<(), ResolveError> {
    for id in graph.iter_ids() {
        register_module(table, graph, id)?;
    }
    Ok(())
}

/// Install every builtin in the table's [`BuiltinRegistry`] as a
/// [`CallableKind::Builtin`] entry under its bare name.
///
/// Must run **before** [`annotate_program`] if the walker is expected to
/// resolve builtin call sites (e.g. `poseidon(a, b)`). Callers that only
/// care about user-module resolution can skip this step — [`annotate_program`]
/// simply won't emit annotations for builtin names in that case.
///
/// ## Name-collision policy (Phase 3C.2)
///
/// Builtins go in under their bare name. If a root module also declares
/// `fn poseidon() {...}`, the later [`register_module`] call will panic
/// on duplicate insert. Phase 3C.3+ will refine the shadowing story
/// (either reject user shadowing with a diagnostic or let it win).
/// Until then, the production call order is:
///
/// 1. `register_builtins(&mut table)` — populates bare builtin names.
/// 2. `register_all(&mut table, &graph)` — populates module symbols.
///
/// so any collision surfaces as a clear table panic instead of a silent
/// dispatch mismatch.
pub fn register_builtins(table: &mut SymbolTable) {
    let n = table.builtin_registry().len();
    for i in 0..n {
        // The registry owns `&'static str` names — cheap to clone into
        // the table's `String` key.
        let name = table
            .builtin_registry()
            .get(i)
            .expect("index in 0..len must be valid")
            .name
            .to_string();
        table.insert(name, CallableKind::Builtin { entry_index: i });
    }
}

/// Composite key for the annotation map: `(module, expr_id)`.
///
/// [`ExprId`]s are dense *within one parsed [`Program`]*, not across
/// modules — each call to the parser resets its counter to 1. Using
/// the bare `ExprId` as a map key would therefore collide across
/// modules. Phase 3C.2 prefixes with the owning [`ModuleId`] instead,
/// which keeps the resolver pass cheap (no parser-level id remap) and
/// gives Phase 3D/3E consumers an unambiguous handle: they know which
/// module they are compiling, so supplying the pair is free.
pub type AnnotationKey = (ModuleId, ExprId);

/// Output of the resolver pass: the `(ModuleId, ExprId) → SymbolId`
/// annotation map plus any resolve-time diagnostics accumulated along
/// the way.
///
/// The `annotations` table mirrors the plan doc's `ResolvedProgram`
/// sketch: each resolvable leaf in every module gets an entry.
/// Consumers that only care about resolution (Phase 3D/3E compilers)
/// read `annotations`; diagnostic pipelines read `diagnostics` and
/// fold each [`ResolveError`] into the session's error report.
#[derive(Debug, Default)]
pub struct ResolvedProgram {
    /// `(module, expr_id) → symbol` for every successfully resolved
    /// [`Expr::Ident`], [`Expr::StaticAccess`], and [`Expr::DotAccess`]
    /// node in every module. Unresolved nodes are silently omitted —
    /// the Phase 3D/3E consumers fall back to their legacy lookup for
    /// anything not in the map.
    pub annotations: HashMap<AnnotationKey, SymbolId>,
    /// Resolve-time diagnostics accumulated by the walker — currently
    /// only [`ResolveError::ProveBlockUnsupportedShape`] variants
    /// emitted inside `prove {}` / `circuit {}` scopes. Empty for
    /// well-formed programs.
    pub diagnostics: Vec<ResolveError>,
}

/// Walk every [`Expr`] in every module and emit an annotation map from
/// `(ModuleId, ExprId)` to [`SymbolId`] for each resolvable reference.
///
/// This is the resolver pass proper — Phase 3C.2. For every
/// [`Expr::Ident`], [`Expr::StaticAccess`], and [`Expr::DotAccess`] the
/// walker tries to resolve the name against:
///
/// 1. the current lexical scope (params + let/mut bindings inside the
///    enclosing function/block) — a match **skips** annotation so
///    Phase 3D/3E's compilers keep using their local-variable storage.
/// 2. the current module's own symbols in the [`SymbolTable`] (private
///    + exported fns registered by [`register_module`]).
/// 3. selective imports (`import { foo } from "lib"`) — the importer's
///    alias is empty, the name must appear in
///    [`ImportEdgeKind::Selective::names`].
/// 4. namespace imports (`import "lib" as l`) — only reached for
///    [`Expr::StaticAccess`] and [`Expr::DotAccess`], where the leading
///    `l` is the import alias and the trailing `::foo` / `.foo` is the
///    exported name.
/// 5. builtins — caught by step 2's bare-name lookup if
///    [`register_builtins`] ran before this function.
///
/// Unresolvable names are **silently omitted** from the returned map.
/// Phase 3D/3E consumers fall back to their legacy lookup for any
/// `ExprId` not present in the map, so the resolver can ship
/// incrementally without breaking existing behaviour.
///
/// ## What 3C.2 deliberately skips
///
/// - `Expr::Call`'s own annotation. The callee is already walked and
///   annotated; the `Call` node itself doesn't need a separate entry
///   (callers follow the callee's id).
/// - [`FnAlias`](crate::symbol::CallableKind::FnAlias) creation. Phase
///   3C.3 handles `let a = p::fn` const-folding.
/// - [`ProveBlockUnsupportedShape`] diagnostics. Phase 3C.3.
/// - Static members (`Int::MAX`, `Field::ZERO`). The
///   [`statics::lookup`](crate::statics::lookup) table is empty until
///   Phase 6; for now we just fall through to the namespace-import
///   check and the compilers keep their legacy static resolution.
/// - `ConstKind` refinement. Phase 3C.1 parks every exported let as
///   `ConstKind::Field`; 3C.2 does not touch that.
/// - Module graph audit. The caller should run [`SymbolTable::audit`]
///   separately after registration + annotation finish.
///
/// ## Gap 2.4 and the definer's scope
///
/// The walker annotates each expression **against the module that
/// declares it**, not the module that eventually inlines it at lowering
/// time. That is the whole point of doing this at parse time: a
/// reference to `hash_node` inside `tree::merkle_step` resolves to
/// `hash::hash_node`'s `SymbolId` now, so by the time the ProveIR
/// compiler inlines `merkle_step` into a `prove {}` block in `main.ach`,
/// there are no bare names left for it to re-resolve against the wrong
/// scope. Phase 3E wires the consumer side; 3C.2 just plants the
/// annotations.
pub fn annotate_program(graph: &ModuleGraph, table: &SymbolTable) -> ResolvedProgram {
    let mut out = ResolvedProgram::default();
    for module in graph.iter() {
        let prefix = module_prefix(module.id, graph);
        let mut ctx = AnnotateCtx {
            graph,
            table,
            module,
            prefix,
            annotations: &mut out.annotations,
            diagnostics: &mut out.diagnostics,
            scope: Vec::new(),
            in_prove_depth: 0,
        };
        for stmt in &module.program.stmts {
            walk_stmt(&mut ctx, stmt);
        }
    }
    out
}

// ----------------------------------------------------------------------
// Annotate walker internals
// ----------------------------------------------------------------------

/// What flavour of local binding a name represents. Enables Phase
/// 3C.3's FnAlias + prove-block shape diagnostics — the walker stores
/// extra metadata alongside the shadow set so later call sites can
/// re-classify references without re-walking the RHS.
#[derive(Clone, Debug)]
enum LocalKind {
    /// Plain value binding: fn params, `for` loop vars, ordinary
    /// `let x = 42`. Shadows module symbols; nothing special.
    Plain,
    /// `let a = p::fn` where the RHS const-resolved at annotation
    /// time to a single fn-valued [`SymbolId`]. Subsequent references
    /// to `a` annotate directly to the target — Phase 3D/3E dispatch
    /// through the target without ever creating a
    /// [`CallableKind::FnAlias`] entry in the table (the plan-doc
    /// version lives in the table, but the annotation-map approach
    /// gives both backends the same observable behaviour with no
    /// extra mutation cost).
    Alias(SymbolId),
    /// `let a = if c { f } else { g }` where both branches const-
    /// resolve to fn symbols — a dynamic fn value. Calling `a()`
    /// inside a prove block emits
    /// [`UnsupportedShape::DynamicFnValue`].
    DynamicFn,
    /// `let m = { k: v, ... }` — a Map literal. Field/index access
    /// on `m` inside a prove block emits
    /// [`UnsupportedShape::RuntimeMapAccess`].
    RuntimeMap,
}

/// Per-module walker state. Holds read-only refs to the graph/table/
/// module plus `&mut` handles to the annotation map and diagnostic
/// vector, the lexical scope stack, and the prove-block depth
/// counter.
struct AnnotateCtx<'a> {
    graph: &'a ModuleGraph,
    table: &'a SymbolTable,
    module: &'a ModuleNode,
    /// Precomputed `"modN::"` prefix (or `""` for the root module) used
    /// to look up the current module's own symbols in [`SymbolTable`].
    prefix: String,
    annotations: &'a mut HashMap<AnnotationKey, SymbolId>,
    /// Accumulated diagnostics. Phase 3C.3 only pushes
    /// [`ResolveError::ProveBlockUnsupportedShape`] variants; later
    /// phases may add more.
    diagnostics: &'a mut Vec<ResolveError>,
    /// Stack of lexical scopes. Each entry binds a name to its
    /// [`LocalKind`]; inner layers shadow outer layers. At module top
    /// level the stack is empty — top-level `let`/`mut` bindings are
    /// not tracked because exported ones live in the `SymbolTable`
    /// and private ones have no annotation-time consumer yet.
    scope: Vec<HashMap<String, LocalKind>>,
    /// Depth counter of nested `prove {}` / `circuit {}` blocks. Zero
    /// at module top level; incremented on entry, decremented on
    /// exit. `> 0` means every shape check in the walker should run.
    in_prove_depth: u32,
}

impl<'a> AnnotateCtx<'a> {
    fn push_scope(&mut self) {
        self.scope.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scope.pop();
    }

    /// Bind a local name to `kind` inside the innermost scope. A
    /// no-op at the module top level (where `scope` is empty) — see
    /// the field docstring above for the rationale.
    fn add_local(&mut self, name: &str, kind: LocalKind) {
        if let Some(top) = self.scope.last_mut() {
            top.insert(name.to_string(), kind);
        }
    }

    /// Walk the scope stack from innermost to outermost and return
    /// the first matching binding's kind, if any.
    fn lookup_local(&self, name: &str) -> Option<&LocalKind> {
        for layer in self.scope.iter().rev() {
            if let Some(kind) = layer.get(name) {
                return Some(kind);
            }
        }
        None
    }

    fn is_local(&self, name: &str) -> bool {
        self.lookup_local(name).is_some()
    }

    fn push_diagnostic(&mut self, span: Span, shape: UnsupportedShape, reason: &'static str) {
        self.diagnostics
            .push(ResolveError::ProveBlockUnsupportedShape {
                span,
                shape,
                reason,
            });
    }
}

fn walk_stmt(ctx: &mut AnnotateCtx, stmt: &Stmt) {
    match stmt {
        Stmt::LetDecl { name, value, .. } | Stmt::MutDecl { name, value, .. } => {
            walk_expr(ctx, value);
            // Classify the RHS for FnAlias + shape-diagnostic tracking.
            let kind = classify_let_rhs(ctx, value);
            ctx.add_local(name, kind);
        }
        Stmt::Assignment { target, value, .. } => {
            walk_expr(ctx, target);
            walk_expr(ctx, value);
        }
        Stmt::FnDecl { params, body, .. } => {
            // Params and the body share one scope in Achronyme — a
            // top-level `let` inside the body shadows a param.
            ctx.push_scope();
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.pop_scope();
        }
        Stmt::CircuitDecl { params, body, .. } => {
            ctx.push_scope();
            ctx.in_prove_depth += 1;
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.in_prove_depth -= 1;
            ctx.pop_scope();
        }
        Stmt::Print { value, .. } => walk_expr(ctx, value),
        Stmt::Return { value: Some(v), .. } => walk_expr(ctx, v),
        Stmt::Return { value: None, .. } => {}
        Stmt::Expr(e) => walk_expr(ctx, e),
        Stmt::Export { inner, .. } => walk_stmt(ctx, inner),
        // PublicDecl, WitnessDecl, Import, SelectiveImport, ExportList,
        // ImportCircuit, Break, Continue, Error — no embedded exprs to
        // walk.
        _ => {}
    }
}

/// Walk the statements of a [`Block`] **without** managing its scope.
/// Used when the caller has already pushed a scope (e.g. the fn-body
/// walker that wants params and body in the same scope).
fn walk_block_stmts(ctx: &mut AnnotateCtx, block: &Block) {
    for stmt in &block.stmts {
        walk_stmt(ctx, stmt);
    }
}

/// Walk a [`Block`] as an independent lexical scope. Pushes, walks,
/// pops.
fn walk_block_scoped(ctx: &mut AnnotateCtx, block: &Block) {
    ctx.push_scope();
    walk_block_stmts(ctx, block);
    ctx.pop_scope();
}

fn walk_expr(ctx: &mut AnnotateCtx, expr: &Expr) {
    // Step 1: try to resolve the expression itself.
    let module_id = ctx.module.id;
    match expr {
        Expr::Ident { id, name, .. } => {
            if let Some(sid) = resolve_ident(ctx, name) {
                ctx.annotations.insert((module_id, *id), sid);
            }
        }
        Expr::StaticAccess {
            id,
            type_name,
            member,
            ..
        } => {
            if let Some(sid) = resolve_static_access(ctx, type_name, member) {
                ctx.annotations.insert((module_id, *id), sid);
            }
        }
        Expr::DotAccess {
            id, object, field, ..
        } => {
            if let Some(sid) = resolve_dot_access(ctx, object, field) {
                ctx.annotations.insert((module_id, *id), sid);
            }
        }
        _ => {}
    }

    // Step 2: recurse into children regardless of whether we resolved
    // step 1. Annotating the parent does NOT short-circuit the walk —
    // a `DotAccess { object: Ident(alias), .. }` still has its inner
    // `Ident` walked, which is harmless because the alias won't resolve
    // as an ident (no module symbol shares its name by construction).
    match expr {
        Expr::Number { .. }
        | Expr::FieldLit { .. }
        | Expr::BigIntLit { .. }
        | Expr::Bool { .. }
        | Expr::StringLit { .. }
        | Expr::Nil { .. }
        | Expr::Ident { .. }
        | Expr::StaticAccess { .. }
        | Expr::Error { .. } => {}
        Expr::BinOp { lhs, rhs, .. } => {
            walk_expr(ctx, lhs);
            walk_expr(ctx, rhs);
        }
        Expr::UnaryOp { operand, .. } => walk_expr(ctx, operand),
        Expr::Call {
            callee, args, span, ..
        } => walk_call(ctx, callee, args, span),
        Expr::Index {
            object,
            index,
            span,
            ..
        } => {
            // Inside a prove block, indexing into a local Map literal
            // is `RuntimeMapAccess`. Plain arrays (witness arrays,
            // fixed-size `[Field; N]` style bindings) don't bind as
            // `LocalKind::RuntimeMap`, so they pass through.
            if ctx.in_prove_depth > 0 {
                if let Expr::Ident { name, .. } = object.as_ref() {
                    if matches!(ctx.lookup_local(name), Some(LocalKind::RuntimeMap)) {
                        ctx.push_diagnostic(
                            span.clone(),
                            UnsupportedShape::RuntimeMapAccess,
                            "indexing a runtime map inside a prove block",
                        );
                    }
                }
            }
            walk_expr(ctx, object);
            walk_expr(ctx, index);
        }
        Expr::DotAccess {
            object,
            field: _,
            span,
            ..
        } => {
            // Standalone DotAccess (not the callee of a Call — the
            // Call arm handles that path). Inside a prove block,
            // `m.field` where `m` is a local Map literal is a
            // `RuntimeMapAccess`.
            if ctx.in_prove_depth > 0 {
                if let Expr::Ident { name, .. } = object.as_ref() {
                    if matches!(ctx.lookup_local(name), Some(LocalKind::RuntimeMap)) {
                        ctx.push_diagnostic(
                            span.clone(),
                            UnsupportedShape::RuntimeMapAccess,
                            "field access on a runtime map inside a prove block",
                        );
                    }
                }
            }
            walk_expr(ctx, object);
        }
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            walk_expr(ctx, condition);
            walk_block_scoped(ctx, then_block);
            match else_branch {
                Some(ElseBranch::Block(b)) => walk_block_scoped(ctx, b),
                Some(ElseBranch::If(e)) => walk_expr(ctx, e),
                None => {}
            }
        }
        Expr::For {
            var,
            iterable,
            body,
            ..
        } => {
            match iterable {
                ForIterable::Range { .. } => {}
                ForIterable::ExprRange { end, .. } => walk_expr(ctx, end),
                ForIterable::Expr(e) => walk_expr(ctx, e),
            }
            ctx.push_scope();
            ctx.add_local(var, LocalKind::Plain);
            walk_block_stmts(ctx, body);
            ctx.pop_scope();
        }
        Expr::While {
            condition, body, ..
        } => {
            walk_expr(ctx, condition);
            walk_block_scoped(ctx, body);
        }
        Expr::Forever { body, .. } => walk_block_scoped(ctx, body),
        Expr::Block { block, .. } => walk_block_scoped(ctx, block),
        Expr::FnExpr { params, body, .. } => {
            ctx.push_scope();
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.pop_scope();
        }
        Expr::Prove { params, body, .. } => {
            ctx.push_scope();
            ctx.in_prove_depth += 1;
            for p in params {
                ctx.add_local(&p.name, LocalKind::Plain);
            }
            walk_block_stmts(ctx, body);
            ctx.in_prove_depth -= 1;
            ctx.pop_scope();
        }
        Expr::Array { elements, .. } => {
            for e in elements {
                walk_expr(ctx, e);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, v) in pairs {
                walk_expr(ctx, v);
            }
        }
    }
}

/// Walk a `Call { callee, args }` with prove-block shape checks.
/// This is broken out of [`walk_expr`] because the callee is inspected
/// for [`UnsupportedShape::RuntimeMethodChain`] + [`UnsupportedShape::DynamicFnValue`]
/// *before* being walked, and each argument is inspected for
/// [`UnsupportedShape::NonStaticFnArg`].
fn walk_call(
    ctx: &mut AnnotateCtx,
    callee: &Expr,
    args: &[achronyme_parser::ast::CallArg],
    call_span: &Span,
) {
    if ctx.in_prove_depth > 0 {
        // DynamicFnValue: calling a local that was bound to an
        // if/else of fn references.
        if let Expr::Ident { name, span, .. } = callee {
            if matches!(ctx.lookup_local(name), Some(LocalKind::DynamicFn)) {
                ctx.push_diagnostic(
                    span.clone(),
                    UnsupportedShape::DynamicFnValue,
                    "calling a local bound to a dynamic fn value inside a prove block",
                );
            }
        }
        // RuntimeMethodChain: `expr.method()` where `expr` is not a
        // namespace import alias. Namespace calls via `l.foo()` use
        // the `Expr::DotAccess` path and resolve to a module symbol;
        // non-namespace DotAccess callees are runtime method dispatch
        // which prove blocks can't model.
        if let Expr::DotAccess { object, span, .. } = callee {
            if !is_namespace_alias_ident(ctx, object) {
                ctx.push_diagnostic(
                    span.clone(),
                    UnsupportedShape::RuntimeMethodChain,
                    "method call on a value that is not a namespace alias",
                );
            }
        }
        // NonStaticFnArg: any positional argument that is itself an
        // if/else of fn references.
        for a in args {
            if let Expr::If {
                then_block,
                else_branch,
                span,
                ..
            } = &a.value
            {
                if is_dynamic_fn_if(ctx, then_block, else_branch.as_ref()) {
                    ctx.push_diagnostic(
                        span.clone(),
                        UnsupportedShape::NonStaticFnArg,
                        "passing a dynamic fn value as an argument inside a prove block",
                    );
                }
            }
        }
        let _ = call_span; // reserved for future whole-call diagnostics
    }

    walk_expr(ctx, callee);
    for a in args {
        walk_expr(ctx, &a.value);
    }
}

// ----------------------------------------------------------------------
// Resolution helpers
// ----------------------------------------------------------------------

/// Resolve a bare identifier against the walker's lexical stack and the
/// symbol table. Returns `None` on any of:
///
/// - name is a plain local / dynamic-fn local / runtime-map local
///   (shadowing wins; those categories are handled by their own
///   diagnostic paths, not by annotation)
/// - name is not in the current module, not selectively imported, and
///   not a bare builtin
///
/// Returns `Some(target)` when `name` is a [`LocalKind::Alias`] — the
/// resolver flattens FnAlias chains at annotation time, so each
/// reference to `a` after `let a = p::fn` is indistinguishable from a
/// direct reference to `p::fn`.
fn resolve_ident(ctx: &AnnotateCtx, name: &str) -> Option<SymbolId> {
    if let Some(kind) = ctx.lookup_local(name) {
        return match kind {
            LocalKind::Alias(sid) => Some(*sid),
            LocalKind::Plain | LocalKind::DynamicFn | LocalKind::RuntimeMap => None,
        };
    }

    // 1. Same-module symbol (private fn, exported fn, exported Constant).
    let qualified = qualify(&ctx.prefix, name);
    if let Some(id) = ctx.table.lookup(&qualified) {
        return Some(id);
    }

    // 2. Selective import (`import { foo } from "lib"`).
    for edge in &ctx.module.imports {
        if let ImportEdgeKind::Selective { names } = &edge.kind {
            if names.iter().any(|n| n == name) {
                let target_prefix = module_prefix(edge.target, ctx.graph);
                let target_qualified = qualify(&target_prefix, name);
                if let Some(id) = ctx.table.lookup(&target_qualified) {
                    return Some(id);
                }
            }
        }
    }

    // 3. Bare builtin (requires `register_builtins` to have run).
    //    In the root module this also catches bare lookups that aren't
    //    in the current module's private set — step 1 already tried
    //    the empty-prefix variant, so this is only reached for non-root
    //    modules.
    if !ctx.prefix.is_empty() {
        if let Some(id) = ctx.table.lookup(name) {
            // Only treat as a match if it's actually a builtin — a
            // bare-name hit against some unrelated root-module fn
            // would be a namespace violation.
            if matches!(ctx.table.get(id), CallableKind::Builtin { .. }) {
                return Some(id);
            }
        }
    }

    None
}

/// Resolve `Type::member` syntax. Three possible outcomes:
///
/// 1. The `Type` is a language-level static (`Int`, `Field`, …). The
///    stub [`statics::lookup`](crate::statics::lookup) table is empty
///    in Phase 3C.2, so this branch always falls through — the
///    compilers keep their legacy static matches alive.
/// 2. The `Type` is a namespace import alias. Resolve to the exported
///    name inside the target module.
/// 3. Neither — leave unresolved.
fn resolve_static_access(ctx: &AnnotateCtx, type_name: &str, member: &str) -> Option<SymbolId> {
    // Language-level statics take precedence but are a stub for now.
    // We explicitly check so a future populated STATIC_MEMBERS table
    // beats namespace-alias collisions.
    if crate::statics::lookup(type_name, member).is_some() {
        // Statics have no SymbolId — they live in a separate table.
        // Signal "handled, but not via SymbolId" by returning None; the
        // compiler's legacy static lookup still runs unchanged.
        return None;
    }

    for edge in &ctx.module.imports {
        if matches!(edge.kind, ImportEdgeKind::Namespace) && edge.alias == type_name {
            let target_prefix = module_prefix(edge.target, ctx.graph);
            let qualified = qualify(&target_prefix, member);
            if let Some(id) = ctx.table.lookup(&qualified) {
                return Some(id);
            }
        }
    }
    None
}

/// Resolve `object.field` where `object` is an identifier that matches a
/// namespace import alias. This is the second parser surface for
/// qualified module access — ProveIR already accepts both `l::foo` and
/// `l.foo` as synonyms, so the resolver treats them uniformly.
fn resolve_dot_access(ctx: &AnnotateCtx, object: &Expr, field: &str) -> Option<SymbolId> {
    let Expr::Ident { name, .. } = object else {
        return None;
    };
    if ctx.is_local(name) {
        return None;
    }
    for edge in &ctx.module.imports {
        if matches!(edge.kind, ImportEdgeKind::Namespace) && &edge.alias == name {
            let target_prefix = module_prefix(edge.target, ctx.graph);
            let qualified = qualify(&target_prefix, field);
            if let Some(id) = ctx.table.lookup(&qualified) {
                return Some(id);
            }
        }
    }
    None
}

/// Try to const-resolve a `let` RHS to a single fn-valued [`SymbolId`].
/// Only the three leaf shapes (bare ident, `Type::member`, `alias.member`)
/// are considered — matching a more elaborate expression dynamically
/// is the user's job (or the VM's). Returns `Some(id)` when:
///
/// - the expression is [`Expr::Ident`] / [`Expr::StaticAccess`] /
///   [`Expr::DotAccess`] and resolves against the current context;
/// - AND the resolved symbol's kind is [`CallableKind::UserFn`],
///   [`CallableKind::Builtin`], or [`CallableKind::FnAlias`]
///   (constants and circom templates aren't first-class callables in
///   the 3C.3 alias sense).
fn const_resolve_fn(ctx: &AnnotateCtx, expr: &Expr) -> Option<SymbolId> {
    let sid = match expr {
        Expr::Ident { name, .. } => resolve_ident(ctx, name)?,
        Expr::StaticAccess {
            type_name, member, ..
        } => resolve_static_access(ctx, type_name, member)?,
        Expr::DotAccess { object, field, .. } => resolve_dot_access(ctx, object, field)?,
        _ => return None,
    };
    match ctx.table.get(sid) {
        CallableKind::UserFn { .. }
        | CallableKind::Builtin { .. }
        | CallableKind::FnAlias { .. } => Some(sid),
        _ => None,
    }
}

/// Decide what [`LocalKind`] a `let x = <rhs>` binding should produce.
/// The classification drives Phase 3C.3's FnAlias + shape diagnostics:
///
/// - a const-resolved fn reference → [`LocalKind::Alias`]
/// - an `if` whose both branches const-resolve to fn references →
///   [`LocalKind::DynamicFn`]
/// - a map literal → [`LocalKind::RuntimeMap`]
/// - anything else → [`LocalKind::Plain`]
fn classify_let_rhs(ctx: &AnnotateCtx, rhs: &Expr) -> LocalKind {
    if let Some(target) = const_resolve_fn(ctx, rhs) {
        return LocalKind::Alias(target);
    }
    if let Expr::If {
        then_block,
        else_branch,
        ..
    } = rhs
    {
        if is_dynamic_fn_if(ctx, then_block, else_branch.as_ref()) {
            return LocalKind::DynamicFn;
        }
    }
    if matches!(rhs, Expr::Map { .. }) {
        return LocalKind::RuntimeMap;
    }
    LocalKind::Plain
}

/// Return `true` if both branches of an `if/else` const-resolve to
/// fn-valued symbols — the structural pattern that makes a binding a
/// [`LocalKind::DynamicFn`] and that triggers
/// [`UnsupportedShape::DynamicFnValue`] / [`UnsupportedShape::NonStaticFnArg`]
/// inside a prove block. The tail of each branch is checked: the
/// last statement of a block must be a `Stmt::Expr` that
/// const-resolves, or the else branch must chain to another `if` that
/// itself is a dynamic-fn `if`.
fn is_dynamic_fn_if(
    ctx: &AnnotateCtx,
    then_block: &Block,
    else_branch: Option<&ElseBranch>,
) -> bool {
    if block_tail_fn(ctx, then_block).is_none() {
        return false;
    }
    match else_branch {
        Some(ElseBranch::Block(b)) => block_tail_fn(ctx, b).is_some(),
        Some(ElseBranch::If(e)) => {
            // Nested else-if: require the whole chain to be fn-valued.
            if let Expr::If {
                then_block: inner_then,
                else_branch: inner_else,
                ..
            } = e.as_ref()
            {
                is_dynamic_fn_if(ctx, inner_then, inner_else.as_ref())
            } else {
                false
            }
        }
        None => false,
    }
}

/// Extract the fn-valued symbol out of a block's tail statement, if any.
fn block_tail_fn(ctx: &AnnotateCtx, block: &Block) -> Option<SymbolId> {
    match block.stmts.last()? {
        Stmt::Expr(e) => const_resolve_fn(ctx, e),
        _ => None,
    }
}

/// Return `true` if the given expression is an [`Expr::Ident`] whose
/// name matches a namespace import alias on the current module. Used
/// by the prove-block method-chain diagnostic to distinguish
/// `l.foo()` (valid namespace call) from `value.method()` (runtime
/// method dispatch).
fn is_namespace_alias_ident(ctx: &AnnotateCtx, expr: &Expr) -> bool {
    let Expr::Ident { name, .. } = expr else {
        return false;
    };
    if ctx.is_local(name) {
        return false;
    }
    ctx.module
        .imports
        .iter()
        .any(|e| matches!(e.kind, ImportEdgeKind::Namespace) && &e.alias == name)
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// Build the qualified-name prefix for a module: `""` for the root,
/// `"modN::"` otherwise. See [`register_module`]'s "Key choice"
/// section for why we use the module id number instead of a user
/// alias.
fn module_prefix(id: ModuleId, graph: &ModuleGraph) -> String {
    if id == graph.root() {
        String::new()
    } else {
        format!("mod{}::", id.as_u32())
    }
}

fn qualify(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}{name}")
    }
}

/// Unwrap `Stmt::Export { inner, .. }` to return the inner statement.
/// Non-exported statements pass through unchanged.
fn unwrap_exported(stmt: &Stmt) -> Option<&Stmt> {
    match stmt {
        Stmt::Export { inner, .. } => Some(inner),
        other => Some(other),
    }
}

fn is_exported(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Export { .. })
}

// ==========================================================================
// Unit tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_graph::{LoadedModule, ModuleGraph, ModuleSource};
    use achronyme_parser::parse_program;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    /// In-memory `ModuleSource` mirroring the one in `module_graph::tests`.
    /// Duplicated here to keep the two test modules independent; a
    /// shared helper would cost more than the 40 lines of copy.
    #[derive(Default)]
    struct MockSource {
        files: HashMap<String, String>,
    }

    impl MockSource {
        fn add(&mut self, name: &str, source: &str) {
            self.files.insert(name.to_string(), source.to_string());
        }
    }

    impl ModuleSource for MockSource {
        fn canonicalize(
            &mut self,
            _importer: Option<&Path>,
            relative: &str,
        ) -> Result<PathBuf, String> {
            if self.files.contains_key(relative) {
                Ok(PathBuf::from(relative))
            } else {
                Err(format!("no such module `{relative}`"))
            }
        }

        fn load(&mut self, canonical: &Path) -> Result<LoadedModule, String> {
            let key = canonical.to_string_lossy().into_owned();
            let source = self
                .files
                .get(&key)
                .ok_or_else(|| format!("missing source for `{key}`"))?;
            let (program, errors) = parse_program(source);
            if !errors.is_empty() {
                return Err(format!("parse errors in `{key}`: {}", errors[0].message));
            }
            // Mirror the ir::ModuleLoader contract: walk top-level
            // exports and flatten to a name list.
            let exported_names = program
                .stmts
                .iter()
                .filter_map(|s| match s {
                    Stmt::Export { inner, .. } => match inner.as_ref() {
                        Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => {
                            Some(name.clone())
                        }
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            Ok(LoadedModule {
                program,
                exported_names,
            })
        }
    }

    #[test]
    fn single_module_registers_fn_and_let() {
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn add(a, b) { a + b }\n\
             export let PI = 3\n\
             fn mul(a, b) { a * b }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        register_all(&mut table, &graph).expect("register");

        // Root module → unqualified keys.
        let add_id = table.lookup("add").expect("add registered");
        let mul_id = table.lookup("mul").expect("mul registered");
        let pi_id = table.lookup("PI").expect("PI registered");

        match table.get(add_id) {
            CallableKind::UserFn {
                module, stmt_index, ..
            } => {
                assert_eq!(*module, graph.root());
                assert_eq!(*stmt_index, 0);
            }
            other => panic!("expected UserFn, got {other:?}"),
        }
        match table.get(mul_id) {
            CallableKind::UserFn { stmt_index, .. } => assert_eq!(*stmt_index, 2),
            other => panic!("expected UserFn, got {other:?}"),
        }
        assert!(matches!(
            table.get(pi_id),
            CallableKind::Constant {
                const_kind: ConstKind::Field,
                ..
            }
        ));
    }

    #[test]
    fn private_let_is_not_registered() {
        let mut src = MockSource::default();
        src.add("main", "let private_const = 42\nfn f() { private_const }");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        register_all(&mut table, &graph).expect("register");

        assert!(table.lookup("private_const").is_none());
        assert!(table.lookup("f").is_some());
    }

    #[test]
    fn private_fn_is_registered_same_as_exported() {
        // Private fns still get SymbolTable entries — the resolver
        // needs them to resolve intra-module references. Only
        // non-exported *lets* are skipped.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn helper() { 1 }\n\
             export fn public_api() { helper() }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        register_all(&mut table, &graph).expect("register");

        assert!(table.lookup("helper").is_some());
        assert!(table.lookup("public_api").is_some());
    }

    #[test]
    fn non_root_module_uses_mod_n_prefix() {
        let mut src = MockSource::default();
        src.add("lib", "export fn add(a, b) { a + b }");
        src.add("main", "import \"lib\" as l\nlet x = l::add(1, 2)");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        register_all(&mut table, &graph).expect("register");

        // `lib` was loaded first (reverse topo), so it got ModuleId(0).
        // `main` is the root, so its fns/lets use bare keys. `lib`'s
        // `add` lives under `mod0::add`.
        assert_eq!(graph.root().as_u32(), 1);
        assert!(table.lookup("mod0::add").is_some());
        assert!(table.lookup("add").is_none(), "lib::add should not be bare");
    }

    #[test]
    fn topo_order_registers_dependencies_before_dependents() {
        let mut src = MockSource::default();
        src.add("c", "export fn deep() { 1 }");
        src.add("b", "import \"c\" as c\nexport fn middle() { c::deep() }");
        src.add("a", "import \"b\" as b\nlet top = b::middle()");
        let graph = ModuleGraph::build("a", &mut src).expect("build");
        let mut table = SymbolTable::new();
        register_all(&mut table, &graph).expect("register");

        // c=mod0, b=mod1, a=root. We confirm each module's unique
        // symbol is present.
        assert!(table.lookup("mod0::deep").is_some());
        assert!(table.lookup("mod1::middle").is_some());
        // `top` is a private let in the root module — not registered.
        assert!(table.lookup("top").is_none());
    }

    #[test]
    fn duplicate_top_level_fn_errors() {
        let mut src = MockSource::default();
        src.add("main", "fn dup() { 1 }\nfn dup() { 2 }");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        let err = register_all(&mut table, &graph).unwrap_err();
        match err {
            ResolveError::DuplicateModuleSymbol { name, module } => {
                assert_eq!(name, "dup");
                assert_eq!(module, graph.root().as_u32());
            }
            other => panic!("expected DuplicateModuleSymbol, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_fn_vs_let_errors() {
        let mut src = MockSource::default();
        src.add("main", "fn dup() { 1 }\nexport let dup = 42");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        let err = register_all(&mut table, &graph).unwrap_err();
        assert!(matches!(err, ResolveError::DuplicateModuleSymbol { .. }));
    }

    // ======================================================================
    // annotate_program — Phase 3C.2
    // ======================================================================

    use crate::builtins::BuiltinRegistry;
    use achronyme_parser::ast::{Program, TypedParam};

    /// Walk every Expr in a Program, calling `f` on each. Used by the
    /// 3C.2 tests to hand-pick specific nodes (by kind + name) and
    /// assert on their annotations without building a full visitor.
    fn visit_program<F: FnMut(&Expr)>(program: &Program, mut f: F) {
        for stmt in &program.stmts {
            visit_stmt(stmt, &mut f);
        }
    }

    fn visit_stmt<F: FnMut(&Expr)>(stmt: &Stmt, f: &mut F) {
        match stmt {
            Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => visit_expr(value, f),
            Stmt::Assignment { target, value, .. } => {
                visit_expr(target, f);
                visit_expr(value, f);
            }
            Stmt::FnDecl { body, .. } | Stmt::CircuitDecl { body, .. } => {
                for s in &body.stmts {
                    visit_stmt(s, f);
                }
            }
            Stmt::Print { value, .. } => visit_expr(value, f),
            Stmt::Return { value: Some(v), .. } => visit_expr(v, f),
            Stmt::Expr(e) => visit_expr(e, f),
            Stmt::Export { inner, .. } => visit_stmt(inner, f),
            _ => {}
        }
    }

    fn visit_expr<F: FnMut(&Expr)>(expr: &Expr, f: &mut F) {
        f(expr);
        match expr {
            Expr::BinOp { lhs, rhs, .. } => {
                visit_expr(lhs, f);
                visit_expr(rhs, f);
            }
            Expr::UnaryOp { operand, .. } => visit_expr(operand, f),
            Expr::Call { callee, args, .. } => {
                visit_expr(callee, f);
                for a in args {
                    visit_expr(&a.value, f);
                }
            }
            Expr::Index { object, index, .. } => {
                visit_expr(object, f);
                visit_expr(index, f);
            }
            Expr::DotAccess { object, .. } => visit_expr(object, f),
            Expr::If {
                condition,
                then_block,
                else_branch,
                ..
            } => {
                visit_expr(condition, f);
                for s in &then_block.stmts {
                    visit_stmt(s, f);
                }
                match else_branch {
                    Some(ElseBranch::Block(b)) => {
                        for s in &b.stmts {
                            visit_stmt(s, f);
                        }
                    }
                    Some(ElseBranch::If(e)) => visit_expr(e, f),
                    None => {}
                }
            }
            Expr::For { iterable, body, .. } => {
                match iterable {
                    ForIterable::ExprRange { end, .. } => visit_expr(end, f),
                    ForIterable::Expr(e) => visit_expr(e, f),
                    _ => {}
                }
                for s in &body.stmts {
                    visit_stmt(s, f);
                }
            }
            Expr::While {
                condition, body, ..
            } => {
                visit_expr(condition, f);
                for s in &body.stmts {
                    visit_stmt(s, f);
                }
            }
            Expr::Forever { body, .. } | Expr::FnExpr { body, .. } | Expr::Prove { body, .. } => {
                for s in &body.stmts {
                    visit_stmt(s, f);
                }
            }
            Expr::Block { block, .. } => {
                for s in &block.stmts {
                    visit_stmt(s, f);
                }
            }
            Expr::Array { elements, .. } => {
                for e in elements {
                    visit_expr(e, f);
                }
            }
            Expr::Map { pairs, .. } => {
                for (_, v) in pairs {
                    visit_expr(v, f);
                }
            }
            _ => {}
        }
    }

    /// Find every `Expr::Ident { name: expected }` in a module and return
    /// their [`ExprId`]s in source order.
    fn find_idents(program: &Program, expected: &str) -> Vec<ExprId> {
        let mut out = Vec::new();
        visit_program(program, |e| {
            if let Expr::Ident { id, name, .. } = e {
                if name == expected {
                    out.push(*id);
                }
            }
        });
        out
    }

    fn find_static_accesses(program: &Program, type_name: &str, member: &str) -> Vec<ExprId> {
        let mut out = Vec::new();
        visit_program(program, |e| {
            if let Expr::StaticAccess {
                id,
                type_name: t,
                member: m,
                ..
            } = e
            {
                if t == type_name && m == member {
                    out.push(*id);
                }
            }
        });
        out
    }

    fn find_dot_accesses(program: &Program, object_name: &str, field: &str) -> Vec<ExprId> {
        let mut out = Vec::new();
        visit_program(program, |e| {
            if let Expr::DotAccess {
                id,
                object,
                field: f,
                ..
            } = e
            {
                if f == field {
                    if let Expr::Ident { name, .. } = object.as_ref() {
                        if name == object_name {
                            out.push(*id);
                        }
                    }
                }
            }
        });
        out
    }

    /// Build a fresh table with the production builtin registry plus
    /// the given graph's module symbols.
    fn build_full_table(graph: &ModuleGraph) -> SymbolTable {
        let mut table =
            SymbolTable::with_registry(BuiltinRegistry::default()).expect("registry audit");
        register_builtins(&mut table);
        register_all(&mut table, graph).expect("register_all");
        table
    }

    #[test]
    fn annotates_same_module_fn_call() {
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn helper() { 1 }\n\
             fn entry() { helper() }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let helper_id = table.lookup("helper").expect("helper registered");
        let root = graph.get(graph.root());
        let ident_ids = find_idents(&root.program, "helper");
        assert_eq!(
            ident_ids.len(),
            1,
            "expected one `helper` ident in the call site"
        );
        assert_eq!(
            annotations.get(&(graph.root(), ident_ids[0])),
            Some(&helper_id)
        );
    }

    #[test]
    fn local_param_shadows_module_fn() {
        // fn x is a module symbol; calling `x` inside `fn f(x) { x }`
        // references the *parameter*, not the module fn. The walker
        // must NOT annotate the param reference.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn x() { 0 }\n\
             fn f(x) { x }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let root = graph.get(graph.root());
        // There are two Ident "x" nodes: one in the param position
        // (which isn't an Expr) and one in the return expression `x`.
        // `find_idents` only sees Expr::Ident, so exactly one result.
        let ident_ids = find_idents(&root.program, "x");
        assert_eq!(ident_ids.len(), 1, "expected the `x` in the body");
        assert!(
            !annotations.contains_key(&(graph.root(), ident_ids[0])),
            "shadowed param must not be annotated against the module fn"
        );
    }

    #[test]
    fn selective_import_resolves_to_target_module_symbol() {
        let mut src = MockSource::default();
        src.add("lib", "export fn add(a, b) { a + b }");
        src.add(
            "main",
            "import { add } from \"lib\"\nfn call() { add(1, 2) }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let add_id = table.lookup("mod0::add").expect("add registered");
        let root = graph.get(graph.root());
        let ident_ids = find_idents(&root.program, "add");
        assert_eq!(ident_ids.len(), 1);
        assert_eq!(
            annotations.get(&(graph.root(), ident_ids[0])),
            Some(&add_id)
        );
    }

    #[test]
    fn namespace_import_via_static_access() {
        let mut src = MockSource::default();
        src.add("lib", "export fn add(a, b) { a + b }");
        src.add("main", "import \"lib\" as l\nlet x = l::add(1, 2)");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let add_id = table.lookup("mod0::add").expect("add registered");
        let root = graph.get(graph.root());
        let sa_ids = find_static_accesses(&root.program, "l", "add");
        assert_eq!(sa_ids.len(), 1);
        assert_eq!(annotations.get(&(graph.root(), sa_ids[0])), Some(&add_id));
    }

    #[test]
    fn namespace_import_via_dot_access() {
        let mut src = MockSource::default();
        src.add("lib", "export fn add(a, b) { a + b }");
        src.add("main", "import \"lib\" as l\nlet x = l.add(1, 2)");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let add_id = table.lookup("mod0::add").expect("add registered");
        let root = graph.get(graph.root());
        let dot_ids = find_dot_accesses(&root.program, "l", "add");
        assert_eq!(
            dot_ids.len(),
            1,
            "expected one `l.add` DotAccess in the call site"
        );
        assert_eq!(annotations.get(&(graph.root(), dot_ids[0])), Some(&add_id));
    }

    #[test]
    fn builtin_call_is_annotated_after_register_builtins() {
        let mut src = MockSource::default();
        src.add("main", "fn f(a, b) { poseidon(a, b) }");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let poseidon_id = table.lookup("poseidon").expect("builtin registered");
        // Sanity: it's actually a Builtin kind.
        assert!(matches!(
            table.get(poseidon_id),
            CallableKind::Builtin { .. }
        ));

        let root = graph.get(graph.root());
        let ident_ids = find_idents(&root.program, "poseidon");
        assert_eq!(ident_ids.len(), 1);
        assert_eq!(
            annotations.get(&(graph.root(), ident_ids[0])),
            Some(&poseidon_id)
        );
    }

    #[test]
    fn annotates_against_definer_scope_not_caller_scope() {
        // Gap 2.4 preview. The `c::deep()` call inside b::middle()
        // must resolve to `mod0::deep` (c's fn) at annotation time,
        // because we walk module `b` against `b`'s own imports. When
        // Phase 3E inlines `middle` into `a.ach`, the annotation is
        // already attached — `a.ach`'s scope never gets a chance to
        // re-resolve `c::deep` against its own (non-existent) `c`
        // import.
        let mut src = MockSource::default();
        src.add("c", "export fn deep() { 1 }");
        src.add("b", "import \"c\" as c\nexport fn middle() { c::deep() }");
        src.add("a", "import \"b\" as b\nlet top = b::middle()");
        let graph = ModuleGraph::build("a", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        // c::deep lives under mod0::deep; b::middle under mod1::middle.
        let deep_id = table.lookup("mod0::deep").expect("deep registered");
        let middle_id = table.lookup("mod1::middle").expect("middle registered");

        // Check the annotation on `c::deep` inside b's program.
        let b_id = ModuleId::from_raw(1);
        let b_module = graph.get(b_id);
        let c_deep_ids = find_static_accesses(&b_module.program, "c", "deep");
        assert_eq!(c_deep_ids.len(), 1);
        assert_eq!(
            annotations.get(&(b_id, c_deep_ids[0])),
            Some(&deep_id),
            "c::deep inside b should resolve to c's fn at parse time"
        );

        // And the annotation on `b::middle` inside a's program.
        let a_module = graph.get(graph.root());
        let b_middle_ids = find_static_accesses(&a_module.program, "b", "middle");
        assert_eq!(b_middle_ids.len(), 1);
        assert_eq!(
            annotations.get(&(graph.root(), b_middle_ids[0])),
            Some(&middle_id)
        );
    }

    #[test]
    fn nested_block_scope_tracks_shadowing() {
        // The inner `g` let shadows the outer `g`. Both references to
        // `g` are locals, so neither should be annotated.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn g() { 0 }\n\
             fn f() { let g = 1\n { let g = 2\n g } }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let root = graph.get(graph.root());
        let ident_ids = find_idents(&root.program, "g");
        // One Ident `g` appears — the trailing reference inside the
        // nested block. The outer/inner `let g = …` LHS isn't an Expr.
        assert_eq!(ident_ids.len(), 1);
        assert!(
            !annotations.contains_key(&(graph.root(), ident_ids[0])),
            "nested let g should shadow the module-level fn g"
        );
    }

    #[test]
    fn exported_constant_is_resolved_inside_same_module() {
        // Phase 3C.1 registered `PI` as a Constant. Inside the same
        // module, a bare reference to `PI` should annotate against
        // that Constant (not fall through to "local" — top-level
        // lets are not tracked in the scope stack for exactly this
        // reason).
        let mut src = MockSource::default();
        src.add("main", "export let PI = 3\nfn area(r) { PI }");
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let annotations = annotate_program(&graph, &table).annotations;

        let pi_id = table.lookup("PI").expect("PI registered");
        let root = graph.get(graph.root());
        let ident_ids = find_idents(&root.program, "PI");
        assert_eq!(ident_ids.len(), 1);
        assert_eq!(annotations.get(&(graph.root(), ident_ids[0])), Some(&pi_id));
    }

    #[test]
    fn register_builtins_populates_bare_names() {
        // Defensive: register_builtins should insert every default
        // builtin under its bare name, and each should resolve via
        // table.lookup.
        let mut table =
            SymbolTable::with_registry(BuiltinRegistry::default()).expect("registry audit");
        register_builtins(&mut table);
        for name in ["poseidon", "assert_eq", "range_check", "mux", "print"] {
            let id = table
                .lookup(name)
                .unwrap_or_else(|| panic!("{name} missing after register_builtins"));
            assert!(matches!(table.get(id), CallableKind::Builtin { .. }));
        }
    }

    // Suppress the unused-import warning for TypedParam — imported to
    // document the param-walking contract even though tests use string
    // inputs that parse into them.
    #[allow(dead_code)]
    fn _param_doc_marker(_: TypedParam) {}

    // ======================================================================
    // FnAlias + ProveBlockUnsupportedShape — Phase 3C.3
    // ======================================================================

    use crate::error::UnsupportedShape;

    #[test]
    fn fn_alias_local_resolves_to_target() {
        // `let a = helper; a()` — the call-site `a` is annotated
        // directly to helper's SymbolId, so Phase 3D/3E dispatch
        // through the alias uniformly.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn helper() { 1 }\n\
             fn caller() { let a = helper\n a() }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);
        assert!(
            resolved.diagnostics.is_empty(),
            "no diagnostics expected, got {:?}",
            resolved.diagnostics
        );

        let helper_id = table.lookup("helper").expect("helper registered");
        let root = graph.get(graph.root());
        let a_idents = find_idents(&root.program, "a");
        assert_eq!(
            a_idents.len(),
            1,
            "expected one `a` Ident in the call-site position"
        );
        assert_eq!(
            resolved.annotations.get(&(graph.root(), a_idents[0])),
            Some(&helper_id),
            "FnAlias should flatten to the target symbol"
        );
    }

    #[test]
    fn fn_alias_cross_module_via_static_access() {
        // `let a = l::helper; a()` — the alias resolves against a
        // namespace import, so the call site annotates to the
        // imported module's symbol.
        let mut src = MockSource::default();
        src.add("lib", "export fn helper() { 1 }");
        src.add(
            "main",
            "import \"lib\" as l\n\
             fn caller() { let a = l::helper\n a() }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        let helper_id = table.lookup("mod0::helper").expect("helper registered");
        let root = graph.get(graph.root());
        let a_idents = find_idents(&root.program, "a");
        assert_eq!(a_idents.len(), 1);
        assert_eq!(
            resolved.annotations.get(&(graph.root(), a_idents[0])),
            Some(&helper_id)
        );
    }

    #[test]
    fn fn_alias_shadows_outer_module_fn() {
        // Inside `f`, `let a = poseidon` binds `a` as an alias to the
        // builtin. The outer `fn a()` is shadowed inside f's body —
        // `a(1, 2)` annotates to poseidon, not to the module's `a`.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn a() { 0 }\n\
             fn f() { let a = poseidon\n a(1, 2) }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        let poseidon_id = table.lookup("poseidon").expect("builtin registered");
        let root = graph.get(graph.root());
        // find_idents returns source order. The first `a` is the let
        // LHS position? No — that's a String, not an Expr. The first
        // Ident `a` is the call-site in `a(1, 2)`. And the let RHS
        // contains Ident("poseidon"), not `a`, so we get exactly one
        // Ident("a") in the program.
        let a_idents = find_idents(&root.program, "a");
        assert_eq!(a_idents.len(), 1);
        assert_eq!(
            resolved.annotations.get(&(graph.root(), a_idents[0])),
            Some(&poseidon_id),
            "inner alias should shadow the outer module fn `a`"
        );
    }

    #[test]
    fn dynamic_fn_value_emitted_inside_prove_block() {
        // `let a = if true { poseidon } else { mux }; a(1,2,3)` in a
        // prove block. Both branches const-resolve to fn symbols, so
        // `a` is a DynamicFn local, and calling it in prove mode
        // fires the DynamicFnValue diagnostic.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn outer() {\n\
               prove() {\n\
                 let a = if true { poseidon } else { mux }\n\
                 a(1, 2, 3)\n\
               }\n\
             }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        assert!(
            resolved.diagnostics.iter().any(|d| matches!(
                d,
                ResolveError::ProveBlockUnsupportedShape {
                    shape: UnsupportedShape::DynamicFnValue,
                    ..
                }
            )),
            "expected DynamicFnValue, got {:?}",
            resolved.diagnostics
        );
    }

    #[test]
    fn dynamic_fn_value_outside_prove_is_silent() {
        // Same pattern as above, without the `prove()` wrapper —
        // VM mode handles dynamic fn values through closures, so no
        // diagnostic should fire.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn outer() {\n\
               let a = if true { poseidon } else { mux }\n\
               a(1, 2, 3)\n\
             }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);
        assert!(
            resolved.diagnostics.is_empty(),
            "no diagnostics expected outside prove block, got {:?}",
            resolved.diagnostics
        );
    }

    #[test]
    fn runtime_map_access_emitted_inside_prove_block() {
        // `let m = { k: 1 }; m.k` inside a prove block. The Map
        // literal is classified as RuntimeMap; any DotAccess on `m`
        // emits RuntimeMapAccess.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn outer() {\n\
               prove() {\n\
                 let m = { k: 1 }\n\
                 m.k\n\
               }\n\
             }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        assert!(
            resolved.diagnostics.iter().any(|d| matches!(
                d,
                ResolveError::ProveBlockUnsupportedShape {
                    shape: UnsupportedShape::RuntimeMapAccess,
                    ..
                }
            )),
            "expected RuntimeMapAccess, got {:?}",
            resolved.diagnostics
        );
    }

    #[test]
    fn runtime_method_chain_emitted_inside_prove_block() {
        // `let x = 1; x.foo()` inside a prove block. The callee is a
        // DotAccess whose object is a plain local — not a namespace
        // alias — so walk_call emits RuntimeMethodChain.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn outer() {\n\
               prove() {\n\
                 let x = 1\n\
                 x.foo()\n\
               }\n\
             }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        assert!(
            resolved.diagnostics.iter().any(|d| matches!(
                d,
                ResolveError::ProveBlockUnsupportedShape {
                    shape: UnsupportedShape::RuntimeMethodChain,
                    ..
                }
            )),
            "expected RuntimeMethodChain, got {:?}",
            resolved.diagnostics
        );
    }

    #[test]
    fn namespace_dot_call_is_not_method_chain() {
        // `l.helper()` where `l` is a namespace alias — valid in
        // prove mode, no diagnostic.
        let mut src = MockSource::default();
        src.add("lib", "export fn helper() { 1 }");
        src.add(
            "main",
            "import \"lib\" as l\n\
             fn outer() {\n\
               prove() {\n\
                 l.helper()\n\
               }\n\
             }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        assert!(
            resolved.diagnostics.is_empty(),
            "namespace dot call should not trigger RuntimeMethodChain, got {:?}",
            resolved.diagnostics
        );
    }

    #[test]
    fn non_static_fn_arg_emitted_inside_prove_block() {
        // `poseidon(if true { poseidon } else { mux }, 2)` inside a
        // prove block. The first arg is an If whose branches both
        // const-resolve to fn symbols — a dynamic fn value in
        // argument position.
        let mut src = MockSource::default();
        src.add(
            "main",
            "fn outer() {\n\
               prove() {\n\
                 poseidon(if true { poseidon } else { mux }, 2)\n\
               }\n\
             }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let table = build_full_table(&graph);
        let resolved = annotate_program(&graph, &table);

        assert!(
            resolved.diagnostics.iter().any(|d| matches!(
                d,
                ResolveError::ProveBlockUnsupportedShape {
                    shape: UnsupportedShape::NonStaticFnArg,
                    ..
                }
            )),
            "expected NonStaticFnArg, got {:?}",
            resolved.diagnostics
        );
    }

    #[test]
    fn stmt_index_skips_imports_but_counts_position() {
        // The stmt_index field must point at the actual statement
        // inside the original Program.stmts, not a "just fns" slice.
        // If the walker counted wrong, a consumer that dereferences
        // `module.program.stmts[stmt_index]` would get the wrong node.
        let mut src = MockSource::default();
        src.add("lib", "export fn unused() { 0 }");
        src.add(
            "main",
            "import \"lib\" as l\n\
             let junk = 1\n\
             fn target() { 42 }",
        );
        let graph = ModuleGraph::build("main", &mut src).expect("build");
        let mut table = SymbolTable::new();
        register_all(&mut table, &graph).expect("register");

        let target_id = table.lookup("target").expect("target registered");
        match table.get(target_id) {
            CallableKind::UserFn { stmt_index, .. } => {
                // main.ach has: import=0, let=1, fn=2
                assert_eq!(*stmt_index, 2);
            }
            other => panic!("expected UserFn, got {other:?}"),
        }
    }
}
