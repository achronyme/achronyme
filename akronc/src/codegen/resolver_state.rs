//! Resolver-state hookup for the `Compiler` orchestrator.
//!
//! Covers the dispatch machinery: the manual install path (for tests
//! and CLI flows that build their own [`SymbolTable`] and
//! [`ResolvedProgram`]) and the in-memory-root auto-build path
//! invoked from [`Compiler::compile`] whenever the caller didn't
//! install a state up front.
//!
//! Two free helpers live here too — `program_has_imports` and
//! `has_import` — since they're used only by
//! `try_auto_build_resolver_state` to gate multi-module auto-build
//! on `base_path` being set.

use std::path::PathBuf;
use std::sync::Arc;

use achronyme_parser::ast::{Program, Stmt};
use ir::resolver_adapter::ModuleLoaderSource;
use resolve::{
    build_availability_map, build_dispatch_maps, build_resolver_state, ModuleId, ResolvedProgram,
    SymbolTable,
};

use super::Compiler;
use crate::module_loader::ModuleLoader;

impl Compiler {
    /// Install a pre-built resolver state. Tests and CLI flows that
    /// want to control how the module graph is loaded can build the
    /// [`SymbolTable`] + [`ResolvedProgram`] externally and hand them
    /// to the compiler before calling [`Compiler::compile`].
    ///
    /// `root_module` is the [`ModuleId`] of the root of the graph
    /// `program` belongs to; pass [`resolve::ModuleGraph::root`].
    ///
    /// Clears any previous resolver state and the hit trace. Does
    /// NOT populate the dispatch maps — external installers that
    /// care about cross-module dispatch must either build the maps
    /// themselves or use the [`Compiler::compile`] auto-build path,
    /// which derives them from the graph.
    pub fn install_resolver_state(
        &mut self,
        table: SymbolTable,
        program: ResolvedProgram,
        root_module: ModuleId,
    ) {
        self.resolver_symbol_table = Some(table);
        self.resolved_program = Some(program);
        self.resolver_root_module = Some(root_module);
        self.resolver_hits.clear();
        self.resolver_dispatch_by_symbol = None;
        self.resolver_module_by_key = None;
        self.resolver_availability_map = None;
        self.resolver_outer_functions = None;
    }

    /// Build a resolver state for the current program and install it
    /// on this compiler. Used by [`Compiler::compile`] to wire
    /// resolver-driven dispatch when no state was installed up front.
    ///
    /// ## Multi-module policy
    ///
    /// - Single-module programs (no imports) always go through the
    ///   in-memory-root override: the adapter serves the already
    ///   parsed [`Program`] to the graph builder without re-parsing.
    /// - Multi-module programs build the full import graph when
    ///   `self.base_path` is set — the adapter's in-memory-root fix
    ///   lets the graph builder resolve transitive `./x.ach`
    ///   imports against `base_path`. Without a `base_path` (typical
    ///   for in-memory tests), multi-module compiles silently skip
    ///   the auto-build, falling back to the `fn_decl_asts`
    ///   aggregation path.
    ///
    /// On success, this also precomputes the fn_table dispatch maps
    /// via [`build_dispatch_maps`] so the ProveIR compiler can
    /// translate `SymbolId → fn_table key` and `fn_table key →
    /// ModuleId` without re-parsing resolver conventions at every
    /// call site.
    ///
    /// A silent no-op if any step fails — the resolver state is an
    /// optimisation path, not a correctness requirement, so a
    /// resolver failure must NOT break compilation.
    pub(super) fn try_auto_build_resolver_state(&mut self, program: &Program) {
        // Multi-module programs without base_path can't resolve
        // transitive imports — the adapter would fail to
        // canonicalize `./foo.ach` against an empty base. Skip in
        // that case; legacy path still works.
        if program_has_imports(program) && self.base_path.is_none() {
            return;
        }

        // Mirror ir::ModuleLoader's export-name flattening so
        // register_module sees the same list the legacy loader
        // would.
        let exported_names: Vec<String> = program
            .stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Export { inner, .. } => match inner.as_ref() {
                    Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect();

        // Opaque pseudo-path — the adapter's root override matches
        // by equality against this PathBuf, nothing more. Even in
        // the multi-module case, the root itself is served from
        // memory; only transitive imports touch the filesystem.
        let root_path = PathBuf::from("<resolve-in-memory-root>");
        let mut local_loader = ModuleLoader::new();
        let mut source = ModuleLoaderSource::with_root(
            self.base_path.clone(),
            &mut local_loader,
            root_path,
            program.clone(),
            exported_names,
        );
        let Ok(state) = build_resolver_state("<resolve-in-memory-root>", &mut source) else {
            return;
        };

        // Precompute the fn_table dispatch maps from the SymbolTable
        // + ModuleGraph. Both maps are Arc-shared so per-prove-block
        // handoff into `OuterResolverState` is a refcount bump
        // rather than a HashMap clone.
        let (dispatch_by_symbol, module_by_key) = build_dispatch_maps(&state.table, &state.graph);
        let availability_map = build_availability_map(&state.table, &state.graph);

        // Derive outer functions from the graph so prove blocks can
        // use them instead of the incremental fn_decl_asts.
        let outer_functions = resolve::build_outer_functions(&state, &dispatch_by_symbol);

        let root_module = state.root();
        self.resolved_program = Some(state.resolved);
        self.resolver_symbol_table = Some(state.table);
        self.resolver_root_module = Some(root_module);
        self.resolver_dispatch_by_symbol = Some(Arc::new(dispatch_by_symbol));
        self.resolver_module_by_key = Some(Arc::new(module_by_key));
        self.resolver_availability_map = Some(availability_map);
        self.resolver_outer_functions = Some(outer_functions);
    }
}

/// Returns true if a program contains any top-level `import` /
/// `selective import`. Multi-module auto-build is gated on the
/// presence of `base_path`: in-memory compiles without a filesystem
/// root can't canonicalize transitive imports, so the resolver state
/// for such programs is silently skipped and the `fn_decl_asts`
/// aggregation path handles dispatch.
fn program_has_imports(program: &Program) -> bool {
    program.stmts.iter().any(has_import)
}

fn has_import(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Import { .. } | Stmt::SelectiveImport { .. } | Stmt::ImportCircuit { .. } => true,
        Stmt::Export { inner, .. } => has_import(inner),
        _ => false,
    }
}
