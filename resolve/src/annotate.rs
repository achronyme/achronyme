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

use achronyme_parser::ast::Stmt;

use crate::error::ResolveError;
use crate::module_graph::{ModuleGraph, ModuleId};
use crate::symbol::{Availability, CallableKind, ConstKind};
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
