//! Module graph builder.
//!
//! Walks a `.ach` source tree starting from a root file, loading every
//! transitively-imported module exactly once and recording the import
//! edges. The result is a [`ModuleGraph`] with nodes sorted in reverse
//! topological order (dependencies before dependents); the annotate
//! pass uses this ordering to populate the
//! [`SymbolTable`](crate::table::SymbolTable).
//!
//! ## What this does *not* do
//!
//! - No symbol resolution. Identifiers inside each module's AST remain
//!   name-based until the annotate pass runs.
//! - No bytecode emission. The legacy
//!   `compiler/src/statements/mod.rs:compile_import` is still
//!   authoritative for import lowering; this builder is pure addition.
//! - No circom-library handling. `import circuit "…"` statements are
//!   ignored here — circom libraries live in the VM compiler's own
//!   `CircomLibraryRegistry` and will be folded into the resolver only
//!   after the `.ach`-module pipeline is fully migrated.
//!
//! ## Decoupling from the filesystem
//!
//! The builder talks to the outside world through the
//! [`ModuleSource`] trait. Real use wires it to `ir::ModuleLoader` via
//! a thin adapter; tests use an in-memory mock. Keeping the trait here
//! means `resolve/` still has only one downstream dep
//! (`achronyme-parser`), respecting the dep barrier.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use achronyme_parser::ast::{Program, Span, Stmt};

use crate::error::ResolveError;

/// Dense identifier for a module inside a single [`ModuleGraph`].
///
/// Assigned in reverse topological order — a module's id is always
/// **larger** than the ids of the modules it imports, because leaves
/// are pushed to the node vector first during the DFS load. The
/// annotate pass exploits this: iterating `0..graph.len()` yields each
/// module with all of its dependencies already available in the
/// [`SymbolTable`](crate::table::SymbolTable).
///
/// Ids are stable within one graph and **not** comparable across
/// graphs. They are not `SymbolId`s — those come from the resolver
/// pass and reference individual fns / lets, not whole modules.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleId(u32);

impl ModuleId {
    /// Construct from a raw `u32`. Prefer the builder-returned ids
    /// over constructing these by hand.
    pub const fn from_raw(n: u32) -> Self {
        Self(n)
    }

    /// Raw underlying `u32`, suitable for indexing a
    /// `Vec<_>` or hashing.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// A single `.ach` module loaded by [`ModuleGraph::build`].
#[derive(Debug)]
pub struct ModuleNode {
    /// This module's id inside the owning graph. Equal to its position
    /// in [`ModuleGraph::nodes`].
    pub id: ModuleId,
    /// Canonical key used for dedup (usually a `canonicalize()`d
    /// filesystem path; tests may use any unique bytes wrapped in a
    /// `PathBuf`).
    pub path: PathBuf,
    /// The parsed AST, with [`ExprId`](achronyme_parser::ast::ExprId)s
    /// assigned at parse time.
    pub program: Program,
    /// Names this module exports — the union of `export fn` / `export
    /// let` declarations and any `export { a, b, … }` lists. Supplied
    /// by the [`ModuleSource`] adapter (the legacy
    /// `ir::ModuleLoader::collect_exports` logic stays authoritative).
    pub exported_names: Vec<String>,
    /// Outgoing import edges, in source order. Selective and namespace
    /// imports are both represented; circom imports are filtered out.
    pub imports: Vec<ImportEdge>,
}

/// One resolved edge in the module graph.
#[derive(Debug, Clone)]
pub struct ImportEdge {
    /// The namespace alias bound by `import "…" as alias`. Empty for
    /// selective imports, which do not introduce an alias.
    pub alias: String,
    /// The module being imported.
    pub target: ModuleId,
    /// Namespace vs selective import.
    pub kind: ImportEdgeKind,
    /// Source span of the import statement that produced this edge —
    /// used for diagnostics during annotation.
    pub span: Span,
}

/// Shape of an [`ImportEdge`] — mirrors the two parser variants
/// (`Stmt::Import` and `Stmt::SelectiveImport`).
#[derive(Debug, Clone)]
pub enum ImportEdgeKind {
    /// `import "path" as alias` — the whole module is exposed as a
    /// namespace under `alias`. Calls land via `alias::name` or
    /// `alias.name` (the annotate pass handles both).
    Namespace,
    /// `import { a, b, c } from "path"` — individual names are
    /// copied into the importer's scope. The `names` vector is the
    /// exact selector list from the parser, preserved for the
    /// annotation pass.
    Selective {
        /// The unqualified names the importer wants exposed.
        names: Vec<String>,
    },
}

/// The output of [`ModuleSource::load`] — the minimal amount of state
/// the graph builder needs from each module. Owned, because the graph
/// takes ownership of every loaded AST.
pub struct LoadedModule {
    /// Parsed AST.
    pub program: Program,
    /// Exported top-level names. The adapter is responsible for
    /// applying export-list semantics (duplicate detection, "not
    /// defined" errors, etc.); the graph builder trusts whatever
    /// arrives here.
    pub exported_names: Vec<String>,
}

/// The outside world's contribution to the resolver — path
/// canonicalization plus "read file, return parsed AST and exports".
///
/// Real deployments wrap `ir::ModuleLoader`; tests use a
/// `HashMap`-backed mock (see the `tests` module below).
pub trait ModuleSource {
    /// Resolve a user-written relative path (from an `import`
    /// statement) against the canonical path of the file that
    /// contained it. `importer` is `None` when resolving the root file
    /// passed to [`ModuleGraph::build`].
    ///
    /// Returning a `PathBuf` (not `&Path`) keeps ownership simple: the
    /// builder stores the result in its `by_path` dedup map.
    fn canonicalize(&mut self, importer: Option<&Path>, relative: &str) -> Result<PathBuf, String>;

    /// Load and parse the module at the given canonical path. The
    /// adapter is expected to cache by canonical path — calling
    /// `load` twice with the same key must return semantically
    /// identical [`LoadedModule`] values.
    fn load(&mut self, canonical: &Path) -> Result<LoadedModule, String>;
}

/// The result of a successful [`ModuleGraph::build`]. Holds every
/// transitively-reachable module with outgoing import edges and the
/// id of the root module the build started from.
#[derive(Debug)]
pub struct ModuleGraph {
    /// All loaded modules, **reverse-topologically ordered**: nodes
    /// earlier in the vector are imported by nodes later in the
    /// vector. Never the other way around. Iterating `0..len()`
    /// visits dependencies before dependents.
    nodes: Vec<ModuleNode>,
    /// Canonical path → id. Used for O(1) dedup when a module is
    /// imported from more than one place (diamond pattern).
    by_path: HashMap<PathBuf, ModuleId>,
    /// Id of the root module passed to [`build`](Self::build). Always
    /// the last pushed node, therefore `nodes.last().id`.
    root: ModuleId,
}

impl ModuleGraph {
    /// Build a graph rooted at `root_relative_path`.
    ///
    /// `source` is consulted for every distinct module. Cycle
    /// detection runs on the DFS stack, not on the whole
    /// graph — a diamond (A→B, A→C, B→D, C→D) loads `D` exactly once
    /// without firing a cycle error.
    pub fn build(
        root_relative_path: &str,
        source: &mut dyn ModuleSource,
    ) -> Result<Self, ResolveError> {
        let mut graph = Self {
            nodes: Vec::new(),
            by_path: HashMap::new(),
            root: ModuleId::from_raw(0),
        };
        let mut dfs_stack: HashSet<PathBuf> = HashSet::new();

        let root_canonical = source
            .canonicalize(None, root_relative_path)
            .map_err(|reason| ResolveError::ModuleCanonicalizeFailed {
                relative: root_relative_path.to_string(),
                importer: None,
                reason,
            })?;

        let root_id = graph.load_recursive(root_canonical, source, &mut dfs_stack)?;
        graph.root = root_id;
        Ok(graph)
    }

    /// Id of the module the build started from. Always `len() - 1`.
    pub fn root(&self) -> ModuleId {
        self.root
    }

    /// Number of modules in the graph.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the graph holds no modules. A successful `build()`
    /// never produces an empty graph — this accessor exists for
    /// parity with `len()` and for `Vec`-like ergonomics.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Look up a module by id. Panics (debug-only) if `id` is out of
    /// range; release builds return a freshly constructed default — we
    /// choose panic-in-debug because every `ModuleId` the graph hands
    /// out is guaranteed valid, so an out-of-range lookup is a
    /// resolver bug.
    pub fn get(&self, id: ModuleId) -> &ModuleNode {
        &self.nodes[id.as_u32() as usize]
    }

    /// Look up a module by canonical path.
    pub fn lookup(&self, canonical: &Path) -> Option<ModuleId> {
        self.by_path.get(canonical).copied()
    }

    /// Iterate over every module in reverse-topological order —
    /// dependencies first. The annotate pass consumes this.
    pub fn iter(&self) -> impl Iterator<Item = &ModuleNode> {
        self.nodes.iter()
    }

    /// Same as [`iter`](Self::iter) but yields owned ids, so the
    /// caller can hold them across mutable borrows of the graph.
    pub fn iter_ids(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.nodes.iter().map(|n| n.id)
    }

    // ------------------------------------------------------------------
    // Internal: DFS loader
    // ------------------------------------------------------------------

    fn load_recursive(
        &mut self,
        canonical: PathBuf,
        source: &mut dyn ModuleSource,
        dfs_stack: &mut HashSet<PathBuf>,
    ) -> Result<ModuleId, ResolveError> {
        // 1. Already fully loaded once (diamond dedup).
        if let Some(&id) = self.by_path.get(&canonical) {
            return Ok(id);
        }

        // 2. Currently on the DFS stack → cycle. `insert` returns
        //    `false` if the key was already present.
        if !dfs_stack.insert(canonical.clone()) {
            return Err(ResolveError::ModuleCycle { path: canonical });
        }

        // 3. Parse the module via the ModuleSource adapter.
        let loaded = source
            .load(&canonical)
            .map_err(|reason| ResolveError::ModuleLoadFailed {
                path: canonical.clone(),
                reason,
            })?;

        // 4. Pull the import edges out of the AST and recurse.
        let pending = collect_imports(&loaded.program);
        let mut edges = Vec::with_capacity(pending.len());
        for import in pending {
            let child_canonical = source
                .canonicalize(Some(&canonical), &import.relative)
                .map_err(|reason| ResolveError::ModuleCanonicalizeFailed {
                    relative: import.relative.clone(),
                    importer: Some(canonical.clone()),
                    reason,
                })?;
            let target = self.load_recursive(child_canonical, source, dfs_stack)?;
            edges.push(ImportEdge {
                alias: import.alias,
                target,
                kind: import.kind,
                span: import.span,
            });
        }

        // 5. Pop ourselves from the DFS stack and push the finished
        //    node. `by_path` goes in only now, so a cycle that tries
        //    to reach us mid-load still sees us on `dfs_stack`.
        dfs_stack.remove(&canonical);
        let id = ModuleId::from_raw(self.nodes.len() as u32);
        self.by_path.insert(canonical.clone(), id);
        self.nodes.push(ModuleNode {
            id,
            path: canonical,
            program: loaded.program,
            exported_names: loaded.exported_names,
            imports: edges,
        });
        Ok(id)
    }
}

// ----------------------------------------------------------------------
// Import collection
// ----------------------------------------------------------------------

struct PendingImport {
    relative: String,
    alias: String,
    kind: ImportEdgeKind,
    span: Span,
}

/// Walk a [`Program`]'s top-level statements and extract every import
/// statement as a `PendingImport`. Exported imports are unwrapped
/// (`export import "foo" as bar` is still an import from the
/// resolver's point of view). `ImportCircuit` statements are skipped
/// on purpose — they are handled by the legacy circom pipeline in the
/// VM compiler.
fn collect_imports(program: &Program) -> Vec<PendingImport> {
    let mut out = Vec::new();
    for stmt in &program.stmts {
        collect_from_stmt(stmt, &mut out);
    }
    out
}

fn collect_from_stmt(stmt: &Stmt, out: &mut Vec<PendingImport>) {
    match stmt {
        Stmt::Import { path, alias, span } => {
            // Skip .circom imports — they are handled by the circom
            // pipeline, not the .ach module graph.
            if path.ends_with(".circom") {
                return;
            }
            out.push(PendingImport {
                relative: path.clone(),
                alias: alias.clone(),
                kind: ImportEdgeKind::Namespace,
                span: span.clone(),
            });
        }
        Stmt::SelectiveImport { names, path, span } => {
            if path.ends_with(".circom") {
                return;
            }
            out.push(PendingImport {
                relative: path.clone(),
                alias: String::new(),
                kind: ImportEdgeKind::Selective {
                    names: names.clone(),
                },
                span: span.clone(),
            });
        }
        Stmt::Export { inner, .. } => {
            // `export import` is uncommon but well-defined — walk
            // into the wrapped statement the same way the VM compiler
            // does.
            collect_from_stmt(inner, out);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
