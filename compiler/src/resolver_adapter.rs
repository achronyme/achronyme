//! Compiler ↔ resolver bridge — Movimiento 2 Phase 3D.
//!
//! [`CompilerModuleSource`] adapts [`ir::module_loader::ModuleLoader`]
//! (the compiler's existing lazy module cache) to the
//! [`resolve::module_graph::ModuleSource`] trait so the resolver pass
//! can build a [`resolve::ModuleGraph`] without re-parsing any file
//! the compiler already saw.
//!
//! ## In-memory root override
//!
//! The common entry point for this compiler is
//! [`crate::codegen::Compiler::compile`], which receives a `&str`
//! source blob directly — there is no filesystem path for the root.
//! To keep that path alive while still exposing a
//! [`resolve::ModuleGraph`] rooted at the in-memory program, the
//! adapter supports a **root override**: the caller hands over the
//! already-parsed [`Program`] + exported names + a pseudo-canonical
//! path, and the first `canonicalize(None, …)` / matching `load` pair
//! returns the override instead of touching disk. Any subsequent
//! transitive imports fall through to the real loader.
//!
//! The override is cheap in expected use: the program is cloned once
//! when handed to the graph, and the adapter exists only for the
//! duration of the `ModuleGraph::build` call.

use std::path::{Path, PathBuf};

use achronyme_parser::ast::Program;
use ir::module_loader::ModuleLoader;
use resolve::module_graph::{LoadedModule, ModuleSource};

/// [`ModuleSource`] implementation that layers an optional in-memory
/// root on top of [`ir::module_loader::ModuleLoader`].
///
/// See the module docs for the "root override" rationale. When the
/// root override is absent, every call delegates to the loader, so
/// this is also a valid shape for filesystem-rooted compiles once a
/// future phase plumbs through the root's canonical path.
pub struct CompilerModuleSource<'a> {
    /// Fallback base directory used when canonicalizing a relative
    /// path whose importer has no parent directory (the
    /// in-memory-root case).
    base_path: Option<PathBuf>,
    /// The compiler's existing module cache. Borrowed mutably because
    /// [`ModuleLoader::load`] memoises parsing per path.
    loader: &'a mut ModuleLoader,
    /// Optional in-memory root: short-circuits the first
    /// `canonicalize(None, …)` / `load` pair so the adapter never
    /// re-parses the root source.
    root_override: Option<RootOverride>,
}

struct RootOverride {
    /// Pseudo-canonical path returned from `canonicalize(None, …)`.
    /// Only matters as a unique opaque key — it never hits the
    /// filesystem.
    canonical: PathBuf,
    /// Already-parsed root AST.
    program: Program,
    /// Top-level `export fn` / `export let` names. Mirrors the
    /// contract [`ir::module_loader::ModuleLoader::load`] exposes so
    /// the resolver's `register_module` pass sees the same shape.
    exported_names: Vec<String>,
}

impl<'a> CompilerModuleSource<'a> {
    /// Construct without an in-memory root — every `canonicalize` /
    /// `load` call hits the loader.
    pub fn new(base_path: Option<PathBuf>, loader: &'a mut ModuleLoader) -> Self {
        Self {
            base_path,
            loader,
            root_override: None,
        }
    }

    /// Construct with an in-memory root override. `canonical` is the
    /// pseudo-path that the graph builder will see for the root
    /// module; `program` is the already-parsed AST; `exported_names`
    /// mirrors the contract of [`ir::module_loader::ModuleExports`].
    pub fn with_root(
        base_path: Option<PathBuf>,
        loader: &'a mut ModuleLoader,
        canonical: PathBuf,
        program: Program,
        exported_names: Vec<String>,
    ) -> Self {
        Self {
            base_path,
            loader,
            root_override: Some(RootOverride {
                canonical,
                program,
                exported_names,
            }),
        }
    }
}

impl<'a> ModuleSource for CompilerModuleSource<'a> {
    fn canonicalize(&mut self, importer: Option<&Path>, relative: &str) -> Result<PathBuf, String> {
        // Root canonicalization short-circuits when an in-memory
        // override is installed. The graph builder only ever passes
        // `importer = None` for the root call; transitive imports
        // always carry the parent canonical path.
        if importer.is_none() {
            if let Some(ro) = &self.root_override {
                return Ok(ro.canonical.clone());
            }
        }
        // Phase 3F: transitive imports from the in-memory root arrive
        // with `importer = Some(<resolve-in-memory-root>)`. That
        // pseudo-path has no real filesystem parent, so we substitute
        // `self.base_path` as the base directory for resolving
        // `relative`. This is the only way `compile(&source)` compiles
        // can walk a multi-module import graph without a real root
        // file on disk.
        let is_in_memory_root = match (&self.root_override, importer) {
            (Some(ro), Some(imp)) => imp == ro.canonical,
            _ => false,
        };
        let base = if is_in_memory_root {
            self.base_path
                .clone()
                .unwrap_or_else(|| Path::new(".").to_path_buf())
        } else {
            importer
                .and_then(|p| p.parent())
                .map(|p| p.to_path_buf())
                .or_else(|| self.base_path.clone())
                .unwrap_or_else(|| Path::new(".").to_path_buf())
        };
        let resolved = base.join(relative);
        resolved
            .canonicalize()
            .map_err(|e| format!("cannot canonicalize `{relative}`: {e}"))
    }

    fn load(&mut self, canonical: &Path) -> Result<LoadedModule, String> {
        // Root override match: return a clone of the in-memory
        // program so the graph takes ownership without us losing the
        // override (the resolver pass may call load multiple times
        // during diamond-import dedup — not relevant for the root
        // itself, but cheap to keep correct).
        if let Some(ro) = &self.root_override {
            if ro.canonical == canonical {
                return Ok(LoadedModule {
                    program: ro.program.clone(),
                    exported_names: ro.exported_names.clone(),
                });
            }
        }
        let exports = self.loader.load(canonical)?;
        Ok(LoadedModule {
            program: exports.program.clone(),
            exported_names: exports.exported_names.clone(),
        })
    }
}
