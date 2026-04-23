//! Public entry points on [`ProveIrCompiler`].
//!
//! Seven methods that drive a full compilation pass:
//!
//! - [`compile`] / [`compile_with_trace`] — thin wrappers that delegate
//!   to [`compile_with_source_dir`].
//! - [`compile_with_source_dir`] — the legacy entry that wires up
//!   resolver-state hooks and module loading.
//! - [`compile_into_instance`] — used internally by both the prove and
//!   circuit entries; runs the actual `compile_block_stmts` after
//!   pre-loading outer scope, fns, and (optionally) resolver state.
//! - [`compile_circuit`] — circuit-mode entry (file-based, supports
//!   imports + `circuit { … }` blocks). Runs the M2 Phase 6E
//!   resolver-state path when the source parses cleanly.
//! - [`try_build_circuit_resolver_state`] — Phase 3G helper that
//!   builds the (state, dispatch_by_symbol, module_by_key) bundle
//!   from a parsed source + source dir. Returns `None` on any build
//!   error so the caller can fall back to the legacy path.
//! - [`compile_prove_block`] — prove-block entry (string-based, no
//!   imports). Used by the .ach inline `prove { … }` lowering.
//!
//! Every entry constructs its own `ProveIrCompiler<F>` instance, so
//! state never leaks across compilations.

use std::path::Path;

use achronyme_parser::ast::{Block, Program, Stmt};
use memory::FieldBackend;

use super::helpers::{program_to_block, to_span};
use super::{
    CircuitResolverBundle, CompEnvValue, FnDef, OuterResolverState, OuterScope, OuterScopeEntry,
    ProveIrCompiler,
};
use crate::prove_ir::types::{CaptureArrayDef, ProveIR};
use ir_forge::ProveIrError;
use resolve::{
    build_availability_map, build_dispatch_maps, build_resolver_state, AnnotationKey, SymbolId,
};

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Compile an AST Block into a ProveIR template.
    ///
    /// `outer_scope`: values and functions from the enclosing scope.
    /// Pass `OuterScope::default()` for self-contained circuits.
    pub fn compile(block: &Block, outer_scope: &OuterScope) -> Result<ProveIR, ProveIrError> {
        Self::compile_with_source_dir(block, outer_scope, None, None)
    }

    /// Like [`compile`] but also returns the resolver shadow-hit
    /// trace that was recorded during the walk. Phase 3E.1 consumers
    /// (integration tests under `ir/tests/prove_ir_resolver_dispatch.rs`)
    /// use this to verify that the annotation-driven dispatch points
    /// at the same symbol the legacy env/fn_table lookup is about to
    /// pick. Not used by the production pipeline — the hit trace is
    /// observation only until Phase 3E.2 flips dispatch.
    pub fn compile_with_trace(
        block: &Block,
        outer_scope: &OuterScope,
    ) -> Result<(ProveIR, Vec<(AnnotationKey, SymbolId)>), ProveIrError> {
        let (prove_ir, compiler) = Self::compile_into_instance(block, outer_scope, None, None)?;
        Ok((prove_ir, compiler.resolver_hits))
    }

    pub(super) fn compile_with_source_dir(
        block: &Block,
        outer_scope: &OuterScope,
        source_dir: Option<std::path::PathBuf>,
        source_path: Option<std::path::PathBuf>,
    ) -> Result<ProveIR, ProveIrError> {
        Self::compile_into_instance(block, outer_scope, source_dir, source_path).map(|(ir, _)| ir)
    }

    /// Worker shared by [`compile_with_source_dir`] and
    /// [`compile_with_trace`]. Returns the fully-compiled ProveIR
    /// alongside the compiler instance so shadow-dispatch consumers
    /// can inspect the hit trace without re-running the walk.
    pub(super) fn compile_into_instance(
        block: &Block,
        outer_scope: &OuterScope,
        source_dir: Option<std::path::PathBuf>,
        source_path: Option<std::path::PathBuf>,
    ) -> Result<(ProveIR, Self), ProveIrError> {
        let mut compiler = Self::new();
        compiler.source_dir = source_dir;
        if let Some(path) = source_path {
            compiler.compiling_modules.insert(path);
        }

        // Register outer scope values as potential captures
        for (name, entry) in &outer_scope.values {
            match entry {
                OuterScopeEntry::Scalar => {
                    compiler
                        .env
                        .insert(name.clone(), CompEnvValue::Capture(name.clone()));
                }
                OuterScopeEntry::Array(n) => {
                    let elem_names: Vec<String> = (0..*n).map(|i| format!("{name}_{i}")).collect();
                    for ename in &elem_names {
                        compiler
                            .env
                            .insert(ename.clone(), CompEnvValue::Capture(ename.clone()));
                    }
                    compiler
                        .env
                        .insert(name.clone(), CompEnvValue::Array(elem_names));
                }
            }
        }

        // Register outer scope functions in fn_table for inlining.
        // When resolver state is available, embed the owning ModuleId
        // and Availability directly in the FnDef so compile_user_fn_call
        // can read them without a separate map lookup.
        let module_map = outer_scope
            .resolver_state
            .as_ref()
            .map(|s| &s.module_by_dispatch_key);
        let avail_map = outer_scope
            .resolver_state
            .as_ref()
            .map(|s| &s.availability_by_key);
        for stmt in &outer_scope.functions {
            if let Stmt::FnDecl {
                name,
                params,
                return_type,
                body,
                ..
            } = stmt
            {
                let owner_module = module_map.and_then(|m| m.get(name).copied());
                let availability = avail_map.and_then(|m| m.get(name).copied());
                compiler.fn_table.insert(
                    name.clone(),
                    FnDef {
                        params: params.clone(),
                        body: body.clone(),
                        return_type: return_type.clone(),
                        owner_module,
                        availability,
                    },
                );
            }
        }

        // Seed circom template imports from the outer scope.
        for (key, callable) in &outer_scope.circom_imports {
            compiler.circom_table.insert(key.clone(), callable.clone());
        }

        // Install the caller-built resolver state. The resolver_table +
        // resolved_program drive annotation-lookup; fn_symbol_index
        // (built below) translates SymbolId → fn_table key at dispatch.
        if let Some(state) = &outer_scope.resolver_state {
            compiler.resolver_table = Some(state.table.clone());
            compiler.resolver_resolved = Some(state.resolved.clone());
            compiler.resolver_root_module = Some(state.root_module);
            // Build fn_symbol_index: for each (SymbolId → fn_key) in
            // the dispatch map, record only entries whose key is
            // actually present in fn_table (filters stale/unused
            // symbols).
            for (sid, key) in state.dispatch_key_by_symbol.iter() {
                if compiler.fn_table.contains_key(key) {
                    compiler.fn_symbol_index.insert(*sid, key.clone());
                }
            }
        }

        // Compile all statements in the block
        compiler.compile_block_stmts(block)?;

        // Classify captures
        let captures =
            crate::prove_ir::capture::classify_captures(&compiler.captured_names, &compiler.body);

        // Build capture_arrays: arrays from outer scope whose elements were captured
        let mut capture_arrays = Vec::new();
        for (name, entry) in &outer_scope.values {
            if let OuterScopeEntry::Array(n) = entry {
                let has_captured =
                    (0..*n).any(|i| compiler.captured_names.contains(&format!("{name}_{i}")));
                if has_captured {
                    capture_arrays.push(CaptureArrayDef {
                        name: name.clone(),
                        size: *n,
                    });
                }
            }
        }

        let prove_ir = ProveIR {
            name: None,
            public_inputs: std::mem::take(&mut compiler.public_inputs),
            witness_inputs: std::mem::take(&mut compiler.witness_inputs),
            captures,
            body: std::mem::take(&mut compiler.body),
            capture_arrays,
        };
        Ok((prove_ir, compiler))
    }

    /// Convenience: parse source and compile as a self-contained circuit.
    ///
    /// Movimiento 2 Phase 3G: if `source_path` is set and the
    /// resolver's module-graph build succeeds, we pre-populate the
    /// ProveIR compiler's `fn_table` from the full graph (every
    /// transitively-reachable [`CallableKind::UserFn`]), precompute
    /// the dispatch maps, and install the resolver state alongside.
    /// This gives standalone circuit compiles the same cross-module
    /// reach as the VM compiler's prove-block path, killing gap 2.4
    /// in circuit mode as well.
    ///
    /// When the resolver auto-build fails (no source_path, unreadable
    /// transitive imports, etc.) the legacy path runs unchanged: the
    /// root-module's top-level fns go via `OuterScope::functions`
    /// and the preamble imports are processed at block-walk time via
    /// `register_module_exports`, which only sees surface-level
    /// exports.
    pub fn compile_circuit(
        source: &str,
        source_path: Option<&Path>,
    ) -> Result<ProveIR, ProveIrError> {
        use achronyme_parser::ast::{InputDecl, Stmt, Visibility};

        let (program, errors) = achronyme_parser::parse_program(source);
        if !errors.is_empty() {
            return Err(ProveIrError::ParseError(Box::new(errors[0].clone())));
        }

        // Phase 3G: try to build the resolver state and dispatch
        // maps upfront. Requires source_path so we can compute a
        // base directory for transitive imports. Silently fails
        // (returning None) if any step errors — the legacy path is
        // always a valid fallback.
        let source_dir = source_path.and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let canonical_source = source_path.and_then(|p| p.canonicalize().ok());
        let resolver_bundle = Self::try_build_circuit_resolver_state(&program, source_dir.clone());
        let has_resolver_state = resolver_bundle.is_some();

        // Collect top-level statements before the circuit declaration.
        //
        // When the resolver state built successfully, the preamble
        // imports and top-level fns are already covered by the
        // graph-driven pre-population below — we MUST skip them here
        // so compile_block_stmts doesn't re-register the same
        // entries (which would be wasted work) or, worse, produce
        // conflicting fn_table keys via register_module_exports.
        let mut preamble_stmts: Vec<Stmt> = Vec::new();
        let mut outer_functions: Vec<Stmt> = Vec::new();
        let mut circuit_decl = None;

        for stmt in &program.stmts {
            match stmt {
                Stmt::CircuitDecl { .. } if circuit_decl.is_none() => {
                    circuit_decl = Some(stmt);
                }
                Stmt::CircuitDecl { span, .. } => {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "only one circuit declaration is allowed per file".into(),
                        span: to_span(span),
                    });
                }
                Stmt::Import { .. } | Stmt::SelectiveImport { .. } if circuit_decl.is_none() => {
                    if !has_resolver_state {
                        preamble_stmts.push(stmt.clone());
                    }
                }
                Stmt::FnDecl { .. } if circuit_decl.is_none() => {
                    if !has_resolver_state {
                        outer_functions.push(stmt.clone());
                    }
                }
                Stmt::Export { .. } if circuit_decl.is_none() => {
                    if !has_resolver_state {
                        preamble_stmts.push(stmt.clone());
                    }
                }
                _ => {}
            }
        }

        if let Some(Stmt::CircuitDecl {
            params,
            body,
            name,
            span,
            ..
        }) = circuit_decl
        {
            // Synthesize public/witness declarations from typed params
            let mut stmts = Vec::new();
            for param in params {
                let ta =
                    param
                        .type_ann
                        .as_ref()
                        .ok_or_else(|| ProveIrError::UnsupportedOperation {
                            description: format!(
                                "circuit parameter `{}` has no type annotation",
                                param.name
                            ),
                            span: crate::error::span_box(Some(diagnostics::SpanRange::from(span))),
                        })?;
                let vis = ta
                    .visibility
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "circuit parameter `{}` requires Public or Witness",
                            param.name
                        ),
                        span: crate::error::span_box(Some(diagnostics::SpanRange::from(span))),
                    })?;
                let decl = InputDecl {
                    name: param.name.clone(),
                    array_size: ta.array_size,
                    type_ann: Some(ta.clone()),
                };
                match vis {
                    Visibility::Public => stmts.push(Stmt::PublicDecl {
                        names: vec![decl],
                        span: span.clone(),
                    }),
                    Visibility::Witness => stmts.push(Stmt::WitnessDecl {
                        names: vec![decl],
                        span: span.clone(),
                    }),
                }
            }

            // Phase 3G: if the resolver auto-build succeeded, swap
            // the legacy outer_functions list for a graph-driven
            // one (every transitive UserFn renamed to its fn_table
            // key) and attach the resolver state so the ProveIR
            // compiler's annotation path fires for dispatch.
            let (functions_for_scope, resolver_state_for_scope) = match resolver_bundle {
                Some(bundle) => {
                    let graph_functions =
                        resolve::build_outer_functions(&bundle.state, &bundle.dispatch_by_symbol);
                    let avail_map =
                        build_availability_map(&bundle.state.table, &bundle.state.graph);
                    let state_for_scope = Some(OuterResolverState {
                        table: std::sync::Arc::new(bundle.state.table.clone()),
                        resolved: std::sync::Arc::new(bundle.state.resolved.clone()),
                        root_module: bundle.state.root(),
                        dispatch_key_by_symbol: std::sync::Arc::new(bundle.dispatch_by_symbol),
                        module_by_dispatch_key: std::sync::Arc::new(bundle.module_by_key),
                        availability_by_key: std::sync::Arc::new(avail_map),
                    });
                    (graph_functions, state_for_scope)
                }
                None => (outer_functions, None),
            };

            // Prepend imports/exports before the circuit body (only
            // when the resolver state isn't carrying them — see the
            // `has_resolver_state` gate in the collection loop above).
            let mut all_stmts = preamble_stmts;
            all_stmts.extend(stmts);
            all_stmts.extend(body.stmts.clone());
            let circuit_block = Block {
                stmts: all_stmts,
                span: body.span.clone(),
            };
            let outer_scope = OuterScope {
                functions: functions_for_scope,
                resolver_state: resolver_state_for_scope,
                ..Default::default()
            };
            let mut prove_ir = Self::compile_with_source_dir(
                &circuit_block,
                &outer_scope,
                source_dir,
                canonical_source,
            )?;
            prove_ir.name = Some(name.clone());
            return Ok(prove_ir);
        }

        // Flat format is no longer supported — require circuit declaration
        Err(ProveIrError::UnsupportedOperation {
            description: "flat circuit format is not supported; \
                          use `circuit name(param: Public, ...) { body }` instead"
                .into(),
            span: None,
        })
    }

    /// Phase 3G helper: attempt to build a resolver state from a
    /// parsed circuit-file program and its source directory.
    ///
    /// Returns `Some(ResolverBundle)` on success or `None` on any
    /// failure (missing source_dir, graph build error, etc.) so
    /// `compile_circuit` can fall back to the legacy path without
    /// surfacing resolver-level errors to the user — the legacy
    /// path has its own error reporting via
    /// `register_module_exports` + `compile_import`.
    pub(super) fn try_build_circuit_resolver_state(
        program: &Program,
        source_dir: Option<std::path::PathBuf>,
    ) -> Option<CircuitResolverBundle> {
        // Resolving transitive imports requires a filesystem root.
        // Standalone circuit compiles without a source path (rare:
        // only from in-memory API users who don't set source_path)
        // skip the resolver state and take the legacy path.
        source_dir.as_ref()?;

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

        // The root is served from the already-parsed program via the
        // in-memory-root override (no re-parsing). Transitive imports
        // fall through to the loader, which canonicalizes against
        // source_dir via the Phase 3F adapter fix.
        let root_path = std::path::PathBuf::from("<resolve-in-memory-root>");
        let mut local_loader = crate::module_loader::ModuleLoader::new();
        let mut source = crate::resolver_adapter::ModuleLoaderSource::with_root(
            source_dir,
            &mut local_loader,
            root_path,
            program.clone(),
            exported_names,
        );
        let state = build_resolver_state("<resolve-in-memory-root>", &mut source).ok()?;
        let (dispatch_by_symbol, module_by_key) = build_dispatch_maps(&state.table, &state.graph);
        Some(CircuitResolverBundle {
            state,
            dispatch_by_symbol,
            module_by_key,
        })
    }

    // Phase 6E: `outer_functions_from_graph` moved to
    // `resolve::build::build_outer_functions`.

    /// Convenience: parse source and compile as a prove block with outer scope.
    pub fn compile_prove_block(
        source: &str,
        outer_scope: &OuterScope,
    ) -> Result<ProveIR, ProveIrError> {
        let (program, errors) = achronyme_parser::parse_program(source);
        if let Some(err) = errors
            .iter()
            .find(|d| d.severity == diagnostics::Severity::Error)
        {
            return Err(ProveIrError::ParseError(Box::new(err.clone())));
        }
        let block = program_to_block(source, program);
        Self::compile(&block, outer_scope)
    }
}
