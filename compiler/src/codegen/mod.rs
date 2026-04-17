mod diagnostics;

use crate::error::CompilerError;
use crate::function_compiler::FunctionCompiler;
use crate::interner::{
    BigIntInterner, BytesInterner, CircomHandleInterner, CircomLibraryRegistry, FieldInterner,
    StringInterner,
};
use crate::module_loader::ModuleLoader;
use crate::statements::{stmt_span, StatementCompiler};
use achronyme_parser::ast::{ExprId, Program, Span, Stmt};
use achronyme_parser::Diagnostic;
use ir::resolver_adapter::ModuleLoaderSource;
use memory::Value;
use resolve::{
    build_availability_map, build_dispatch_maps, build_resolver_state, Availability, ModuleId,
    ResolvedProgram, SymbolId, SymbolTable,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use vm::opcode::OpCode;

/// The main compiler orchestrator
pub struct Compiler {
    pub compilers: Vec<FunctionCompiler>, // LIFO Stack of function compilers

    // FLAT list of ALL function prototypes (global indices)
    pub prototypes: Vec<memory::Function>,

    // Global Symbol Table (Name -> Entry with index + metadata)
    pub global_symbols: HashMap<String, crate::types::GlobalEntry>,
    pub next_global_idx: u16,
    /// Number of builtin native slots (from `BuiltinRegistry`). User
    /// globals start at this index. Replaces the old `USER_GLOBAL_START`
    /// constant — derived from the registry at construction time.
    pub native_count: u16,

    // String Interner (shared across all functions)
    pub interner: StringInterner,

    // Field Interner (shared across all functions)
    pub field_interner: FieldInterner,

    // BigInt Interner (shared across all functions)
    pub bigint_interner: BigIntInterner,

    // Bytes Interner (binary blobs, e.g. serialized ProveIR)
    pub bytes_interner: BytesInterner,

    /// Circom handle descriptors (template call sites) allocated
    /// during VM-mode codegen. Bulk-imported into the VM heap at
    /// program-load time alongside the constant pool.
    pub circom_handle_interner: CircomHandleInterner,

    /// Registry of compiled circom libraries referenced by the
    /// circom handles in `circom_handle_interner`. The CLI hands
    /// this over to the runtime handler so `library_id` inside a
    /// handle resolves to the same `Arc<CircomLibrary>` the
    /// compiler saw.
    pub circom_library_registry: CircomLibraryRegistry,

    // Module system
    pub base_path: Option<PathBuf>,
    pub module_loader: ModuleLoader,
    pub module_prefix: Option<String>,
    /// Tracks imported module aliases to detect duplicates.
    pub imported_aliases: HashMap<String, PathBuf>,
    /// Tracks modules currently being compiled (for cycle detection).
    pub compiling_modules: HashSet<PathBuf>,
    /// Tracks selectively imported names → (source module path, import span).
    pub imported_names: HashMap<String, (PathBuf, Span)>,
    /// Tracks which selectively imported names have been referenced.
    pub used_imported_names: HashSet<String>,

    // ── Circom interop ────────────────────────────────────────────
    /// Library search directories for `.circom` includes, typically
    /// read from `[circom] libs = [...]` in `achronyme.toml`.
    pub circom_lib_dirs: Vec<PathBuf>,
    /// Namespaces created by `import "x.circom" as P`. Templates are
    /// referenced from prove/circuit/VM bodies via `P.TemplateName(...)(...)`.
    /// These imports are **compile-time only** — no VM bytecode is emitted
    /// for them, so the alias is not registered as a global.
    pub circom_namespaces: HashMap<String, std::sync::Arc<circom::CircomLibrary>>,
    /// Selectively imported Circom templates: unqualified name →
    /// owning library. Populated by
    /// `import { T1, T2 } from "x.circom"`. The template name is
    /// always the map key — rename-on-import (`import { X as Y }`)
    /// is not supported today, so we don't carry a redundant "real
    /// name" column. When rename support lands this field should
    /// grow into a struct with an explicit `real_name: String`.
    pub circom_template_aliases: HashMap<String, std::sync::Arc<circom::CircomLibrary>>,

    /// Span of the expression/statement currently being compiled.
    pub current_span: Option<Span>,

    /// Warnings collected during compilation.
    pub warnings: Vec<Diagnostic>,

    /// Set of known method names for detecting `expr.method(args)` patterns.
    pub known_methods: HashSet<String>,

    /// FnDecl AST nodes accumulated during top-level compilation.
    /// Legacy path for ProveIR prove-block inlining. When the resolver
    /// auto-build succeeds, `resolver_outer_functions` is preferred.
    pub fn_decl_asts: Vec<Stmt>,

    /// Graph-derived outer functions built at resolver auto-build time.
    /// Each FnDecl is renamed to its dispatch key and covers all
    /// transitive UserFn symbols. When `Some`, prove blocks use this
    /// instead of `fn_decl_asts` — it captures transitive imports
    /// that the incremental accumulation misses.
    pub resolver_outer_functions: Option<Vec<Stmt>>,

    /// Prime field for ProveIR serialization. Defaults to BN254.
    pub prime_id: memory::field::PrimeId,

    // ── Movimiento 2 Phase 3D: resolver shadow-dispatch ────────────
    /// Annotation map produced by [`resolve::annotate_program`].
    /// Populated either automatically by [`Compiler::compile`] (for
    /// in-memory single-module programs) or manually via
    /// [`Compiler::install_resolver_state`]. The resolver-driven
    /// dispatch path reads this to resolve call-site annotations;
    /// the legacy name-based path coexists as a fallback for
    /// compiles without resolver state.
    pub resolved_program: Option<ResolvedProgram>,
    /// Symbol table produced alongside `resolved_program`. Stored so
    /// that hits into the annotation map can be resolved to their
    /// [`resolve::CallableKind`] for cross-validation + future
    /// dispatch.
    pub resolver_symbol_table: Option<SymbolTable>,
    /// Root [`ModuleId`] of the graph `resolved_program` belongs to.
    /// The lookup key into
    /// [`resolve::ResolvedProgram::annotations`] is `(module, expr_id)`;
    /// Phase 3D only touches root-module expressions, so stashing
    /// the id here avoids carrying the whole graph around. For
    /// auto-built in-memory roots this is always
    /// [`ModuleId::from_raw(0)`]; external installers pass their
    /// own.
    pub resolver_root_module: Option<ModuleId>,
    /// [`ExprId`] of the expression currently being compiled, set at
    /// the top of `compile_expr`. `compile_ident` reads this to form
    /// the `(module, expr_id)` annotation key without threading the
    /// id through every helper signature.
    pub current_expr_id: Option<ExprId>,
    /// Annotation hits recorded by `compile_ident` during a
    /// compilation pass. Each entry is `(expr_id, symbol_id)` for an
    /// [`Expr::Ident`](achronyme_parser::ast::Expr::Ident) whose
    /// resolver annotation matched. Consumed by Phase 3D tests;
    /// ignored by production code paths.
    pub resolver_hits: Vec<(ExprId, SymbolId)>,
    // ── Movimiento 2 Phase 3F: multi-module dispatch maps ──────────
    /// Precomputed translation from [`SymbolId`] to the fn_table
    /// key the ProveIR compiler uses. Derived at auto-build time
    /// from the resolver's [`SymbolTable`] + [`ModuleGraph`] import
    /// edges — see [`build_dispatch_maps`]. `None` when resolver
    /// state isn't installed. Shared with ProveIR per prove block
    /// via [`OuterResolverState::dispatch_key_by_symbol`].
    ///
    /// The `Arc` indirection makes per-prove-block hand-off free
    /// (cloning `Arc` is a refcount bump, not a `HashMap` copy).
    pub resolver_dispatch_by_symbol: Option<Arc<HashMap<SymbolId, String>>>,
    /// Inverse of [`resolver_dispatch_by_symbol`]: fn_table key to
    /// the owning [`ModuleId`]. Consumed by
    /// [`ir::prove_ir::ProveIrCompiler::compile_user_fn_call`] to
    /// push the definer's module onto the resolver stack before
    /// inlining — the structural half of the gap 2.4 fix.
    pub resolver_module_by_key: Option<Arc<HashMap<String, ModuleId>>>,
    // ── Movimiento 2 Phase 4: availability inference ──────────────
    /// fn_table key → [`Availability`] for every user function.
    /// The VM compiler checks this before emitting bytecode: if a
    /// function is `ProveIr`-only, its body is skipped (no bytecode)
    /// while its AST is still captured in `fn_decl_asts` for ProveIR
    /// inlining. `None` when resolver state isn't installed.
    pub resolver_availability_map: Option<HashMap<String, Availability>>,
}

use vm::specs::NativeMeta;

impl Default for Compiler {
    fn default() -> Self {
        Self::new()
    }
}

impl Compiler {
    pub fn new() -> Self {
        Self::with_extra_natives(&[])
    }

    /// Create a compiler with additional native functions beyond the builtins.
    ///
    /// `extra` entries are appended after the registry builtins — their
    /// indices continue from the VM native count. The VM must register
    /// the same modules in the same order via `VM::register_module()`.
    pub fn with_extra_natives(extra: &[NativeMeta]) -> Self {
        use crate::types::GlobalEntry;
        let registry = resolve::BuiltinRegistry::default();
        let vm_entries = registry.vm_entries_by_handle();
        let native_count = vm_entries.len();

        let mut global_symbols = HashMap::new();

        for entry in &vm_entries {
            let handle = entry.vm_fn.expect("vm_entries_by_handle guarantees vm_fn");
            global_symbols.insert(
                entry.name.to_string(),
                GlobalEntry {
                    index: handle.as_u32() as u16,
                    type_ann: None,
                    is_mutable: false,
                    param_names: None,
                },
            );
        }

        for (i, meta) in extra.iter().enumerate() {
            let index = native_count + i;
            assert!(
                !global_symbols.contains_key(meta.name),
                "Native name collision: '{}' already defined as builtin",
                meta.name,
            );
            global_symbols.insert(
                meta.name.to_string(),
                GlobalEntry {
                    index: index as u16,
                    type_ann: None,
                    is_mutable: false,
                    param_names: None,
                },
            );
        }

        let next_global_idx = (native_count + extra.len()) as u16;

        // Start with a "main" function compiler (arity=0 for top-level script)
        let main_compiler = FunctionCompiler::new("main".to_string(), 0);

        // Populate known method names from the prototype registry.
        let known_methods: HashSet<String> = vm::known_method_names()
            .into_iter()
            .map(|s| s.to_string())
            .collect();

        Self {
            compilers: vec![main_compiler],
            prototypes: Vec::new(),
            global_symbols,
            next_global_idx,
            native_count: native_count as u16,
            interner: StringInterner::new(),
            field_interner: FieldInterner::new(),
            bigint_interner: BigIntInterner::new(),
            bytes_interner: BytesInterner::new(),
            circom_handle_interner: CircomHandleInterner::new(),
            circom_library_registry: CircomLibraryRegistry::new(),
            base_path: None,
            module_loader: ModuleLoader::new(),
            module_prefix: None,
            imported_aliases: HashMap::new(),
            compiling_modules: HashSet::new(),
            imported_names: HashMap::new(),
            used_imported_names: HashSet::new(),
            circom_lib_dirs: Vec::new(),
            circom_namespaces: HashMap::new(),
            circom_template_aliases: HashMap::new(),
            current_span: None,
            warnings: Vec::new(),
            known_methods,
            fn_decl_asts: Vec::new(),
            resolver_outer_functions: None,
            prime_id: memory::field::PrimeId::Bn254,
            resolved_program: None,
            resolver_symbol_table: None,
            resolver_root_module: None,
            current_expr_id: None,
            resolver_hits: Vec::new(),
            resolver_dispatch_by_symbol: None,
            resolver_module_by_key: None,
            resolver_availability_map: None,
        }
    }

    /// Install a pre-built resolver state. Tests and CLI flows that
    /// want to control how the module graph is loaded can build the
    /// [`SymbolTable`] + [`ResolvedProgram`] externally and hand them
    /// to the compiler before calling [`Compiler::compile`].
    ///
    /// `root_module` is the [`ModuleId`] of the root of the graph
    /// `program` belongs to; pass [`resolve::ModuleGraph::root`].
    ///
    /// Clears any previous resolver state and the hit trace. Does
    /// NOT populate the Phase 3F dispatch maps — external installers
    /// that care about cross-module dispatch must either build the
    /// maps themselves or use the [`Compiler::compile`] auto-build
    /// path, which derives them from the graph.
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
    /// on this compiler. Used by [`Compiler::compile`] as the bridge
    /// between the legacy dispatch path and the resolver-driven one.
    ///
    /// ## Multi-module policy (Phase 3F)
    ///
    /// - Single-module programs (no imports) always go through the
    ///   in-memory-root override: the adapter serves the already
    ///   parsed [`Program`] to the graph builder without re-parsing.
    /// - Multi-module programs build the full import graph when
    ///   `self.base_path` is set — the adapter's in-memory-root fix
    ///   lets the graph builder resolve transitive `./x.ach`
    ///   imports against `base_path`. Without a `base_path` (typical
    ///   for in-memory tests), multi-module compiles silently skip
    ///   the auto-build, falling back to the legacy `fn_decl_asts`
    ///   aggregation.
    ///
    /// On success, this also precomputes the Phase 3F fn_table
    /// dispatch maps via [`build_dispatch_maps`] so the ProveIR
    /// compiler can translate `SymbolId → fn_table key` and
    /// `fn_table key → ModuleId` without re-parsing resolver
    /// conventions at every call site.
    ///
    /// A silent no-op if any step fails — the resolver state is an
    /// optimisation path, not a correctness requirement, so a
    /// resolver failure must NOT break compilation.
    fn try_auto_build_resolver_state(&mut self, program: &Program) {
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

        // Phase 3F: precompute the fn_table dispatch maps from the
        // SymbolTable + ModuleGraph. Both maps are Arc-shared so
        // per-prove-block handoff into `OuterResolverState` is a
        // refcount bump rather than a HashMap clone.
        let (dispatch_by_symbol, module_by_key) = build_dispatch_maps(&state.table, &state.graph);
        let availability_map = build_availability_map(&state.table, &state.graph);

        // Phase 6E: derive outer functions from the graph so prove
        // blocks can use them instead of the incremental fn_decl_asts.
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

    // Wrappers for FunctionCompiler
    pub fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        self.current()?.alloc_reg()
    }

    pub fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        self.current()?.alloc_contiguous(count)
    }

    pub fn free_reg(&mut self, reg: u8) -> Result<(), CompilerError> {
        self.current()?.free_reg(reg)
    }

    pub fn add_constant(&mut self, val: Value) -> Result<usize, CompilerError> {
        Ok(self.current()?.add_constant(val))
    }

    pub fn add_upvalue(&mut self, is_local: bool, index: u8) -> Result<u8, CompilerError> {
        Ok(self.current()?.add_upvalue(is_local, index))
    }

    pub fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) -> Result<(), CompilerError> {
        self.current()?.emit_abc(op, a, b, c);
        Ok(())
    }

    pub fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) -> Result<(), CompilerError> {
        self.current()?.emit_abx(op, a, bx);
        Ok(())
    }

    pub fn intern_string(&mut self, s: &str) -> u32 {
        self.interner.intern(s)
    }

    pub fn intern_field(&mut self, fe: memory::FieldElement) -> u32 {
        self.field_interner.intern(fe)
    }

    pub fn intern_bigint(&mut self, bi: memory::BigInt) -> u32 {
        self.bigint_interner.intern(bi)
    }

    pub fn intern_bytes(&mut self, data: Vec<u8>) -> u32 {
        self.bytes_interner.intern(data)
    }

    /// Register a circom handle descriptor and return the heap
    /// index the VM will resolve at program-run time.
    pub fn intern_circom_handle(&mut self, handle: memory::CircomHandle) -> u32 {
        self.circom_handle_interner.intern(handle)
    }

    /// Register a circom library in the compile-time registry and
    /// return its id. Called by the VM-mode codegen when it sees
    /// the first template call against a library.
    pub fn register_circom_library(&mut self, lib: std::sync::Arc<circom::CircomLibrary>) -> u32 {
        self.circom_library_registry.intern(lib)
    }

    /// Returns a mutable reference to the current (top) function compiler
    pub fn current(&mut self) -> Result<&mut FunctionCompiler, CompilerError> {
        self.compilers
            .last_mut()
            .ok_or_else(|| CompilerError::InternalError("compiler stack underflow".into()))
    }

    /// Returns an immutable reference to the current function compiler
    pub fn current_ref(&self) -> Result<&FunctionCompiler, CompilerError> {
        self.compilers
            .last()
            .ok_or_else(|| CompilerError::InternalError("compiler stack underflow".into()))
    }

    pub fn append_debug_symbols(&self, buffer: &mut Vec<u8>) {
        // 1. Invert Name->Index to (Index, Name) for serialization
        let mut symbols: Vec<(u16, &String)> = self
            .global_symbols
            .iter()
            .map(|(k, v)| (v.index, k))
            .collect();

        // 2. Sort by Index (Deterministic output is mandatory for build reproducibility)
        symbols.sort_by_key(|&(idx, _)| idx);

        // 3. Write Section
        buffer.extend_from_slice(&[0xDB, 0x67]); // Magic "DBg"
        buffer.extend_from_slice(&(symbols.len() as u16).to_le_bytes());

        for (index, name) in symbols {
            let name_bytes = name.as_bytes();
            buffer.extend_from_slice(&index.to_le_bytes());
            buffer.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buffer.extend_from_slice(name_bytes);
        }
    }

    pub fn compile(&mut self, source: &str) -> Result<Vec<u32>, CompilerError> {
        let (program, parse_errors) = achronyme_parser::parse_program(source);
        // Only reject actual errors, not warnings (W008, W010, etc.)
        if let Some(err) = parse_errors
            .iter()
            .find(|d| d.severity == achronyme_parser::Severity::Error)
        {
            return Err(CompilerError::DiagnosticError(Box::new(err.clone())));
        }
        // Collect parser warnings into our warning list
        for diag in parse_errors {
            if diag.severity == achronyme_parser::Severity::Warning {
                self.warnings.push(diag);
            }
        }

        // Movimiento 2 Phase 3D — if no resolver state was
        // pre-installed (via `install_resolver_state`), try to build
        // one from the parsed root. Only kicks in for single-module
        // in-memory programs (no imports); anything more advanced
        // stays on the legacy path until Phase 3E wires the real
        // multi-module graph. Any failure is silent — the legacy
        // compilation path must not regress because of a resolver
        // hiccup.
        if self.resolved_program.is_none() {
            self.try_auto_build_resolver_state(&program);
        }

        let mut terminated = false;
        let mut unreachable_warned = false;
        for stmt in &program.stmts {
            if terminated && !unreachable_warned {
                if let Some(span) = stmt_span(stmt) {
                    self.emit_warning(
                        Diagnostic::warning("unreachable code", span.into()).with_code("W003"),
                    );
                }
                unreachable_warned = true;
            }
            self.compile_stmt(stmt)?;
            if !terminated && is_terminator(stmt) {
                terminated = true;
            }
        }

        // W005: unused selective imports
        for (name, (_path, span)) in &self.imported_names {
            if !self.used_imported_names.contains(name) && !name.starts_with('_') {
                self.warnings.push(
                    Diagnostic::warning(
                        format!("imported name `{name}` is never used"),
                        span.into(),
                    )
                    .with_code("W005"),
                );
            }
        }

        // Final return
        self.emit_abc(OpCode::Return, 0, 0, 0)?; // Return Nil/0

        let func = self.current()?;
        let (opt_bytecode, opt_line_info) = crate::optimizer::optimize(
            func.bytecode.clone(),
            func.line_info.clone(),
            &mut func.max_slots,
        );
        func.bytecode = opt_bytecode;
        func.line_info = opt_line_info;

        Ok(self.current()?.bytecode.clone())
    }
}

/// Returns true if a statement is a control-flow terminator (return, break, continue).
pub(crate) fn is_terminator(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return { .. } | Stmt::Break { .. } | Stmt::Continue { .. }
    )
}

/// Returns true if a program contains any top-level `import` /
/// `selective import`. Phase 3F gates multi-module auto-build on
/// the presence of `base_path`: in-memory compiles without a
/// filesystem root can't canonicalize transitive imports, so the
/// resolver state for such programs is silently skipped and the
/// legacy `fn_decl_asts` aggregation path handles dispatch.
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

#[cfg(test)]
mod tests;

