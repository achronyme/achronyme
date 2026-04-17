mod constructors;
mod diagnostics;
mod resolver_state;
mod wrappers;

use crate::error::CompilerError;
use crate::function_compiler::FunctionCompiler;
use crate::interner::{
    BigIntInterner, BytesInterner, CircomHandleInterner, CircomLibraryRegistry, FieldInterner,
    StringInterner,
};
use crate::module_loader::ModuleLoader;
use crate::statements::{stmt_span, StatementCompiler};
use achronyme_parser::ast::{ExprId, Span, Stmt};
use achronyme_parser::Diagnostic;
use resolve::{Availability, ModuleId, ResolvedProgram, SymbolId, SymbolTable};
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

impl Compiler {
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

#[cfg(test)]
mod tests;

