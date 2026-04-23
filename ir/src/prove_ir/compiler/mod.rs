//! ProveIR compiler: AST Block → ProveIR template.
//!
//! Originally a single 6,747-LOC file; split per-concern in audit
//! gap §2.11 #1. The submodules each contribute one or more
//! `impl<F: FieldBackend> ProveIrCompiler<F> { ... }` blocks; this
//! file owns the type definitions and struct that they share.
//!
//! ## Submodules
//!
//! - [`api`] — public entry points (`compile`, `compile_with_trace`,
//!   `compile_circuit`, `compile_prove_block`, plus the internal
//!   `compile_into_instance` backbone).
//! - [`state`] — constructor + resolver-hit tracking + Circom template
//!   registration.
//! - [`stmts`] — 16 statement walkers (`compile_block_stmts`,
//!   `compile_stmt`, declarations, assignments, imports, ...).
//! - [`exprs`] — 17 expression compilers (`compile_expr` dispatch,
//!   atoms, control flow, user-fn inlining, arith/bool/comparison).
//! - [`calls`] — 21 call-dispatch + builtin-lowering methods (Circom
//!   integration, M2 annotation dispatch, per-builtin lowering).
//! - [`methods`] — 11 dot-access + method-call helpers (arity checks,
//!   assert message extraction, len() carve-out).
//! - [`helpers`] — 4 free utilities (`program_to_block`,
//!   `flat_index_suffix`, `to_span`, `annotation_to_ir_type`).
//! - [`tests`] — 159 tests (only compiled under `#[cfg(test)]`).
//!
//! Cross-submodule calls go through `pub(super)` visibility; the
//! struct fields are also `pub(super)` so each concern can read +
//! mutate the shared compiler state.

mod api;
mod calls;
mod exprs;
mod helpers;
mod methods;
mod state;
mod stmts;

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use achronyme_parser::ast::*;
use memory::{Bn254Fr, FieldBackend};

use super::types::*;
use ir_forge::CircomCallable;

use resolve::{
    AnnotationKey, Availability, ModuleId, ResolvedProgram, ResolverState, SymbolId, SymbolTable,
};

// ---------------------------------------------------------------------------
// Environment values
// ---------------------------------------------------------------------------

/// A value in the ProveIR compilation environment.
#[derive(Clone, Debug)]
enum CompEnvValue {
    /// A local scalar variable (let-binding or input).
    Scalar(String),
    /// A local array variable.
    Array(Vec<String>),
    /// A captured value from the outer scope.
    Capture(String),
}

/// Type information for a variable in the outer (VM) scope.
///
/// Used by the bytecode compiler to tell the ProveIR compiler which
/// outer-scope names are arrays and their sizes. Not serialized.
#[derive(Clone, Debug)]
pub enum OuterScopeEntry {
    Scalar,
    Array(usize),
}

/// Everything the enclosing scope makes available to a prove/circuit block.
///
/// `values` carries captured scalars and arrays from the VM scope.
/// `functions` carries FnDecl AST nodes that should be registered in the
/// ProveIR compiler's `fn_table` before the block body is compiled, so
/// that user-defined functions from the outer scope can be inlined.
/// `circom_imports` carries circom template handles — keyed by their
/// lookup name inside the block (bare template name for selective
/// imports, `"P::T"` for namespaced ones). The `compiler` crate is
/// responsible for flattening namespace imports into `P::T` keys
/// before handing the scope over.
///
/// `resolver_state` (Movimiento 2 Phase 3E) forwards the VM compiler's
/// already-built [`ResolvedProgram`] + [`SymbolTable`] + root
/// [`ModuleId`]. When present, the ProveIR compiler uses it to record
/// shadow resolver hits alongside its own dispatch. The legacy
/// `fn_table`/`env` lookup remains authoritative in 3E.1; Phase
/// 3E.2/3 is where dispatch actually reads from annotations.
#[derive(Clone, Debug, Default)]
pub struct OuterScope {
    /// Captured values (scalars / arrays) from the VM scope.
    pub values: HashMap<String, OuterScopeEntry>,
    /// Function declarations to register in fn_table before compilation.
    pub functions: Vec<Stmt>,
    /// Circom templates importable into this block. Keys are the
    /// names the ProveIR dispatcher will look up at Call time.
    pub circom_imports: HashMap<String, CircomCallable>,
    /// Optional resolver state forwarded from the caller. None
    /// means "standalone compile" — the ProveIR compiler will
    /// either run without resolver observation, or (future work)
    /// build its own state.
    pub resolver_state: Option<OuterResolverState>,
}

/// Borrow-free bundle of resolver state for prove-block outer scope.
///
/// The VM compiler stores these three pieces in separate `Option`
/// fields; for the prove-block hand-off we repackage them into a
/// single [`Arc`]-shared struct so cloning `OuterScope` is free
/// regardless of how big the symbol table grows. The VM compiler
/// moves its own state into `Arc`s at the hand-off point (see
/// `compile_prove` in the `compiler` crate).
///
/// [`SymbolTable`] and [`ResolvedProgram`] are not `Clone`
/// themselves — the `Arc` indirection is therefore mandatory, not
/// a premature optimisation.
#[derive(Clone, Debug)]
pub struct OuterResolverState {
    /// Symbol table shared by the VM + ProveIR compilers.
    pub table: std::sync::Arc<SymbolTable>,
    /// Annotation map keyed by `(module_id, expr_id)`.
    pub resolved: std::sync::Arc<ResolvedProgram>,
    /// Root module id in the graph the annotations were built for.
    pub root_module: ModuleId,
    /// Phase 3F: precomputed map from [`SymbolId`] to the fn_table
    /// key the ProveIR compiler uses. Built once at auto-build
    /// time by walking the resolver's [`SymbolTable`] + module
    /// graph edges (see `compiler::build_dispatch_maps`).
    /// Consumed by [`resolve_dispatch_via_annotation`] to translate
    /// resolved user-fn annotations into fn_table lookups without
    /// parsing the resolver's name-mangling convention at dispatch
    /// time. Empty when the compile had no multi-module state —
    /// e.g. single-module programs whose only user fns are root
    /// and need no alias prefix.
    pub dispatch_key_by_symbol: std::sync::Arc<HashMap<SymbolId, String>>,
    /// Phase 3F inverse of [`dispatch_key_by_symbol`]: fn_table key
    /// to the owning [`ModuleId`]. Consumed by
    /// [`ProveIrCompiler::compile_user_fn_call`] to push the
    /// definer's module onto the resolver stack before inlining
    /// the body — the structural half of the gap 2.4 fix. Both
    /// the annotation path and the legacy StaticAccess path go
    /// through this, so every inlined body correctly resolves
    /// bare identifiers against the definer's scope.
    pub module_by_dispatch_key: std::sync::Arc<HashMap<String, ModuleId>>,
    /// Phase 4: fn_table key → [`Availability`] for every user function.
    /// `compile_user_fn_call` checks this to reject inlining of
    /// Vm-only functions inside prove blocks.
    pub availability_by_key: std::sync::Arc<HashMap<String, Availability>>,
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

/// A user-defined function stored for inlining.
#[derive(Clone, Debug)]
struct FnDef {
    params: Vec<TypedParam>,
    body: Block,
    #[allow(dead_code)]
    return_type: Option<TypeAnnotation>,
    /// Owning module id — used for resolver module stack push in
    /// `compile_user_fn_call` so bare identifiers inside the inlined
    /// body resolve against the definer's scope. `None` for functions
    /// defined locally inside a prove/circuit block.
    owner_module: Option<ModuleId>,
    /// Availability of this function (Phase 4). `None` for locally
    /// defined functions or when resolver state is not installed.
    /// `compile_user_fn_call` checks this to reject Vm-only functions.
    availability: Option<Availability>,
}

/// The annotation-driven dispatch choice for a call site.
///
/// Returned by [`ProveIrCompiler::resolve_dispatch_via_annotation`].
/// `Builtin` dispatches via [`ProveIrLowerHandle`] into the lowering
/// table; `UserFn` carries the fn_table key for inlining. The legacy
/// name-based path in [`compile_named_call`] handles the
/// `NoAnnotation` fallback.
pub(super) enum DispatchDecision {
    Builtin {
        handle: resolve::builtins::ProveIrLowerHandle,
    },
    UserFn {
        qualified_name: String,
    },
    NoAnnotation,
}

/// Phase 3G: the full bundle of resolver state a standalone
/// [`ProveIrCompiler::compile_circuit`] invocation uses.
///
/// Built by [`ProveIrCompiler::try_build_circuit_resolver_state`]
/// from the parsed source + source directory. Short-circuits to
/// `None` on any build error so the caller can fall back to the
/// legacy path. The fields are consumed twice: once by
/// [`ProveIrCompiler::outer_functions_from_graph`] to derive
/// renamed [`Stmt::FnDecl`] entries for the fn_table population,
/// and once by the `OuterResolverState` constructor so the
/// ProveIR compiler's annotation-driven dispatch can flip.
pub(super) struct CircuitResolverBundle {
    state: ResolverState,
    dispatch_by_symbol: HashMap<SymbolId, String>,
    module_by_key: HashMap<String, ModuleId>,
}

/// Compiles an AST `Block` (from a prove block or circuit file) into a `ProveIR`.
pub struct ProveIrCompiler<F: FieldBackend = Bn254Fr> {
    /// Maps variable names → what they resolve to.
    env: HashMap<String, CompEnvValue>,
    /// Mutable variable SSA versioning: original_name → current version number.
    /// A name in this map means it was declared with `mut`.
    ssa_versions: HashMap<String, u32>,
    /// Tracks which names are captured from the outer scope.
    captured_names: HashSet<String>,
    /// Functions available for inlining.
    fn_table: HashMap<String, FnDef>,
    /// Recursion guard: functions currently being inlined.
    call_stack: HashSet<String>,
    /// Monotonic counter for unique function inlining names.
    inline_counter: u32,
    /// Accumulated circuit body nodes.
    body: Vec<CircuitNode>,
    /// Public input declarations.
    public_inputs: Vec<ProveInputDecl>,
    /// Witness input declarations.
    witness_inputs: Vec<ProveInputDecl>,
    /// Directory of the source file being compiled (for resolving relative imports).
    source_dir: Option<std::path::PathBuf>,
    /// Module loader for resolving imports (shared across recursive loads).
    module_loader: crate::module_loader::ModuleLoader,
    /// Tracks modules currently being compiled (for circular import detection).
    compiling_modules: HashSet<std::path::PathBuf>,
    /// Flat table of circom templates callable from this block, keyed
    /// by the name the dispatcher looks up (bare template name for
    /// selective imports, `"P::T"` for namespace imports). Populated
    /// by `register_circom_template` — typically seeded from
    /// [`OuterScope::circom_imports`] before `compile_block_stmts`.
    circom_table: HashMap<String, CircomCallable>,
    /// Monotonic counter used to allocate unique prefixes
    /// (`circom_call_0`, `circom_call_1`, ...) for circom template
    /// instantiations. Bumped on use, not on registration.
    circom_call_counter: usize,
    // ── Movimiento 2 Phase 3E ────────────────────────────────────
    /// Optional resolver state forwarded from the outer (VM)
    /// compiler via [`OuterScope::resolver_state`]. Installed at
    /// the start of `compile_with_source_dir`. When `None`, every
    /// resolver-shadow hook is a no-op (single-module prove blocks
    /// compiled without a pre-built resolver state).
    resolver_table: Option<std::sync::Arc<SymbolTable>>,
    /// Annotation map mirroring [`resolver_table`]; see the
    /// `compiler` crate's [`Compiler::resolved_program`] doc for
    /// the key semantics.
    resolver_resolved: Option<std::sync::Arc<ResolvedProgram>>,
    /// The [`ModuleId`] annotations are currently being resolved
    /// against when the stack is empty. Installed from
    /// `OuterScope::resolver_state.root_module` at compile-start.
    resolver_root_module: Option<ModuleId>,
    /// Stack of module ids that should override
    /// [`resolver_root_module`] while walking inlined user-fn
    /// bodies. Phase 3E.3 / 3F structural fix for gap 2.4: every
    /// [`compile_user_fn_call`] looks up its fn_table key in
    /// [`resolver_module_by_key`] and, if present, pushes the
    /// discovered [`ModuleId`] before compiling the inlined body
    /// and pops on exit. The stack top is consulted by every
    /// annotation lookup during the walk so that bare identifiers
    /// inside the inlined body resolve against the definer's
    /// scope, not the caller's.
    resolver_module_stack: Vec<ModuleId>,
    /// Reverse index from [`SymbolId`] to fn_table key, built during
    /// fn_table registration from the dispatch maps in
    /// [`OuterResolverState`]. Consumed by
    /// [`resolve_dispatch_via_annotation`] to translate a resolved
    /// user-fn annotation into the fn_table key.
    fn_symbol_index: HashMap<SymbolId, String>,
    /// Phase 3E shadow hit trace: every `(module_id, expr_id)` the
    /// annotation table resolved to a [`SymbolId`] during the walk.
    /// Populated by [`record_resolver_hit`]; consumed by tests
    /// under `ir/tests/prove_ir_resolver_dispatch.rs`. Clears per
    /// compile invocation.
    resolver_hits: Vec<(AnnotationKey, SymbolId)>,
    /// The id of the [`Expr`] currently being walked, set at the
    /// top of [`compile_expr`]. Pairs with
    /// [`resolver_root_module`] to form the annotation lookup key.
    /// `None` outside expression contexts.
    current_expr_id: Option<ExprId>,
    /// Phantom data for the field backend type parameter.
    _field: PhantomData<F>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
