//! # Resolve — Unified dispatch resolver for Achronyme
//!
//! This crate implements the shared symbol table consulted by both the VM
//! bytecode compiler (`compiler/`) and the ProveIR compiler
//! (`ir/src/prove_ir/`). It is the backbone of Movimiento 2 — the refactor
//! that eliminates the two-table divergence problem where a name could
//! resolve in one backend but fail in the other.
//!
//! ## What lives here
//!
//! - [`symbol`] — the core data types: [`SymbolId`], [`CallableKind`],
//!   [`Availability`], [`Arity`]. One [`SymbolId`] per resolvable name.
//! - [`builtins`] — [`BuiltinRegistry`] and [`BuiltinEntry`]. The single
//!   source of truth for every builtin in the language, with an
//!   [`Availability`] marker that the audit step enforces at build time.
//! - [`table`] — [`SymbolTable`] and its query API. Both compilers read
//!   from it after the resolver pass annotates the AST with
//!   [`SymbolId`]s.
//! - [`statics`] — the const array of static members (`Int::MAX`,
//!   `Field::ZERO`, etc.). Consulted by both compilers; currently a stub
//!   to be populated in Phase 6.
//! - [`error`] — [`ResolveError`] with the diagnostic variants the
//!   resolver pass can emit.
//!
//! ## What does NOT live here (yet)
//!
//! - The resolver pass itself (walks the AST annotating expressions with
//!   [`SymbolId`]s). Landing in Phase 3C.
//! - The builtin entries themselves. Landing in Phase 2.
//!
//! The module graph builder ([`module_graph`]) landed in Phase 3B.
//!
//! ## Movimiento 2 roadmap
//!
//! The refactor lands in six phases (0–6). This crate is part of the
//! backbone added in Phase 1 onward. The **authoritative phase status**
//! lives in `.claude/plans/movimiento-2-unified-dispatch.md` — that's
//! the RFC. The phase sequence is:
//!
//! - **Phase 0** — extract `lower_builtin` in `ir/src/prove_ir/compiler.rs`.
//! - **Phase 1** — this crate's skeleton: types + empty registry + audit.
//! - **Phase 2** — populate [`BuiltinRegistry::default()`] and wire both
//!   compilers to read from it.
//! - **Phase 3** — resolver pass + [`SymbolId`] annotation on the AST.
//! - **Phase 4** — lazy compilation driven by reachability + [`Availability`].
//! - **Phase 5** — `ConstExpr` surfacing for template args.
//! - **Phase 6** — registry-driven dispatch (`NATIVE_TABLE` deleted),
//!   `FnDef` enrichment, graph-derived outer functions.
//!
//! Do not edit "current phase" markers here — they go stale. Consult
//! the RFC instead. This doc block describes the crate's *scope*, not
//! its *progress*.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod annotate;
pub mod availability;
pub mod build;
pub mod builtins;
pub mod const_eval;
pub mod error;
pub mod module_graph;
pub mod statics;
pub mod symbol;
pub mod table;

pub use annotate::{
    annotate_program, register_all, register_builtins, register_module, AnnotationKey,
    ResolvedProgram,
};
pub use availability::{infer_availability, AvailabilityResult, RestrictionReason};
pub use build::{
    build_availability_map, build_dispatch_maps, build_outer_functions, build_resolver_state,
    ResolverState,
};
pub use builtins::{BuiltinEntry, BuiltinRegistry};
pub use const_eval::{evaluate_constants, ConstValues};
pub use error::{ResolveError, UnsupportedShape};
pub use module_graph::{
    ImportEdge, ImportEdgeKind, LoadedModule, ModuleGraph, ModuleId, ModuleNode, ModuleSource,
};
pub use symbol::{Arity, Availability, CallableKind, SymbolId};
pub use table::SymbolTable;
