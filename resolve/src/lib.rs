//! # Resolve — Unified dispatch resolver for Achronyme
//!
//! This crate implements the shared symbol table consulted by both the VM
//! bytecode compiler (`compiler/`) and the ProveIR compiler
//! (`ir/src/prove_ir/`). It eliminates the two-table divergence problem
//! where a name could resolve in one backend but fail in the other.
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
//!   `Field::ZERO`, etc.). Consulted by both compilers.
//! - [`error`] — [`ResolveError`] with the diagnostic variants the
//!   resolver pass can emit.
//!
//! ## Scope
//!
//! This doc block describes the crate's *scope*, not its *progress*.
//! For historical context on how individual modules came to be, consult
//! `git log` and `git blame`.

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
