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
//!   [`SymbolId`]s). Landing in Phase 3.
//! - The module graph builder. Landing in Phase 3.
//! - The builtin entries themselves. Landing in Phase 2.
//!
//! ## Movimiento 2 phase status
//!
//! - **Phase 0** ✅ — extract `lower_builtin` in `ir/src/prove_ir/compiler.rs`.
//! - **Phase 1** ✅ (this commit) — crate skeleton: types + empty registry + audit tests.
//! - **Phase 2** — populate [`BuiltinRegistry::default()`]; both compilers
//!   read builtins from it.
//! - **Phase 3** — resolver pass + [`SymbolId`] annotation on the AST.
//! - **Phase 4** — lazy compilation driven by reachability + [`Availability`].
//! - **Phase 5** — `ConstExpr` surfacing for template args.
//! - **Phase 6** — final cleanup. `fn_table`, `global_symbols`, and
//!   `fn_decl_asts` are removed; statics unified in [`statics`].
//!
//! See `.claude/plans/movimiento-2-unified-dispatch.md` for the full RFC.

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod builtins;
pub mod error;
pub mod statics;
pub mod symbol;
pub mod table;

pub use builtins::{BuiltinEntry, BuiltinRegistry};
pub use error::ResolveError;
pub use symbol::{Arity, Availability, CallableKind, SymbolId};
pub use table::SymbolTable;
