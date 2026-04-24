//! [`ResolveError`] — every failure the resolver can produce.
//!
//! Phase 1 ships the structural variants (audit failures, table-invariant
//! violations). Phase 3 will add the AST-annotation variants (undefined
//! symbol, ambiguous resolution, [`ProveBlockUnsupportedShape`], etc.).
//!
//! These errors are **resolver errors** — they represent bugs in either
//! the registry construction (audit failures) or in user source code
//! (undefined symbol, unsupported shape). They are NOT
//! [`BuiltinAuditError`] — that type is wrapped inside
//! [`ResolveError::BuiltinAudit`] so callers only need to match on
//! [`ResolveError`].

use crate::builtins::BuiltinAuditError;
use achronyme_parser::ast::Span;
use std::fmt;
use std::path::PathBuf;

/// Why a particular construct is unsupported inside a `prove {}` /
/// `circuit {}` block. Prove blocks compile to constraint systems,
/// which cannot express dynamic dispatch, runtime map lookups, or
/// method chains that aren't known at resolve time. Each variant
/// names a specific shape that works in VM mode but fails in prove
/// mode — surfaced eagerly by the resolver pass so users get a clean
/// error instead of a deep lowering panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedShape {
    /// `let a = if cond { f } else { g }; a()` — the callable bound
    /// by `a` is chosen at runtime, so the constraint system can't
    /// fix a single target.
    DynamicFnValue,
    /// `p::map.element` or `m[key]` inside a prove block, where the
    /// object is a runtime map/struct rather than a namespace import.
    RuntimeMapAccess,
    /// `expr.method()` where `method` is a user fn looked up at
    /// runtime on `expr`, not a static namespace call or a builtin.
    RuntimeMethodChain,
    /// `f(if cond { g } else { h })` — a function argument that is
    /// itself a dynamic fn value. Resolves at VM runtime via
    /// closures; prove mode needs a single known target.
    NonStaticFnArg,
}

impl UnsupportedShape {
    /// Short human label used in diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::DynamicFnValue => "dynamic fn value",
            Self::RuntimeMapAccess => "runtime map access",
            Self::RuntimeMethodChain => "runtime method chain",
            Self::NonStaticFnArg => "non-static fn argument",
        }
    }
}

impl fmt::Display for UnsupportedShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Every failure mode the resolver can produce.
///
/// Phase 1 covers just the structural failures; Phase 3 will extend this
/// enum with the AST-annotation failures (undefined symbol, ambiguous
/// qualified name, unsupported shape inside a prove block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// The [`BuiltinRegistry`](crate::builtins::BuiltinRegistry) failed
    /// its [`audit`](crate::builtins::BuiltinRegistry::audit) — a
    /// registered builtin violates one of the availability invariants.
    /// This is a build-time bug, never a user error.
    BuiltinAudit(BuiltinAuditError),

    /// A [`SymbolId`](crate::symbol::SymbolId) referenced at lookup time
    /// does not correspond to any slot in the
    /// [`SymbolTable`](crate::table::SymbolTable). Indicates a resolver
    /// bug: every id the table produces should be valid for the
    /// lifetime of the table.
    InvalidSymbolId {
        /// The offending raw id.
        id: u32,
    },

    /// A [`CallableKind::FnAlias`](crate::symbol::CallableKind::FnAlias)
    /// chain loops back on itself before reaching a non-alias target.
    /// Rare — can only happen if the resolver constructs the chain
    /// incorrectly (e.g., patches an alias to point at itself).
    FnAliasCycle {
        /// The [`SymbolId`](crate::symbol::SymbolId) from which resolution
        /// started.
        start: u32,
        /// How many hops before the cycle was detected.
        depth: usize,
    },

    /// A [`CallableKind::FnAlias`](crate::symbol::CallableKind::FnAlias)
    /// chain is longer than
    /// [`FN_ALIAS_MAX_DEPTH`](crate::symbol::FN_ALIAS_MAX_DEPTH). Almost
    /// always a mistake (real chains are length 1-2).
    FnAliasDepthExceeded {
        /// The [`SymbolId`](crate::symbol::SymbolId) from which resolution
        /// started.
        start: u32,
        /// The configured maximum depth.
        max_depth: usize,
    },

    /// A [`CallableKind::Builtin`](crate::symbol::CallableKind::Builtin)
    /// symbol points at an out-of-range registry entry index. Indicates
    /// the registry was mutated after being handed to the table, or the
    /// resolver pass constructed a [`SymbolId`](crate::symbol::SymbolId)
    /// before the registry was populated.
    BuiltinIndexOutOfRange {
        /// The symbol that carries the bad index.
        symbol_id: u32,
        /// The entry index it claims to reference.
        entry_index: usize,
        /// How many entries the registry actually has.
        registry_len: usize,
    },

    // ----- Phase 3B: module graph builder -----
    /// A relative module path could not be resolved to a canonical
    /// filesystem key. Typically wraps a "file not found" error from
    /// the underlying
    /// [`ModuleSource`](crate::module_graph::ModuleSource). `importer`
    /// is the canonical path of the file that contained the failing
    /// `import` statement, or `None` if the failure occurred while
    /// resolving the graph root.
    ModuleCanonicalizeFailed {
        /// The raw relative path from the `import` statement.
        relative: String,
        /// The canonical path of the file whose `import` failed.
        importer: Option<PathBuf>,
        /// Reason reported by the `ModuleSource` adapter.
        reason: String,
    },

    /// The [`ModuleSource`](crate::module_graph::ModuleSource) adapter
    /// refused to produce a parsed AST for a canonicalized path.
    /// Usually caused by I/O or parse errors inside the backing loader.
    ModuleLoadFailed {
        /// Canonical path the resolver was trying to load.
        path: PathBuf,
        /// Reason reported by the underlying loader.
        reason: String,
    },

    /// A module imports itself (directly or transitively) while the
    /// graph builder is still descending its DFS stack — i.e. a true
    /// cycle, not a diamond re-use. Matches the semantics of the legacy
    /// `CircularImport` error in `akronc::CompilerError`; Phase 6
    /// cleanup will collapse the two into this one.
    ModuleCycle {
        /// Canonical path of the module that completed the cycle.
        path: PathBuf,
    },

    /// A module declares two top-level symbols with the same name —
    /// usually two `fn foo` / `let foo` declarations in the same file,
    /// or a `fn foo` colliding with an `export let foo`. Surfaced by
    /// [`register_module`](crate::annotate::register_module) during
    /// Phase 3C.1; Phase 3E may extend this to catch cross-module
    /// aliasing collisions when the importer's namespace merges.
    DuplicateModuleSymbol {
        /// Unqualified name that collided (the
        /// [`SymbolTable`](crate::table::SymbolTable) key would be
        /// `"{alias}::{name}"` or just `"{name}"` for the root module).
        name: String,
        /// Module that contained both declarations.
        module: u32,
    },

    // ----- Phase 3C.3: prove-block shape diagnostics -----
    /// A construct inside a `prove {}` / `circuit {}` block uses a
    /// shape that resolves in VM mode but cannot be lowered to
    /// constraints. Emitted by the annotate pass
    /// ([`annotate_program`](crate::annotate::annotate_program))
    /// before any lowering runs, so users get a clean early error
    /// instead of a deep panic during IR emission. The
    /// [`UnsupportedShape`] variant identifies which rule fired; the
    /// `reason` field carries a short English-language phrase for
    /// the diagnostic's `note:` line.
    ProveBlockUnsupportedShape {
        /// Source span of the offending construct.
        span: Span,
        /// Which of the four supported-shape rules fired.
        shape: UnsupportedShape,
        /// Short explanation rendered next to the diagnostic. Phase
        /// 3D/3E will wrap this inside a full diagnostic with a
        /// "help" suggestion; 3C.3 stores the reason only.
        reason: &'static str,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltinAudit(inner) => write!(f, "builtin audit failed: {inner}"),
            Self::InvalidSymbolId { id } => write!(
                f,
                "invalid SymbolId {id} — no such entry in the symbol table"
            ),
            Self::FnAliasCycle { start, depth } => write!(
                f,
                "FnAlias chain starting at sym#{start} loops back on itself \
                 after {depth} hop(s)"
            ),
            Self::FnAliasDepthExceeded { start, max_depth } => write!(
                f,
                "FnAlias chain starting at sym#{start} exceeds the maximum \
                 depth of {max_depth}"
            ),
            Self::BuiltinIndexOutOfRange {
                symbol_id,
                entry_index,
                registry_len,
            } => write!(
                f,
                "sym#{symbol_id} references builtin entry {entry_index} but \
                 the registry only has {registry_len} entries"
            ),
            Self::ModuleCanonicalizeFailed {
                relative,
                importer,
                reason,
            } => {
                if let Some(importer) = importer {
                    write!(
                        f,
                        "cannot resolve `import \"{relative}\"` from {}: {reason}",
                        importer.display()
                    )
                } else {
                    write!(f, "cannot resolve root module `{relative}`: {reason}")
                }
            }
            Self::ModuleLoadFailed { path, reason } => {
                write!(f, "failed to load {}: {reason}", path.display())
            }
            Self::ModuleCycle { path } => write!(f, "circular import detected: {}", path.display()),
            Self::DuplicateModuleSymbol { name, module } => {
                write!(f, "module {module} declares `{name}` more than once")
            }
            Self::ProveBlockUnsupportedShape { shape, reason, .. } => {
                write!(f, "{shape} not supported inside a prove block: {reason}")
            }
        }
    }
}

impl std::error::Error for ResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BuiltinAudit(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<BuiltinAuditError> for ResolveError {
    fn from(err: BuiltinAuditError) -> Self {
        Self::BuiltinAudit(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_inner_audit_error() {
        let err = ResolveError::BuiltinAudit(BuiltinAuditError::BothMissingVm { name: "mux" });
        let rendered = format!("{err}");
        assert!(rendered.contains("builtin audit failed"));
        assert!(rendered.contains("mux"));
    }

    #[test]
    fn from_conversion_preserves_variant() {
        let audit = BuiltinAuditError::DuplicateName { name: "dup" };
        let resolve: ResolveError = audit.clone().into();
        assert_eq!(resolve, ResolveError::BuiltinAudit(audit));
    }

    #[test]
    fn source_chain() {
        let err = ResolveError::BuiltinAudit(BuiltinAuditError::VmMissingImpl { name: "print" });
        assert!(std::error::Error::source(&err).is_some());

        let err = ResolveError::InvalidSymbolId { id: 42 };
        assert!(std::error::Error::source(&err).is_none());
    }
}
