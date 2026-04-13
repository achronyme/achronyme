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
use std::fmt;

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
