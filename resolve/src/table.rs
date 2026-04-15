//! The unified symbol table — the single source of truth for every name
//! both compilers can resolve.
//!
//! ## Phase 1 status
//!
//! This file ships the skeleton only:
//! - [`SymbolTable`] struct with the storage layout fixed.
//! - Empty constructor, lookup by qualified name, alias-chain resolver.
//! - Ownership of a [`BuiltinRegistry`] with audit integration.
//! - NO module graph walker, NO AST annotator, NO builtins installer —
//!   those land in Phase 3 and Phase 2 respectively.
//!
//! The Phase 1 entry point is [`SymbolTable::new`], which produces an
//! empty table wrapping an empty registry. Tests in this file verify the
//! storage invariants; Phase 2 onwards will add the real population
//! logic.

use crate::builtins::BuiltinRegistry;
use crate::error::ResolveError;
use crate::symbol::{CallableKind, SymbolId, FN_ALIAS_MAX_DEPTH};
use std::collections::HashMap;

/// The shared dispatch table. Holds every resolved symbol, plus the
/// builtin registry.
///
/// ## Ownership model
///
/// The table owns:
/// - The flat `symbols` vector, indexed by [`SymbolId`].
/// - The `by_qualified_name` map for O(1) name lookup.
/// - The `builtin_registry` (its entries are referenced by
///   [`CallableKind::Builtin::entry_index`]).
///
/// A [`SymbolTable`] is built once per compilation session by
/// `resolve::resolve()` (Phase 3) and then passed by reference to both
/// compilers. Neither compiler mutates the table.
#[derive(Debug, Default, Clone)]
pub struct SymbolTable {
    /// Flat storage of resolved symbols. A [`SymbolId`] is just an
    /// index into this vector.
    symbols: Vec<CallableKind>,

    /// Qualified-name → [`SymbolId`] mapping. Populated by the resolver
    /// pass as it walks module exports, imports, and builtin
    /// registrations.
    by_qualified_name: HashMap<String, SymbolId>,

    /// The single builtin registry, owned by the table so that audit
    /// happens at table build time and the entries are accessible via
    /// [`CallableKind::Builtin::entry_index`].
    builtin_registry: BuiltinRegistry,
}

impl SymbolTable {
    /// Construct an empty table with an empty registry. Phase 1 entry
    /// point; later phases will add a `build()` that takes a parsed
    /// `Program` and a `ModuleLoader`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a table from an already-built [`BuiltinRegistry`]. The
    /// registry is audited before being installed — if audit fails, the
    /// error is wrapped in [`ResolveError::BuiltinAudit`] and no table
    /// is produced.
    ///
    /// Phase 2 will call this from `BuiltinRegistry::default()` to
    /// install the production builtin set.
    pub fn with_registry(registry: BuiltinRegistry) -> Result<Self, ResolveError> {
        registry.audit().map_err(ResolveError::BuiltinAudit)?;
        Ok(Self {
            symbols: Vec::new(),
            by_qualified_name: HashMap::new(),
            builtin_registry: registry,
        })
    }

    /// Borrow the underlying builtin registry. Used by the audit tests
    /// and (starting in Phase 2) by the compilers to look up a
    /// [`CallableKind::Builtin`] entry by index.
    pub fn builtin_registry(&self) -> &BuiltinRegistry {
        &self.builtin_registry
    }

    /// How many symbols are in the table.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Is the table empty? (Phase 1 default state.)
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Insert a new symbol under a qualified name.
    ///
    /// Returns the fresh [`SymbolId`]. Panics if the name is already
    /// registered — a collision during table construction is a bug in
    /// the resolver pass, not a recoverable user error. Duplicate-name
    /// user errors are caught earlier by the import-resolution logic.
    ///
    /// Accepts anything convertible to `String`, so callers can pass
    /// `&str` literals or `String` builders without an explicit
    /// `.into()`.
    pub fn insert(&mut self, qualified_name: impl Into<String>, kind: CallableKind) -> SymbolId {
        let qualified_name = qualified_name.into();
        if self.by_qualified_name.contains_key(&qualified_name) {
            panic!(
                "SymbolTable::insert called with duplicate name `{qualified_name}` \
                 — the resolver pass should have rejected this earlier"
            );
        }
        let id = SymbolId(self.symbols.len() as u32);
        self.symbols.push(kind);
        self.by_qualified_name.insert(qualified_name, id);
        id
    }

    /// Look up a symbol by its fully qualified name.
    pub fn lookup(&self, qualified_name: &str) -> Option<SymbolId> {
        self.by_qualified_name.get(qualified_name).copied()
    }

    /// Borrow the [`CallableKind`] behind a [`SymbolId`].
    ///
    /// Panics (in debug) if the id is out of range — a non-recoverable
    /// logic bug. Release builds wrap the access with `get`.
    pub fn get(&self, id: SymbolId) -> &CallableKind {
        debug_assert!(
            (id.0 as usize) < self.symbols.len(),
            "SymbolId {id} out of range (len={})",
            self.symbols.len()
        );
        &self.symbols[id.0 as usize]
    }

    /// Fallible variant of [`SymbolTable::get`]. Returns `None` if the
    /// id is out of range or is the [`SymbolId::UNRESOLVED`] sentinel.
    pub fn try_get(&self, id: SymbolId) -> Option<&CallableKind> {
        if id == SymbolId::UNRESOLVED {
            return None;
        }
        self.symbols.get(id.0 as usize)
    }

    /// Iterate every `(SymbolId, &CallableKind)` pair in insertion
    /// order. Consumers that need to derive per-symbol metadata (e.g.
    /// Phase 3F's fn_table dispatch-key precomputation in the
    /// `compiler` crate) use this to walk the whole table without
    /// knowing which ids are valid.
    pub fn iter(&self) -> impl Iterator<Item = (SymbolId, &CallableKind)> + '_ {
        self.symbols
            .iter()
            .enumerate()
            .map(|(i, k)| (SymbolId(i as u32), k))
    }

    /// Follow a chain of [`CallableKind::FnAlias`] entries until a
    /// non-alias target is reached, a cycle is detected, or
    /// [`FN_ALIAS_MAX_DEPTH`] is exceeded.
    ///
    /// Returns the final non-alias [`SymbolId`] on success. Used by both
    /// compilers when dispatching through a `let a = p::fn` binding —
    /// see RFC §3.7.
    ///
    /// ## Cycle detection
    ///
    /// Catches **all** cycle shapes, not just self-references:
    /// - `A → A` (self-cycle)
    /// - `A → B → A` (two-hop cycle)
    /// - `A → B → C → A` (longer cycle)
    ///
    /// The walker tracks every visited [`SymbolId`] in a fixed-size
    /// stack buffer (capacity [`FN_ALIAS_MAX_DEPTH`], no allocation).
    /// If a visited id is encountered again, [`ResolveError::FnAliasCycle`]
    /// is returned with the hop count where the cycle was detected —
    /// never [`ResolveError::FnAliasDepthExceeded`], which is reserved
    /// for genuinely long non-cyclic chains.
    pub fn resolve_alias(&self, start: SymbolId) -> Result<SymbolId, ResolveError> {
        // Fixed-size visited buffer: no allocation, bounded by the
        // depth cap. Array of Option<SymbolId> to keep SymbolId: Copy.
        // The loop variable `depth` doubles as the number of slots
        // already populated in `visited` — they increment together.
        let mut visited: [Option<SymbolId>; FN_ALIAS_MAX_DEPTH] = [None; FN_ALIAS_MAX_DEPTH];
        let mut current = start;
        for depth in 0..FN_ALIAS_MAX_DEPTH {
            // Cycle check: has `current` already been visited on this walk?
            if visited[..depth].contains(&Some(current)) {
                return Err(ResolveError::FnAliasCycle {
                    start: start.as_u32(),
                    depth,
                });
            }
            visited[depth] = Some(current);

            let kind = self.try_get(current).ok_or(ResolveError::InvalidSymbolId {
                id: current.as_u32(),
            })?;
            match kind {
                CallableKind::FnAlias { target } => {
                    current = *target;
                }
                _ => return Ok(current),
            }
        }
        Err(ResolveError::FnAliasDepthExceeded {
            start: start.as_u32(),
            max_depth: FN_ALIAS_MAX_DEPTH,
        })
    }

    /// Audit the whole table. Runs the registry audit plus any
    /// table-level invariants (currently: every
    /// [`CallableKind::Builtin`]'s `entry_index` is in range).
    ///
    /// Called once at the end of `resolve()` (Phase 3) — never during
    /// normal compilation.
    pub fn audit(&self) -> Result<(), ResolveError> {
        self.builtin_registry
            .audit()
            .map_err(ResolveError::BuiltinAudit)?;

        let registry_len = self.builtin_registry.len();
        for (idx, kind) in self.symbols.iter().enumerate() {
            if let CallableKind::Builtin { entry_index } = kind {
                if *entry_index >= registry_len {
                    return Err(ResolveError::BuiltinIndexOutOfRange {
                        symbol_id: idx as u32,
                        entry_index: *entry_index,
                        registry_len,
                    });
                }
            }
        }

        // Validate every FnAlias chain terminates — run resolve_alias on
        // each alias symbol. Catches chains that reference missing slots,
        // self-cycles, and multi-hop cycles at table-build time instead
        // of waiting for a user-facing dispatch failure.
        for (idx, kind) in self.symbols.iter().enumerate() {
            if matches!(kind, CallableKind::FnAlias { .. }) {
                self.resolve_alias(SymbolId(idx as u32))?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtins::{BuiltinAuditError, BuiltinEntry, ProveIrLowerHandle, VmFnHandle};
    use crate::symbol::{Arity, Availability, ConstKind};

    #[test]
    fn empty_table() {
        let t = SymbolTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert!(t.lookup("anything").is_none());
        assert!(t.audit().is_ok());
    }

    #[test]
    fn insert_and_lookup() {
        let mut t = SymbolTable::new();
        let id = t.insert(
            "math::PI",
            CallableKind::Constant {
                qualified_name: "math::PI".into(),
                const_kind: ConstKind::Int,
                value_handle: 0,
            },
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t.lookup("math::PI"), Some(id));
        assert!(matches!(t.get(id), CallableKind::Constant { .. }));
    }

    #[test]
    #[should_panic(expected = "duplicate name")]
    fn duplicate_insert_panics() {
        let mut t = SymbolTable::new();
        t.insert(
            "x",
            CallableKind::Constant {
                qualified_name: "x".into(),
                const_kind: ConstKind::Int,
                value_handle: 0,
            },
        );
        t.insert(
            "x",
            CallableKind::Constant {
                qualified_name: "x".into(),
                const_kind: ConstKind::Field,
                value_handle: 0,
            },
        );
    }

    #[test]
    fn alias_chain_follows_to_target() {
        let mut t = SymbolTable::new();
        // base: a UserFn
        let base = t.insert(
            "p::add",
            CallableKind::UserFn {
                qualified_name: "p::add".into(),
                module: crate::module_graph::ModuleId::from_raw(0),
                stmt_index: 0,
                availability: Availability::Both,
            },
        );
        // first alias: a → p::add
        let a = t.insert("a", CallableKind::FnAlias { target: base });
        // second alias: b → a
        let b = t.insert("b", CallableKind::FnAlias { target: a });

        assert_eq!(t.resolve_alias(base).unwrap(), base);
        assert_eq!(t.resolve_alias(a).unwrap(), base);
        assert_eq!(t.resolve_alias(b).unwrap(), base);
    }

    #[test]
    fn alias_self_cycle_is_detected() {
        let mut t = SymbolTable::new();
        // The first insert gets SymbolId(0), so pointing at SymbolId(0)
        // from inside the same insert creates a self-cycle.
        let id = t.insert(
            "loop",
            CallableKind::FnAlias {
                target: SymbolId(0),
            },
        );
        let err = t.resolve_alias(id).unwrap_err();
        assert!(matches!(err, ResolveError::FnAliasCycle { .. }));
    }

    #[test]
    fn alias_two_hop_cycle_is_detected_as_cycle() {
        // A → B → A must produce FnAliasCycle, not FnAliasDepthExceeded.
        // This is the correctness fix for the hardening audit: earlier
        // versions only caught self-cycles and fell through to the
        // depth-exceeded error for multi-hop cycles, giving users a
        // misleading "max depth 16" message when the real problem was
        // a 2-hop loop.
        let mut t = SymbolTable::new();
        // A = slot 0 points at slot 1 (B)
        let a = t.insert(
            "a",
            CallableKind::FnAlias {
                target: SymbolId(1),
            },
        );
        // B = slot 1 points back at slot 0 (A)
        let b = t.insert("b", CallableKind::FnAlias { target: a });

        let err = t.resolve_alias(a).unwrap_err();
        assert!(
            matches!(err, ResolveError::FnAliasCycle { .. }),
            "expected FnAliasCycle, got {err:?}"
        );
        // Also verify the cycle is caught regardless of entry point.
        let err = t.resolve_alias(b).unwrap_err();
        assert!(matches!(err, ResolveError::FnAliasCycle { .. }));
    }

    #[test]
    fn alias_three_hop_cycle_is_detected_as_cycle() {
        // A → B → C → A, another non-self cycle shape.
        let mut t = SymbolTable::new();
        let a = t.insert(
            "a",
            CallableKind::FnAlias {
                target: SymbolId(1),
            },
        );
        let _b = t.insert(
            "b",
            CallableKind::FnAlias {
                target: SymbolId(2),
            },
        );
        let _c = t.insert("c", CallableKind::FnAlias { target: a });

        let err = t.resolve_alias(a).unwrap_err();
        assert!(matches!(err, ResolveError::FnAliasCycle { .. }));
    }

    #[test]
    fn alias_depth_exceeded_is_detected() {
        // Build a chain of 20 aliases — longer than FN_ALIAS_MAX_DEPTH.
        // We populate `symbols` directly since the chain needs forward
        // references that `insert` can't express.
        let mut t = SymbolTable::new();
        for i in 0u32..20 {
            t.symbols.push(CallableKind::FnAlias {
                target: SymbolId(i + 1),
            });
            t.by_qualified_name
                .insert(format!("alias_{i}"), SymbolId(i));
        }
        // Slot 20 doesn't exist — the walker should error out on
        // depth exceed before hitting the out-of-range access because
        // FN_ALIAS_MAX_DEPTH (16) < 20.
        let err = t.resolve_alias(SymbolId(0)).unwrap_err();
        assert!(matches!(err, ResolveError::FnAliasDepthExceeded { .. }));
    }

    #[test]
    fn with_registry_runs_audit() {
        let mut reg = BuiltinRegistry::new();
        reg.push(BuiltinEntry {
            name: "broken",
            arity: Arity::Fixed(1),
            availability: Availability::Both,
            // Missing vm_fn — should fail audit
            vm_fn: None,
            prove_ir_lower: Some(ProveIrLowerHandle::PLACEHOLDER),
        });
        let result = SymbolTable::with_registry(reg);
        assert!(matches!(
            result,
            Err(ResolveError::BuiltinAudit(
                BuiltinAuditError::BothMissingVm { .. }
            ))
        ));
    }

    #[test]
    fn valid_registry_builds_table() {
        let mut reg = BuiltinRegistry::new();
        reg.push(BuiltinEntry {
            name: "poseidon",
            arity: Arity::Fixed(2),
            availability: Availability::Both,
            vm_fn: Some(VmFnHandle::PLACEHOLDER),
            prove_ir_lower: Some(ProveIrLowerHandle::PLACEHOLDER),
        });
        let t = SymbolTable::with_registry(reg).unwrap();
        assert!(t.audit().is_ok());
        assert_eq!(t.builtin_registry().len(), 1);
    }

    #[test]
    fn builtin_index_out_of_range_rejected_by_audit() {
        // Use an explicit empty registry — the default() registry is
        // populated with production builtins, so any index in [0, 21)
        // would be valid. We need a table where *every* index is out
        // of range.
        let mut t = SymbolTable::with_registry(BuiltinRegistry::new()).unwrap();
        t.insert("ghost", CallableKind::Builtin { entry_index: 0 });
        let err = t.audit().unwrap_err();
        assert!(matches!(err, ResolveError::BuiltinIndexOutOfRange { .. }));
    }
}
