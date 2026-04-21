//! Scoped capture environment for template bodies (RFC §6.4).
//!
//! The lowering pass maps **source names** (the `String` identifiers
//! carried on `SsaVar` / `ExtendedInstruction::TemplateCall.outputs`
//! bindings) to **register ids** (`u8` slots in the current frame).
//! When a template body opens a new scope, any bindings introduced
//! inside must die at `ExitScope`; otherwise per-iteration binding
//! trails would grow unbounded — the exact pathology RFC §1 calls
//! out as the cause of the 6.4 GB peak RSS on SHA-256(64).
//!
//! ## Design — "Tarjan-stack" semantics
//!
//! The map is backed by a flat append-only log plus a stack of scope
//! boundaries:
//!
//! - `entries: Vec<(K, V)>` — every `bind` appends to the tail.
//! - `scope_starts: Vec<usize>` — each entry is the `entries.len()`
//!   at the moment the corresponding `enter_scope` ran. `truncate`
//!   on exit restores the prior state in O(Δ).
//!
//! Lookup is a reverse linear scan. With the expected per-scope
//! binding count of a few dozen (captures + locals), this is cheaper
//! than maintaining a `HashMap<K, Vec<V>>` trail, and it keeps the
//! structure allocation-free between `enter_scope`/`exit_scope`
//! pairs that don't exceed the previous high-water mark — the common
//! case inside a rolled loop body.
//!
//! ## Invariants
//!
//! - Construction installs a root scope at index 0. Calling
//!   `exit_scope` on the root scope returns [`ScopedMapError::PopRoot`]
//!   instead of collapsing the structure.
//! - Shadowing inside a single scope is allowed — `lookup` returns
//!   the most recent binding. This tolerates the rare
//!   `let x = ...; let x = ...;` pattern the ProveIR compiler already
//!   emits.
//! - `enter_scope` / `exit_scope` must be paired by the caller. An
//!   imbalance is a lifter bug, not an end-user error.

use std::borrow::Borrow;
use std::hash::Hash;

/// Register index in a Lysis frame. Matches the `u8` slot width used
/// throughout the bytecode (see RFC §4.3, §6.2).
pub type RegId = u8;

/// Errors raised by [`ScopedMap`]. Only surfaces when the caller
/// misuses the API — the executor never sees one of these at runtime
/// because the bytecode validator (RFC §4.5 rules 4/8) has already
/// rejected programs with unbalanced scopes before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedMapError {
    /// `exit_scope` was called when only the root scope remained.
    /// Indicates a lifter bug — the emitter produced more `ExitScope`
    /// opcodes than `EnterScope`.
    PopRoot,
}

impl std::fmt::Display for ScopedMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PopRoot => f.write_str("cannot exit_scope on root scope"),
        }
    }
}

impl std::error::Error for ScopedMapError {}

/// A lexically-scoped key/value map with `enter_scope` / `exit_scope`
/// semantics (RFC §6.4).
///
/// The canonical instantiation in the Lysis lifter is
/// `ScopedMap<String, RegId>`. The type is generic so the unit tests
/// can exercise the scope machinery with cheap keys (`&'static str`,
/// `u32`) and so future passes can reuse it for different mappings.
#[derive(Debug, Clone)]
pub struct ScopedMap<K, V> {
    entries: Vec<(K, V)>,
    scope_starts: Vec<usize>,
}

impl<K, V> Default for ScopedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> ScopedMap<K, V> {
    /// Construct an empty map with a single (root) scope already open.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            // Root scope opens at entry 0.
            scope_starts: vec![0],
        }
    }

    /// Push a new scope. Bindings added after this point are visible
    /// until the matching [`Self::exit_scope`].
    pub fn enter_scope(&mut self) {
        self.scope_starts.push(self.entries.len());
    }

    /// Pop the current scope, dropping every binding introduced since
    /// the matching [`Self::enter_scope`].
    ///
    /// Returns [`ScopedMapError::PopRoot`] if only the root scope
    /// remains — see the invariant notes at module level.
    pub fn exit_scope(&mut self) -> Result<(), ScopedMapError> {
        if self.scope_starts.len() <= 1 {
            return Err(ScopedMapError::PopRoot);
        }
        let start = self
            .scope_starts
            .pop()
            .expect("checked len > 1 above so pop cannot return None");
        self.entries.truncate(start);
        Ok(())
    }

    /// Bind `key` to `value` in the current (innermost) scope. Does
    /// not check for or merge existing bindings — subsequent
    /// [`Self::lookup`] calls pick up the shadowing entry, and both
    /// entries disappear when the scope exits.
    pub fn bind(&mut self, key: K, value: V) {
        self.entries.push((key, value));
    }

    /// Total number of live bindings across every active scope.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if no bindings exist at all. The root scope is still
    /// present — `is_empty` only checks the binding count.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of active scopes, including the root. Starts at 1.
    pub fn scope_depth(&self) -> usize {
        self.scope_starts.len()
    }
}

impl<K, V> ScopedMap<K, V>
where
    K: Eq + Hash,
{
    /// Return the value bound to `key` in the innermost scope that
    /// contains it, or `None` if no scope binds it.
    ///
    /// Reverse linear scan — correct under shadowing because the
    /// first match from the tail is the most recent binding.
    pub fn lookup<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, v)| v)
    }

    /// `true` if some scope binds `key`. Shortcut for
    /// `self.lookup(key).is_some()`.
    pub fn contains<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.lookup(key).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_map_has_root_scope_only() {
        let m: ScopedMap<String, RegId> = ScopedMap::new();
        assert_eq!(m.scope_depth(), 1);
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn bind_and_lookup_in_root_scope() {
        let mut m: ScopedMap<String, RegId> = ScopedMap::new();
        m.bind("x".to_string(), 3);
        m.bind("y".to_string(), 7);
        assert_eq!(m.lookup("x"), Some(&3));
        assert_eq!(m.lookup("y"), Some(&7));
        assert_eq!(m.lookup("z"), None);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn enter_and_exit_scope_preserves_outer_bindings() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.bind("a", 1);
        m.enter_scope();
        m.bind("b", 2);
        assert_eq!(m.lookup("a"), Some(&1));
        assert_eq!(m.lookup("b"), Some(&2));
        m.exit_scope().unwrap();
        assert_eq!(m.lookup("a"), Some(&1));
        assert_eq!(m.lookup("b"), None);
    }

    #[test]
    fn exit_drops_every_binding_added_in_scope() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.enter_scope();
        for i in 0..10 {
            m.bind(Box::leak(format!("k{i}").into_boxed_str()), i);
        }
        assert_eq!(m.len(), 10);
        m.exit_scope().unwrap();
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn inner_scope_shadows_outer() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.bind("x", 1);
        m.enter_scope();
        m.bind("x", 42);
        assert_eq!(m.lookup("x"), Some(&42));
        m.exit_scope().unwrap();
        assert_eq!(m.lookup("x"), Some(&1));
    }

    #[test]
    fn same_scope_shadowing_picks_latest() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.bind("x", 1);
        m.bind("x", 2);
        m.bind("x", 3);
        assert_eq!(m.lookup("x"), Some(&3));
        // Both entries are present — shadowing is not deduplication.
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn nested_scopes_stack_correctly() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.bind("x", 0);

        m.enter_scope();
        m.bind("x", 1);
        assert_eq!(m.lookup("x"), Some(&1));

        m.enter_scope();
        m.bind("x", 2);
        assert_eq!(m.lookup("x"), Some(&2));

        m.exit_scope().unwrap();
        assert_eq!(m.lookup("x"), Some(&1));

        m.exit_scope().unwrap();
        assert_eq!(m.lookup("x"), Some(&0));

        assert_eq!(m.scope_depth(), 1);
    }

    #[test]
    fn exit_root_returns_error() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        assert_eq!(m.exit_scope(), Err(ScopedMapError::PopRoot));
        // Structure still usable after the error.
        m.bind("x", 1);
        assert_eq!(m.lookup("x"), Some(&1));
    }

    #[test]
    fn contains_matches_lookup() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.bind("x", 1);
        assert!(m.contains("x"));
        assert!(!m.contains("y"));
    }

    #[test]
    fn owned_string_keys_borrow_as_str_for_lookup() {
        // The canonical Lysis usage: keys are String (owned by the
        // map) but callers typically look up with &str slices pulled
        // out of the source text.
        let mut m: ScopedMap<String, RegId> = ScopedMap::new();
        m.bind(String::from("signal_a"), 4);
        assert_eq!(m.lookup("signal_a"), Some(&4));
        assert_eq!(m.lookup("other"), None);
    }

    #[test]
    fn scope_depth_tracks_enter_exit() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        assert_eq!(m.scope_depth(), 1);
        m.enter_scope();
        assert_eq!(m.scope_depth(), 2);
        m.enter_scope();
        assert_eq!(m.scope_depth(), 3);
        m.exit_scope().unwrap();
        assert_eq!(m.scope_depth(), 2);
        m.exit_scope().unwrap();
        assert_eq!(m.scope_depth(), 1);
    }

    #[test]
    fn exit_after_bind_restores_len_to_boundary() {
        let mut m: ScopedMap<&str, u32> = ScopedMap::new();
        m.bind("root", 0);
        let boundary = m.len();
        m.enter_scope();
        m.bind("a", 1);
        m.bind("b", 2);
        m.bind("c", 3);
        assert_eq!(m.len(), boundary + 3);
        m.exit_scope().unwrap();
        assert_eq!(m.len(), boundary);
        assert_eq!(m.lookup("root"), Some(&0));
    }

    #[test]
    fn default_matches_new() {
        let a: ScopedMap<String, RegId> = ScopedMap::new();
        let b: ScopedMap<String, RegId> = Default::default();
        assert_eq!(a.scope_depth(), b.scope_depth());
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn generic_value_type_works() {
        // Sanity: ScopedMap is not specialized to RegId.
        let mut m: ScopedMap<&str, String> = ScopedMap::new();
        m.bind("name", "alice".to_string());
        assert_eq!(m.lookup("name").map(|s| s.as_str()), Some("alice"));
    }
}
