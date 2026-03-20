//! Prototype registry — per-tag method tables for method dispatch.
//!
//! Each value tag (INT, STRING, LIST, MAP, FIELD, BIGINT) can have
//! methods registered. The interpreter's `MethodCall` opcode looks up
//! methods here by (tag, name) pair.

use crate::native::MethodFn;
use std::collections::{HashMap, HashSet};

/// Number of possible tag values (4-bit tag → 16 slots).
const TAG_SLOTS: usize = 16;

pub struct PrototypeRegistry {
    tables: [HashMap<&'static str, MethodFn>; TAG_SLOTS],
}

impl Default for PrototypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PrototypeRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            tables: std::array::from_fn(|_| HashMap::new()),
        }
    }

    /// Register a method for a given tag.
    pub fn register(&mut self, tag: u64, name: &'static str, func: MethodFn) {
        self.tables[tag as usize].insert(name, func);
    }

    /// Look up a method by tag and name.
    pub fn lookup(&self, tag: u64, name: &str) -> Option<MethodFn> {
        self.tables.get(tag as usize)?.get(name).copied()
    }

    /// Bootstrap all built-in methods.
    pub fn bootstrap(&mut self) {
        use super::methods;
        methods::int::register(self);
        methods::string::register(self);
        methods::list::register(self);
        methods::map::register(self);
        methods::field::register(self);
        methods::bigint::register(self);
    }

    /// Returns a sorted list of all registered method names (for compiler).
    pub fn all_method_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> =
            self.tables.iter().flat_map(|t| t.keys().copied()).collect();
        names.sort_unstable();
        names.dedup();
        names
    }
}

/// Returns the set of all known method names (bootstrapped once, no VM needed).
/// Used by the compiler to detect `expr.method(args)` patterns.
pub fn known_method_names() -> HashSet<&'static str> {
    let mut registry = PrototypeRegistry::new();
    registry.bootstrap();
    registry
        .tables
        .iter()
        .flat_map(|t| t.keys().copied())
        .collect()
}
