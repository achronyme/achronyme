//! Leaf-level helpers shared by every other annotate submodule:
//! qualified-name construction, module-prefix computation, and
//! `Stmt::Export` inspection. All four are `pub(super)` — they
//! have no external consumers.

use achronyme_parser::ast::Stmt;

use crate::module_graph::{ModuleGraph, ModuleId};

/// Build the qualified-name prefix for a module: `""` for the root,
/// `"modN::"` otherwise. See [`register_module`](super::register_module)'s
/// "Key choice" section for why we use the module id number instead of
/// a user alias.
pub(super) fn module_prefix(id: ModuleId, graph: &ModuleGraph) -> String {
    if id == graph.root() {
        String::new()
    } else {
        format!("mod{}::", id.as_u32())
    }
}

/// Join a module-prefix and an unqualified name into a single table
/// key. Handles the root-module case (empty prefix) without a spurious
/// leading `::`.
pub(super) fn qualify(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}{name}")
    }
}

/// Unwrap `Stmt::Export { inner, .. }` to return the inner statement.
/// Non-exported statements pass through unchanged.
pub(super) fn unwrap_exported(stmt: &Stmt) -> Option<&Stmt> {
    match stmt {
        Stmt::Export { inner, .. } => Some(inner),
        other => Some(other),
    }
}

/// `true` if the statement is a top-level `export { … }` wrapper.
pub(super) fn is_exported(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Export { .. })
}
