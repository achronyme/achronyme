//! Lowering environment — shared identifier resolution state.
//!
//! `LoweringEnv` tracks which identifiers are signal inputs, local
//! bindings, or template captures. It is shared across expression,
//! statement, and template lowering.

use std::collections::HashSet;

/// Identifier resolution categories for lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarKind {
    /// A public or witness input signal.
    Input,
    /// A local let-binding (intermediate signal, variable, output signal).
    Local,
    /// A template parameter captured from the outer scope.
    Capture,
}

/// Environment for resolving identifiers during lowering.
///
/// Tracks which names are inputs, locals, or captures so that
/// `lower_expr` can emit the correct `CircuitExpr` variant.
pub struct LoweringEnv {
    /// Signal inputs (public + witness) — resolve to `CircuitExpr::Input`.
    pub inputs: HashSet<String>,
    /// Local bindings (intermediates, outputs, vars) — resolve to `CircuitExpr::Var`.
    pub locals: HashSet<String>,
    /// Template parameters — resolve to `CircuitExpr::Capture`.
    pub captures: HashSet<String>,
}

impl LoweringEnv {
    pub fn new() -> Self {
        Self {
            inputs: HashSet::new(),
            locals: HashSet::new(),
            captures: HashSet::new(),
        }
    }

    /// Resolve an identifier to its kind, or None if unknown.
    pub fn resolve(&self, name: &str) -> Option<VarKind> {
        if self.inputs.contains(name) {
            Some(VarKind::Input)
        } else if self.locals.contains(name) {
            Some(VarKind::Local)
        } else if self.captures.contains(name) {
            Some(VarKind::Capture)
        } else {
            None
        }
    }
}
