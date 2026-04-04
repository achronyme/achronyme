//! Lowering environment — shared identifier resolution state.
//!
//! `LoweringEnv` tracks which identifiers are signal inputs, local
//! bindings, or template captures. It is shared across expression,
//! statement, and template lowering.

use std::collections::{HashMap, HashSet};

use super::utils::EvalValue;

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
#[derive(Clone)]
pub struct LoweringEnv {
    /// Signal inputs (public + witness) — resolve to `CircuitExpr::Input`.
    pub inputs: HashSet<String>,
    /// Local bindings (intermediates, outputs, vars) — resolve to `CircuitExpr::Var`.
    pub locals: HashSet<String>,
    /// Template parameters — resolve to `CircuitExpr::Capture`.
    pub captures: HashSet<String>,
    /// Arrays — maps base name to element count for index resolution.
    /// When `arr` is registered with size 3, `arr[0]` resolves to `arr_0`.
    pub arrays: HashMap<String, usize>,
    /// Multi-dimensional array strides for linearization.
    /// For `signal c[n][2]`, strides["c"] = [2], so c[i][j] → c[i*2+j].
    pub strides: HashMap<String, Vec<usize>>,
    /// Component array names — declared via `component muls[n]`.
    pub component_arrays: HashSet<String>,
    /// Known constants — loop variables during manual unrolling.
    /// When set, `lower_expr` for `Ident("i")` emits `Const(val)`.
    pub known_constants: HashMap<String, u64>,
    /// Known array constants — compile-time arrays from function calls
    /// like `var C[n] = POSEIDON_C(t)`.  Used to resolve `C[expr]`
    /// to a field constant during lowering.
    pub known_array_values: HashMap<String, EvalValue>,
}

impl LoweringEnv {
    pub fn new() -> Self {
        Self {
            inputs: HashSet::new(),
            locals: HashSet::new(),
            captures: HashSet::new(),
            arrays: HashMap::new(),
            strides: HashMap::new(),
            component_arrays: HashSet::new(),
            known_constants: HashMap::new(),
            known_array_values: HashMap::new(),
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

    /// Register an array variable with its element count.
    /// Individual element names (`name_0`, `name_1`, ...) are added as locals.
    pub fn register_array(&mut self, name: String, len: usize) {
        self.arrays.insert(name, len);
    }

    /// Collect all known names in scope (inputs, locals, captures, known constants).
    /// Used for "did you mean?" suggestions.
    pub fn all_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        names.extend(self.inputs.iter().cloned());
        names.extend(self.locals.iter().cloned());
        names.extend(self.captures.iter().cloned());
        names.extend(self.known_constants.keys().cloned());
        names
    }

    /// Resolve an array element access: `arr[idx]` → element name if idx is constant.
    pub fn resolve_array_element(&self, name: &str, index: usize) -> Option<String> {
        let len = self.arrays.get(name)?;
        if index < *len {
            Some(format!("{name}_{index}"))
        } else {
            None
        }
    }
}
