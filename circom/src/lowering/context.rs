//! Program-level lowering context.
//!
//! `LoweringContext` holds template and function definitions from the
//! parsed `CircomProgram`, enabling component instantiation (template
//! inlining) and function call inlining during lowering.

use std::collections::{HashMap, HashSet};

use ir_forge::types::{CircuitNode, FieldConst};

use crate::ast::{CircomProgram, Definition, FunctionDef, TemplateDef};

/// Maximum inlining depth to prevent infinite recursion from mutually
/// recursive templates or functions.
pub const MAX_INLINE_DEPTH: usize = 64;

/// Program-level context for template and function resolution.
///
/// Passed through the lowering pipeline so that component instantiations
/// can resolve their target template and function calls can be inlined.
pub struct LoweringContext<'a> {
    /// All template definitions, keyed by name.
    pub templates: HashMap<&'a str, &'a TemplateDef>,
    /// All function definitions, keyed by name.
    pub functions: HashMap<&'a str, &'a FunctionDef>,
    /// Current inlining depth (incremented on each component/function inline).
    pub inline_depth: usize,
    /// Template parameter values for the main template (e.g., n=3).
    /// Used to resolve component array sizes and unroll loops at lowering time.
    pub param_values: HashMap<String, FieldConst>,
    /// Bus type names declared in the program (for error detection).
    pub bus_names: HashSet<&'a str>,
    /// Counter for generating unique anonymous component names.
    anon_counter: usize,
    /// Cache of lowered template bodies (before mangling).
    ///
    /// Key: `template_name` for parameterless templates, or
    /// `template_name:param=val:...` for parameterized ones.
    /// Only entries with empty `const_inputs` and `array_args` are cached,
    /// since those guarantee identical lowered output.
    pub body_cache: HashMap<String, Vec<CircuitNode>>,
    /// Side-channel for [`CircuitNode`]s produced during expression
    /// lowering that must land in the enclosing body *before* the
    /// statement whose expression emitted them. Populated by the
    /// Artik witness-call lift pass when it replaces E212; flushed
    /// by every statement-level lowering call before it pushes its
    /// own node.
    pub pending_nodes: Vec<CircuitNode>,
}

impl<'a> LoweringContext<'a> {
    /// Build a context from a parsed Circom program.
    pub fn from_program(program: &'a CircomProgram) -> Self {
        let mut templates = HashMap::new();
        let mut functions = HashMap::new();
        let mut bus_names = HashSet::new();
        for def in &program.definitions {
            match def {
                Definition::Template(t) => {
                    templates.insert(t.name.as_str(), t);
                }
                Definition::Function(f) => {
                    functions.insert(f.name.as_str(), f);
                }
                Definition::Bus(b) => {
                    bus_names.insert(b.name.as_str());
                }
            }
        }
        Self {
            templates,
            functions,
            inline_depth: 0,
            param_values: HashMap::new(),
            bus_names,
            anon_counter: 0,
            body_cache: HashMap::new(),
            pending_nodes: Vec::new(),
        }
    }

    /// Drain [`Self::pending_nodes`] into the caller's body. Call this
    /// from every statement-level lowering site, after lowering the
    /// statement's expressions and before pushing the statement's own
    /// node, so any witness-call side effects land in emission order.
    pub fn flush_pending_nodes(&mut self, nodes: &mut Vec<CircuitNode>) {
        if !self.pending_nodes.is_empty() {
            nodes.append(&mut self.pending_nodes);
        }
    }

    /// Generate a unique ID for an anonymous component.
    pub fn next_anon_id(&mut self) -> usize {
        let id = self.anon_counter;
        self.anon_counter += 1;
        id
    }

    /// Build a combined constants map from `param_values` and `env.known_constants`.
    ///
    /// Used by lowering functions that need to iterate over all constants or pass
    /// to expression evaluation. Prefer [`resolve_constant`] for single lookups.
    pub fn all_constants(&self, env: &super::env::LoweringEnv) -> HashMap<String, FieldConst> {
        let mut all = HashMap::with_capacity(self.param_values.len() + env.known_constants.len());
        for (k, &v) in &self.param_values {
            all.insert(k.clone(), v);
        }
        for (k, &v) in &env.known_constants {
            all.entry(k.clone()).or_insert(v);
        }
        all
    }

    /// Look up a single constant by name without creating a merged HashMap.
    ///
    /// Checks `param_values` first (template params, precomputed vars),
    /// then `env.known_constants` (signals with known values). This avoids
    /// the allocation overhead of [`all_constants`] for simple lookups.
    #[inline]
    pub fn resolve_constant(
        &self,
        name: &str,
        env: &super::env::LoweringEnv,
    ) -> Option<FieldConst> {
        self.param_values
            .get(name)
            .or_else(|| env.known_constants.get(name))
            .copied()
    }

    /// Create an empty context (for testing).
    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            templates: HashMap::new(),
            functions: HashMap::new(),
            inline_depth: 0,
            body_cache: HashMap::new(),
            param_values: HashMap::new(),
            bus_names: HashSet::new(),
            anon_counter: 0,
            pending_nodes: Vec::new(),
        }
    }
}
