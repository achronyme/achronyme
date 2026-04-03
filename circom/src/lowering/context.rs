//! Program-level lowering context.
//!
//! `LoweringContext` holds template and function definitions from the
//! parsed `CircomProgram`, enabling component instantiation (template
//! inlining) and function call inlining during lowering.

use std::collections::HashMap;

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
    pub param_values: HashMap<String, u64>,
}

impl<'a> LoweringContext<'a> {
    /// Build a context from a parsed Circom program.
    pub fn from_program(program: &'a CircomProgram) -> Self {
        let mut templates = HashMap::new();
        let mut functions = HashMap::new();
        for def in &program.definitions {
            match def {
                Definition::Template(t) => {
                    templates.insert(t.name.as_str(), t);
                }
                Definition::Function(f) => {
                    functions.insert(f.name.as_str(), f);
                }
                Definition::Bus(_) => {} // Not yet supported
            }
        }
        Self {
            templates,
            functions,
            inline_depth: 0,
            param_values: HashMap::new(),
        }
    }
}
