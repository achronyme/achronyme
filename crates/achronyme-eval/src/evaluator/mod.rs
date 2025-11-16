//! Evaluator for SOC (Scientific Operations Calculator)
//!
//! The evaluator walks the AST and computes results using a post-order traversal
//! (visit children before parent).
//!
//! Example evaluation order:
//! ```text
//!       +
//!      / \
//!     2   *
//!        / \
//!       3   4
//!
//! Evaluation order:
//!   1. eval(2) → 2
//!   2. eval(3) → 3
//!   3. eval(4) → 4
//!   4. eval(3*4) → 12
//!   5. eval(2+12) → 14
//! ```

use achronyme_types::Environment;
use achronyme_types::value::Value;
use achronyme_parser::type_annotation::TypeAnnotation;
use std::collections::HashMap;

use crate::constants::ConstantsRegistry;
use crate::functions::FunctionRegistry;
use crate::modules::{ModuleRegistry, create_builtin_registry};

// Module declarations
mod state;
mod modules;
mod lambda_eval;
mod dispatcher;

/// Evaluator
///
/// Walks the AST and computes the result.
pub struct Evaluator {
    pub(crate) env: Environment,
    pub(crate) constants: ConstantsRegistry,
    pub(crate) functions: FunctionRegistry,
    /// Module registry for organizing functions into modules
    pub(crate) module_registry: ModuleRegistry,
    /// Track which modules have been imported
    /// Format: local_name -> (module_name, original_name)
    pub(crate) imported_modules: HashMap<String, (String, String)>,
    /// Track exported values from current module (for user-defined modules)
    /// Format: name -> Value
    pub(crate) exported_values: HashMap<String, Value>,
    /// Track exported types from current module (for user-defined modules)
    /// Format: name -> TypeAnnotation
    pub(crate) exported_types: HashMap<String, TypeAnnotation>,
    /// Cache of loaded user modules to avoid re-parsing
    /// Format: module_path -> (values, types)
    pub(crate) module_cache: HashMap<String, (HashMap<String, Value>, HashMap<String, TypeAnnotation>)>,
    /// Current file being evaluated (for relative imports)
    /// This is the directory path of the file currently being evaluated
    pub(crate) current_file_dir: Option<String>,
    /// Flag to enable tail call optimization mode
    /// When true, CallExpression with rec will return TailCall markers
    pub(crate) tco_mode: bool,
    /// Type registry for storing type aliases
    /// Format: alias_name -> type_definition
    pub(crate) type_registry: HashMap<String, TypeAnnotation>,
    /// Track if we're currently inside a generator (for yield validation)
    pub(crate) in_generator: bool,
    /// Track how many loops we're currently inside (for break/continue validation)
    /// Incremented when entering while/for loops, decremented when leaving
    pub(crate) loop_depth: usize,
    /// Track how many yields have been encountered during current generator execution
    /// Used for resuming generators with nested control flow
    pub(crate) generator_yield_count: usize,
    /// Target yield number to stop at during generator execution
    /// When yield_count reaches this target, the generator suspends
    pub(crate) generator_yield_target: usize,
}

impl Evaluator {
    /// Create a new evaluator
    pub fn new() -> Self {
        Self {
            env: Environment::new(),
            constants: ConstantsRegistry::new(),
            functions: FunctionRegistry::new(),
            module_registry: create_builtin_registry(),
            imported_modules: HashMap::new(),
            exported_values: HashMap::new(),
            exported_types: HashMap::new(),
            module_cache: HashMap::new(),
            current_file_dir: None,
            tco_mode: false,
            type_registry: HashMap::new(),
            in_generator: false,
            loop_depth: 0,
            generator_yield_count: 0,
            generator_yield_target: 0,
        }
    }

    /// Register a type alias
    pub fn register_type_alias(&mut self, name: String, type_definition: TypeAnnotation) {
        self.type_registry.insert(name, type_definition);
    }

    /// Set the current file directory for relative imports (directly)
    /// This is used for testing purposes
    pub fn set_current_file_dir_direct(&mut self, dir: Option<String>) {
        self.current_file_dir = dir;
    }

    /// Get the current file directory
    pub fn get_current_file_dir(&self) -> Option<&String> {
        self.current_file_dir.as_ref()
    }

    /// Resolve a type reference to its definition
    /// Recursively resolves type aliases and expands them
    pub fn resolve_type(&self, type_ann: &TypeAnnotation) -> TypeAnnotation {
        match type_ann {
            TypeAnnotation::TypeReference(name) => {
                // Look up the type alias
                if let Some(definition) = self.type_registry.get(name) {
                    // Recursively resolve in case it references another alias
                    self.resolve_type(definition)
                } else {
                    // Unknown type reference - keep as is (will be caught during type checking)
                    type_ann.clone()
                }
            }
            // For compound types, recursively resolve inner types
            TypeAnnotation::Union(types) => {
                let resolved = types.iter().map(|t| self.resolve_type(t)).collect();
                TypeAnnotation::Union(resolved)
            }
            TypeAnnotation::Tensor { element_type, shape } => {
                TypeAnnotation::Tensor {
                    element_type: Box::new(self.resolve_type(element_type)),
                    shape: shape.clone(),
                }
            }
            TypeAnnotation::Record { fields } => {
                let resolved_fields = fields.iter()
                    .map(|(name, (is_mut, is_optional, ty))| {
                        (name.clone(), (*is_mut, *is_optional, self.resolve_type(ty)))
                    })
                    .collect();
                TypeAnnotation::Record { fields: resolved_fields }
            }
            TypeAnnotation::Function { params, return_type } => {
                let resolved_params = params.iter()
                    .map(|p| p.as_ref().map(|t| self.resolve_type(t)))
                    .collect();
                TypeAnnotation::Function {
                    params: resolved_params,
                    return_type: Box::new(self.resolve_type(return_type)),
                }
            }
            // Simple types don't need resolution
            _ => type_ann.clone(),
        }
    }
}

impl Default for Evaluator {
    fn default() -> Self {
        Self::new()
    }
}
