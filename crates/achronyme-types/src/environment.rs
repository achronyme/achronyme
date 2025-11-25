use crate::sync::{shared, Shared};
use crate::value::Value;
use achronyme_parser::type_annotation::TypeAnnotation;
use std::collections::HashMap;

/// Environment for variable storage with scope support using linked list of scopes
///
/// This is a major performance optimization that uses Arc (reference counting) to
/// share environment data instead of cloning it. This is especially important for
/// recursive functions and closures.
///
/// The environment is now a linked list where each scope points to its parent.
/// When a new scope is created, we create a new Environment that references the
/// current environment as its parent using Arc. This makes scope creation O(1)
/// instead of O(n) where n is the total number of variables.
///
/// Example:
/// ```
/// use achronyme_types::environment::Environment;
/// use achronyme_types::value::Value;
///
/// let mut env = Environment::new();
/// env.define("x".to_string(), Value::Number(5.0)).unwrap();
///
/// // Create new scope for lambda (now cheap!)
/// env.push_scope();
/// env.define("x".to_string(), Value::Number(10.0)).unwrap(); // Shadows outer x
/// assert_eq!(env.get("x").unwrap(), Value::Number(10.0));
///
/// env.pop_scope();
/// assert_eq!(env.get("x").unwrap(), Value::Number(5.0)); // Back to outer x
/// ```
#[derive(Debug, Clone)]
pub struct Environment {
    /// Current scope variables
    variables: HashMap<String, Value>,
    /// Metadata: tracks which variables are mutable
    mutability: HashMap<String, bool>,
    /// Metadata: tracks type annotations for variables (for type checking on assignment)
    type_annotations: HashMap<String, TypeAnnotation>,
    /// Parent environment (if any)
    /// Now uses RwLock to allow mutation of parent scopes
    parent: Option<Shared<Environment>>,
}

impl Environment {
    /// Create a new empty environment (root scope)
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            mutability: HashMap::new(),
            type_annotations: HashMap::new(),
            parent: None,
        }
    }

    /// Create a child environment with this environment as parent
    ///
    /// This is now the primary way to create a new scope. It's O(1) because
    /// we just create a new empty HashMap and an Arc pointer to the parent.
    pub fn new_child(parent: Shared<Environment>) -> Self {
        Self {
            variables: HashMap::new(),
            mutability: HashMap::new(),
            type_annotations: HashMap::new(),
            parent: Some(parent),
        }
    }

    /// Push a new scope onto the stack
    ///
    /// This creates a new nested scope by replacing self with a child that
    /// points to the old self. Variables defined after this will be in the
    /// new scope and can shadow outer variables.
    ///
    /// NOTE: This is now implemented by creating a child and swapping.
    pub fn push_scope(&mut self) {
        let parent = shared(self.clone());
        *self = Environment::new_child(parent);
    }

    /// Pop the current scope from the stack
    ///
    /// This removes the innermost scope and all variables defined in it.
    /// Panics if trying to pop the root scope.
    pub fn pop_scope(&mut self) {
        if let Some(parent) = self.parent.clone() {
            // Clone the parent out of the Shared<> and replace self
            *self = parent.read().clone();
        } else {
            panic!("Cannot pop root scope");
        }
    }

    /// Get the current scope depth (0 = root, 1+ = nested)
    pub fn scope_depth(&self) -> usize {
        let mut depth = 0;
        let mut current_parent = self.parent.clone();
        while let Some(parent) = current_parent {
            depth += 1;
            current_parent = parent.read().parent.clone();
        }
        depth
    }

    /// Define a new variable in the current scope (immutable by default)
    ///
    /// With shadowing enabled, this allows redefining variables from outer scopes.
    /// Within the same scope, redefinition is allowed (for `let x = ...; let x = ...`)
    ///
    /// # Arguments
    /// * `name` - Variable name
    /// * `value` - Initial value
    pub fn define(&mut self, name: String, value: Value) -> Result<(), String> {
        self.define_with_mutability(name, value, false)
    }

    /// Define a mutable variable in the current scope
    ///
    /// # Arguments
    /// * `name` - Variable name
    /// * `value` - Initial value
    pub fn define_mutable(&mut self, name: String, value: Value) -> Result<(), String> {
        self.define_with_mutability(name, value, true)
    }

    /// Define a mutable variable with a type annotation
    ///
    /// The type annotation will be enforced on subsequent assignments.
    ///
    /// # Arguments
    /// * `name` - Variable name
    /// * `value` - Initial value
    /// * `type_ann` - Type annotation to enforce on assignments
    pub fn define_mutable_typed(
        &mut self,
        name: String,
        value: Value,
        type_ann: TypeAnnotation,
    ) -> Result<(), String> {
        // Wrap in MutableRef
        let stored_value = Value::new_mutable(value);

        // Insert into current scope's variables
        self.variables.insert(name.clone(), stored_value);
        self.mutability.insert(name.clone(), true);
        // Store the type annotation for assignment checking
        self.type_annotations.insert(name, type_ann);
        Ok(())
    }

    /// Internal: Define a variable with specified mutability
    fn define_with_mutability(
        &mut self,
        name: String,
        value: Value,
        is_mutable: bool,
    ) -> Result<(), String> {
        // Wrap in MutableRef if mutable
        let stored_value = if is_mutable {
            Value::new_mutable(value)
        } else {
            value
        };

        // Insert into current scope's variables
        self.variables.insert(name.clone(), stored_value);
        self.mutability.insert(name, is_mutable);
        Ok(())
    }

    /// Get a variable value, searching from current to parent scopes
    ///
    /// Auto-dereferences MutableRef values for transparent access
    ///
    /// # Arguments
    /// * `name` - Variable name
    ///
    /// # Returns
    /// Variable value if found in any scope
    ///
    /// # Errors
    /// Returns error if variable not found in any scope
    pub fn get(&self, name: &str) -> Result<Value, String> {
        // Check current scope first
        if let Some(value) = self.variables.get(name) {
            // Auto-deref MutableRef for transparent access
            return value.deref();
        }

        // Search parent scopes
        if let Some(ref parent) = self.parent {
            return parent.read().get(name);
        }

        Err(format!("Undefined variable '{}'", name))
    }

    /// Check if a variable is defined in any scope
    ///
    /// # Arguments
    /// * `name` - Variable name
    ///
    /// # Returns
    /// true if variable exists in any scope
    pub fn has(&self, name: &str) -> bool {
        if self.variables.contains_key(name) {
            return true;
        }

        if let Some(ref parent) = self.parent {
            return parent.read().has(name);
        }

        false
    }

    /// Assign a new value to a mutable variable
    ///
    /// Searches current and parent scopes for the variable.
    /// Only works on variables declared with `mut`.
    ///
    /// # Arguments
    /// * `name` - Variable name
    /// * `value` - New value
    ///
    /// # Errors
    /// Returns error if:
    /// - Variable not found in any scope
    /// - Variable is immutable (not declared with `mut`)
    ///
    /// # Returns
    /// Ok(()) on success. Caller should check type annotations separately.
    pub fn assign(&mut self, name: &str, value: Value) -> Result<(), String> {
        // Check current scope first
        if let Some(var_value) = self.variables.get(name) {
            let is_mutable = self.mutability.get(name).copied().unwrap_or(false);

            if !is_mutable {
                return Err(format!("Cannot assign to immutable variable '{}'", name));
            }

            // Assign to MutableRef
            var_value.assign(value)?;
            return Ok(());
        }

        // Search and mutate in parent scopes
        if let Some(ref parent) = self.parent {
            return parent.write().assign(name, value);
        }

        Err(format!("Undefined variable '{}'", name))
    }

    /// Get the type annotation for a variable, if one exists
    ///
    /// Searches current and parent scopes.
    pub fn get_type_annotation(&self, name: &str) -> Option<TypeAnnotation> {
        // Check current scope first
        if let Some(type_ann) = self.type_annotations.get(name) {
            return Some(type_ann.clone());
        }

        // Search parent scopes
        if let Some(ref parent) = self.parent {
            return parent.read().get_type_annotation(name);
        }

        None
    }

    /// Update an existing variable in the scope where it was defined
    ///
    /// # Arguments
    /// * `name` - Variable name
    /// * `value` - New value
    ///
    /// # Errors
    /// Returns error if variable not found in any scope
    ///
    /// NOTE: This is more complex with the linked structure because we need
    /// to modify the parent, which is behind an Arc. For now, we only allow
    /// setting variables in the current scope. This matches the semantics
    /// of most languages where assignment creates a new binding if it doesn't
    /// exist in the current scope.
    pub fn set(&mut self, name: &str, value: Value) -> Result<(), String> {
        // Check if variable exists in current scope
        if self.variables.contains_key(name) {
            self.variables.insert(name.to_string(), value);
            return Ok(());
        }

        // Check if it exists in parent scopes
        if let Some(ref parent) = self.parent {
            if parent.read().has(name) {
                // Variable exists in parent, but we shadow it in the current scope
                self.variables.insert(name.to_string(), value);
                return Ok(());
            }
        }

        Err(format!("Cannot assign to undefined variable '{}'", name))
    }

    /// Clear all variables in the current scope only
    pub fn clear(&mut self) {
        self.variables.clear();
        self.mutability.clear();
        self.type_annotations.clear();
        self.parent = None;
    }

    /// Get total number of variables in current scope only
    /// (counting parent variables would require traversing the chain)
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Check if current scope has no variables
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Get a snapshot of all visible variables (for lambda closures)
    ///
    /// This flattens the scope chain, with inner scopes overriding outer ones.
    /// Used when creating a closure to capture the current environment.
    ///
    /// DEPRECATED: This is kept for backward compatibility but is expensive.
    /// New code should use `to_shared()` to capture the environment as Shared<Environment>.
    pub fn snapshot(&self) -> HashMap<String, Value> {
        let mut snapshot = HashMap::new();

        // Collect from parent first (so current scope can override)
        if let Some(ref parent) = self.parent {
            snapshot = parent.read().snapshot();
        }

        // Add/override with current scope (deref MutableRef values)
        for (name, value) in &self.variables {
            if let Ok(derefed) = value.deref() {
                snapshot.insert(name.clone(), derefed);
            } else {
                snapshot.insert(name.clone(), value.clone());
            }
        }

        snapshot
    }

    /// Create a new environment from a snapshot (single root scope)
    ///
    /// Used when restoring a closure's captured environment.
    ///
    /// DEPRECATED: This is kept for backward compatibility.
    pub fn from_snapshot(snapshot: HashMap<String, Value>) -> Self {
        Self {
            variables: snapshot,
            mutability: HashMap::new(), // No mutability info in snapshot
            type_annotations: HashMap::new(), // No type info in snapshot
            parent: None,
        }
    }

    /// Convert this environment to an Shared<> for efficient sharing
    ///
    /// This is the preferred way to capture an environment for closures.
    pub fn to_shared(&self) -> Shared<Environment> {
        shared(self.clone())
    }

    /// Create a new environment with a specific parent
    pub fn with_parent(parent: Shared<Environment>) -> Self {
        Self::new_child(parent)
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "environment_tests.rs"]
mod tests;
