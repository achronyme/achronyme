//! Built-in function registry for the VM
//!
//! This module provides the infrastructure for registering and looking up
//! built-in functions by name or numeric ID.

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::collections::HashMap;

/// Type signature for native VM functions
///
/// Takes a mutable reference to the VM and a slice of argument values,
/// returns a Result with the computed value or a VmError.
pub type NativeFn = fn(&mut VM, &[Value]) -> Result<Value, VmError>;

/// Metadata for a single built-in function
#[derive(Clone)]
pub struct BuiltinMetadata {
    /// Function name
    pub name: String,
    /// Function pointer
    pub func: NativeFn,
    /// Expected argument count (-1 for variadic)
    pub arity: i8,
}

/// Registry of all built-in functions
///
/// Provides O(1) lookup by both name (for compiler) and index (for VM)
pub struct BuiltinRegistry {
    /// Name to index mapping (for compiler)
    pub name_to_id: HashMap<String, u16>,
    /// Index to function mapping (for VM)
    pub functions: Vec<BuiltinMetadata>,
}

impl BuiltinRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            name_to_id: HashMap::new(),
            functions: Vec::new(),
        }
    }

    /// Register a built-in function
    ///
    /// # Arguments
    /// * `name` - Function name (must be unique)
    /// * `func` - Function pointer
    /// * `arity` - Number of expected arguments (-1 for variadic)
    ///
    /// # Panics
    /// Panics if the function name is already registered or if more than
    /// 65535 functions are registered (u16 limit).
    pub fn register(&mut self, name: &str, func: NativeFn, arity: i8) {
        if self.name_to_id.contains_key(name) {
            panic!("Built-in function '{}' already registered", name);
        }

        let id = self.functions.len();
        if id > u16::MAX as usize {
            panic!("Too many built-in functions (max 65536)");
        }

        self.name_to_id.insert(name.to_string(), id as u16);
        self.functions.push(BuiltinMetadata {
            name: name.to_string(),
            func,
            arity,
        });
    }

    /// Get function pointer by ID (for VM runtime)
    ///
    /// O(1) array lookup
    #[inline]
    pub fn get_fn(&self, id: u16) -> Option<NativeFn> {
        self.functions.get(id as usize).map(|m| m.func)
    }

    /// Get function metadata by ID
    #[inline]
    pub fn get_metadata(&self, id: u16) -> Option<&BuiltinMetadata> {
        self.functions.get(id as usize)
    }

    /// Get function ID by name (for compiler)
    ///
    /// O(1) hash lookup
    #[inline]
    pub fn get_id(&self, name: &str) -> Option<u16> {
        self.name_to_id.get(name).copied()
    }

    /// Get number of registered functions
    #[inline]
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Check if registry is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }
}

impl Default for BuiltinRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_fn(_vm: &mut VM, _args: &[Value]) -> Result<Value, VmError> {
        Ok(Value::Null)
    }

    #[test]
    fn test_registry_basic() {
        let mut registry = BuiltinRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());

        registry.register("test", dummy_fn, 1);
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());

        assert_eq!(registry.get_id("test"), Some(0));
        assert_eq!(registry.get_id("nonexistent"), None);
    }

    #[test]
    fn test_registry_multiple() {
        let mut registry = BuiltinRegistry::new();

        registry.register("sin", dummy_fn, 1);
        registry.register("cos", dummy_fn, 1);
        registry.register("print", dummy_fn, -1);

        assert_eq!(registry.get_id("sin"), Some(0));
        assert_eq!(registry.get_id("cos"), Some(1));
        assert_eq!(registry.get_id("print"), Some(2));

        let sin_meta = registry.get_metadata(0).unwrap();
        assert_eq!(sin_meta.name, "sin");
        assert_eq!(sin_meta.arity, 1);

        let print_meta = registry.get_metadata(2).unwrap();
        assert_eq!(print_meta.name, "print");
        assert_eq!(print_meta.arity, -1);
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn test_duplicate_registration() {
        let mut registry = BuiltinRegistry::new();
        registry.register("test", dummy_fn, 1);
        registry.register("test", dummy_fn, 1); // Should panic
    }
}
