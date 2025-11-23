//! Runtime Intrinsic Dispatch (RID) - Method dispatch for built-in types
//!
//! This module provides a registry of intrinsic methods that are dispatched at runtime
//! based on the receiver type. This allows uniform method calls on both VM-defined types
//! (like generators) and user-defined objects.

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::collections::HashMap;

mod generator;

/// Type discriminant for intrinsic method lookup
/// We use a string-based discriminant for simplicity
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeDiscriminant {
    Generator,
    Vector,
    String,
    Record,
    Number,
    Boolean,
}

impl TypeDiscriminant {
    /// Get the type discriminant for a value
    pub fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Generator(_) => Some(TypeDiscriminant::Generator),
            Value::Vector(_) => Some(TypeDiscriminant::Vector),
            Value::String(_) => Some(TypeDiscriminant::String),
            Value::Record(_) => Some(TypeDiscriminant::Record),
            Value::Number(_) => Some(TypeDiscriminant::Number),
            Value::Boolean(_) => Some(TypeDiscriminant::Boolean),
            _ => None,
        }
    }
}

/// Intrinsic function signature
///
/// Takes:
/// - &mut VM: mutable reference to the VM for state access
/// - &Value: the receiver (self/this)
/// - &[Value]: arguments to the method
///
/// Returns:
/// - Result<Value, VmError>: the return value or error
pub type IntrinsicFn = fn(&mut VM, &Value, &[Value]) -> Result<Value, VmError>;

/// Registry of intrinsic methods
pub struct IntrinsicRegistry {
    /// Map of (type_discriminant, method_name) -> intrinsic function
    methods: HashMap<(TypeDiscriminant, String), IntrinsicFn>,
}

impl IntrinsicRegistry {
    /// Create a new intrinsic registry with default intrinsics registered
    pub fn new() -> Self {
        let mut registry = Self {
            methods: HashMap::new(),
        };

        // Register built-in intrinsics
        registry.register_generator_intrinsics();

        registry
    }

    /// Register an intrinsic method
    pub fn register(
        &mut self,
        type_disc: TypeDiscriminant,
        method_name: impl Into<String>,
        func: IntrinsicFn,
    ) {
        self.methods.insert((type_disc, method_name.into()), func);
    }

    /// Look up an intrinsic method
    pub fn lookup(&self, type_disc: &TypeDiscriminant, method_name: &str) -> Option<IntrinsicFn> {
        self.methods
            .get(&(type_disc.clone(), method_name.to_string()))
            .copied()
    }

    /// Register all generator intrinsic methods
    fn register_generator_intrinsics(&mut self) {
        self.register(
            TypeDiscriminant::Generator,
            "next",
            generator::generator_next,
        );
    }
}

impl Default for IntrinsicRegistry {
    fn default() -> Self {
        Self::new()
    }
}
