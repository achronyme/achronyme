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
    Complex,
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
            Value::Complex(_) => Some(TypeDiscriminant::Complex),
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
        registry.register_common_intrinsics();

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

    /// Register common intrinsics (Vector, String, Number, etc.)
    fn register_common_intrinsics(&mut self) {
        // Adapter helper: creates an IntrinsicFn that calls a NativeFn
        // It prepends the 'receiver' to the arguments list.
        macro_rules! adapt {
            ($native_fn:expr) => {
                |vm: &mut VM, receiver: &Value, args: &[Value]| -> Result<Value, VmError> {
                    let mut full_args = Vec::with_capacity(args.len() + 1);
                    full_args.push(receiver.clone());
                    full_args.extend_from_slice(args);
                    $native_fn(vm, &full_args)
                }
            };
        }

        // Adapter that puts the receiver at the END of the argument list
        // Useful for HOFs where signature is (callback, collection)
        macro_rules! adapt_last {
            ($native_fn:expr) => {
                |vm: &mut VM, receiver: &Value, args: &[Value]| -> Result<Value, VmError> {
                    let mut full_args = Vec::with_capacity(args.len() + 1);
                    full_args.extend_from_slice(args);
                    full_args.push(receiver.clone());
                    $native_fn(vm, &full_args)
                }
            };
        }

        // === Vector Methods ===
        self.register(
            TypeDiscriminant::Vector,
            "push",
            adapt!(crate::builtins::vector::vm_push),
        );
        self.register(
            TypeDiscriminant::Vector,
            "pop",
            adapt!(crate::builtins::vector::vm_pop),
        );
        self.register(
            TypeDiscriminant::Vector,
            "len",
            adapt!(crate::builtins::string::vm_len),
        ); // len is shared
        self.register(
            TypeDiscriminant::Vector,
            "is_empty",
            adapt!(crate::builtins::vector::vm_is_empty),
        );
        self.register(
            TypeDiscriminant::Vector,
            "first",
            adapt!(crate::builtins::vector::vm_first),
        );
        self.register(
            TypeDiscriminant::Vector,
            "last",
            adapt!(crate::builtins::vector::vm_last),
        );
        self.register(
            TypeDiscriminant::Vector,
            "reverse",
            adapt!(crate::builtins::vector::vm_reverse),
        );
        self.register(
            TypeDiscriminant::Vector,
            "sort",
            adapt!(crate::builtins::vector::vm_sort),
        );
        self.register(
            TypeDiscriminant::Vector,
            "slice",
            adapt!(crate::builtins::vector::vm_slice),
        );
        self.register(
            TypeDiscriminant::Vector,
            "join",
            adapt!(crate::builtins::string::vm_join),
        ); // join works on vectors of strings

        // HOF methods for Vector (Collection is last arg)
        self.register(
            TypeDiscriminant::Vector,
            "map",
            adapt_last!(crate::builtins::hof::vm_map),
        );
        self.register(
            TypeDiscriminant::Vector,
            "filter",
            adapt_last!(crate::builtins::hof::vm_filter),
        );
        self.register(
            TypeDiscriminant::Vector,
            "reduce",
            adapt_last!(crate::builtins::hof::vm_reduce),
        );
        self.register(
            TypeDiscriminant::Vector,
            "any",
            adapt_last!(crate::builtins::hof::vm_any),
        );
        self.register(
            TypeDiscriminant::Vector,
            "all",
            adapt_last!(crate::builtins::hof::vm_all),
        );

        // === String Methods ===
        self.register(
            TypeDiscriminant::String,
            "len",
            adapt!(crate::builtins::string::vm_len),
        );
        self.register(
            TypeDiscriminant::String,
            "trim",
            adapt!(crate::builtins::string::vm_trim),
        );
        self.register(
            TypeDiscriminant::String,
            "upper",
            adapt!(crate::builtins::string::vm_upper),
        );
        self.register(
            TypeDiscriminant::String,
            "lower",
            adapt!(crate::builtins::string::vm_lower),
        );
        self.register(
            TypeDiscriminant::String,
            "split",
            adapt!(crate::builtins::string::vm_split),
        );
        self.register(
            TypeDiscriminant::String,
            "replace",
            adapt!(crate::builtins::string::vm_replace),
        );
        self.register(
            TypeDiscriminant::String,
            "contains",
            adapt!(crate::builtins::string::vm_contains),
        );
        self.register(
            TypeDiscriminant::String,
            "starts_with",
            adapt!(crate::builtins::string::vm_starts_with),
        );
        self.register(
            TypeDiscriminant::String,
            "ends_with",
            adapt!(crate::builtins::string::vm_ends_with),
        );

        // === Number Methods ===
        // Math functions use the factory pattern, so we must call them to get the fn pointer
        self.register(
            TypeDiscriminant::Number,
            "abs",
            adapt!(crate::builtins::math::vm_abs()),
        );
        self.register(
            TypeDiscriminant::Number,
            "ceil",
            adapt!(crate::builtins::math::vm_ceil()),
        );
        self.register(
            TypeDiscriminant::Number,
            "floor",
            adapt!(crate::builtins::math::vm_floor()),
        );
        self.register(
            TypeDiscriminant::Number,
            "round",
            adapt!(crate::builtins::math::vm_round()),
        );
        self.register(
            TypeDiscriminant::Number,
            "sqrt",
            adapt!(crate::builtins::math::vm_sqrt()),
        );
        self.register(
            TypeDiscriminant::Number,
            "str",
            adapt!(crate::builtins::utils::vm_str),
        );

        // === Complex Methods ===
        self.register(
            TypeDiscriminant::Complex,
            "re",
            adapt!(crate::builtins::complex::vm_real),
        );
        self.register(
            TypeDiscriminant::Complex,
            "im",
            adapt!(crate::builtins::complex::vm_imag),
        );
        self.register(
            TypeDiscriminant::Complex,
            "conj",
            adapt!(crate::builtins::complex::vm_conj),
        );
        self.register(
            TypeDiscriminant::Complex,
            "abs",
            adapt!(crate::builtins::complex::vm_magnitude),
        ); // Alias magnitude
        self.register(
            TypeDiscriminant::Complex,
            "mag",
            adapt!(crate::builtins::complex::vm_magnitude),
        );
        self.register(
            TypeDiscriminant::Complex,
            "arg",
            adapt!(crate::builtins::complex::vm_arg),
        ); // Alias phase
        self.register(
            TypeDiscriminant::Complex,
            "phase",
            adapt!(crate::builtins::complex::vm_phase),
        );

        // === Record Methods ===
        self.register(
            TypeDiscriminant::Record,
            "keys",
            adapt!(crate::builtins::records::vm_keys),
        );
        self.register(
            TypeDiscriminant::Record,
            "values",
            adapt!(crate::builtins::records::vm_values),
        );
        self.register(
            TypeDiscriminant::Record,
            "has",
            adapt!(crate::builtins::records::vm_has_field),
        );
    }
}
