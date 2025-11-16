//! Core type checking logic

use achronyme_parser::TypeAnnotation;
use achronyme_types::value::Value;

use super::display::{get_value_type_name, type_annotation_to_string};
use super::error::TypeError;
use super::validators::{
    check_complex_tensor_type, check_function_type, check_real_tensor_type,
    check_record_structural_type,
};

/// Check if a runtime Value matches a TypeAnnotation
///
/// This function performs runtime type checking according to the gradual type system rules.
/// It automatically dereferences MutableRef values for checking.
///
/// # Arguments
/// * `value` - The runtime value to check
/// * `expected` - The expected type annotation
///
/// # Returns
/// * `Ok(())` if the value matches the expected type
/// * `Err(String)` with a descriptive error message if there's a mismatch
///
/// # Examples
/// ```ignore
/// use achronyme_parser::TypeAnnotation;
/// use achronyme_types::value::Value;
/// use achronyme_eval::type_checker::check_type;
///
/// // Simple type checking
/// assert!(check_type(&Value::Number(42.0), &TypeAnnotation::Number).is_ok());
///
/// // Union types
/// let union = TypeAnnotation::Union(vec![TypeAnnotation::Number, TypeAnnotation::String]);
/// assert!(check_type(&Value::Number(42.0), &union).is_ok());
/// assert!(check_type(&Value::String("hello".into()), &union).is_ok());
///
/// // Any type
/// assert!(check_type(&Value::Boolean(true), &TypeAnnotation::Any).is_ok());
/// ```
pub fn check_type(value: &Value, expected: &TypeAnnotation) -> Result<(), String> {
    // Auto-dereference MutableRef for type checking
    let actual_value = match value {
        Value::MutableRef(rc) => &*rc.borrow(),
        v => v,
    };

    if matches_type(actual_value, expected) {
        Ok(())
    } else {
        Err(format!(
            "Type mismatch: expected {}, got {}",
            type_annotation_to_string(expected),
            get_value_type_name(actual_value)
        ))
    }
}

/// Check if a Value matches a TypeAnnotation (internal helper)
pub(crate) fn matches_type(value: &Value, expected: &TypeAnnotation) -> bool {
    match expected {
        // Any type matches everything
        TypeAnnotation::Any => true,

        // Null type only matches null
        TypeAnnotation::Null => matches!(value, Value::Null),

        // Simple types
        TypeAnnotation::Number => matches!(value, Value::Number(_)),
        TypeAnnotation::Boolean => matches!(value, Value::Boolean(_)),
        TypeAnnotation::String => matches!(value, Value::String(_)),
        TypeAnnotation::Complex => matches!(value, Value::Complex(_)),

        // Vector type (heterogeneous, no element type checking)
        TypeAnnotation::Vector => matches!(value, Value::Vector(_)),

        // Edge type (graph edges)
        TypeAnnotation::Edge => matches!(value, Value::Edge { .. }),

        // Generator type (opaque, no yield type checking)
        TypeAnnotation::Generator => matches!(value, Value::Generator(_)),

        // Function type (opaque, accepts any function without signature checking)
        TypeAnnotation::AnyFunction => matches!(value, Value::Function(_)),

        // Union type: value must match at least one variant
        TypeAnnotation::Union(types) => types.iter().any(|t| matches_type(value, t)),

        // Record type with structural typing
        TypeAnnotation::Record { fields } => match value {
            Value::Record(actual_fields) => check_record_structural_type(fields, actual_fields),
            _ => false,
        },

        // Tensor type with optional shape checking
        TypeAnnotation::Tensor {
            element_type,
            shape,
        } => match value {
            Value::Tensor(tensor) => {
                check_real_tensor_type(tensor, element_type, shape.as_ref())
            }
            Value::ComplexTensor(tensor) => {
                check_complex_tensor_type(tensor, element_type, shape.as_ref())
            }
            _ => false,
        },

        // Function type checking
        TypeAnnotation::Function {
            params,
            return_type: _,
        } => match value {
            Value::Function(func) => check_function_type(func, params),
            _ => false,
        },

        // Type reference should be resolved before type checking
        TypeAnnotation::TypeReference(_) => {
            // This is an error condition - type references should be resolved first
            // Return false to indicate a type mismatch
            false
        }
    }
}

/// Check if a Value can be assigned to a type (with coercion rules)
///
/// This function is similar to `check_type` but returns a boolean and is intended
/// for use cases where you need to check assignability without throwing errors.
///
/// # Arguments
/// * `value` - The runtime value to check
/// * `expected` - The expected type annotation
///
/// # Returns
/// * `true` if the value can be assigned to the type
/// * `false` otherwise
pub fn is_assignable(value: &Value, expected: &TypeAnnotation) -> bool {
    // Auto-dereference MutableRef for type checking
    let actual_value = match value {
        Value::MutableRef(rc) => &*rc.borrow(),
        v => v,
    };

    matches_type(actual_value, expected)
}

/// Check if a Value matches a TypeAnnotation and return detailed error information
///
/// This function provides more detailed error information than `check_type`,
/// useful for generating comprehensive error messages.
///
/// # Arguments
/// * `value` - The runtime value to check
/// * `expected` - The expected type annotation
///
/// # Returns
/// * `Ok(())` if the value matches the expected type
/// * `Err(TypeError)` with detailed error information if there's a mismatch
pub fn check_type_detailed(value: &Value, expected: &TypeAnnotation) -> Result<(), TypeError> {
    // Auto-dereference MutableRef for type checking
    let actual_value = match value {
        Value::MutableRef(rc) => &*rc.borrow(),
        v => v,
    };

    if matches_type(actual_value, expected) {
        Ok(())
    } else {
        Err(TypeError::new(
            type_annotation_to_string(expected),
            get_value_type_name(actual_value),
        ))
    }
}
