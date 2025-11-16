//! Specialized type validators for complex types

use achronyme_parser::TypeAnnotation;
use achronyme_types::value::Value;
use std::collections::HashMap;

/// Check structural typing for records
/// A record matches if it has all required fields with correct types (extra fields are OK)
/// Optional fields (marked with ?) are allowed to be absent
pub(crate) fn check_record_structural_type(
    required_fields: &HashMap<String, (bool, bool, TypeAnnotation)>,
    actual_fields: &HashMap<String, Value>,
) -> bool {
    required_fields.iter().all(|(field_name, (_is_mut, is_optional, field_type))| {
        match actual_fields.get(field_name) {
            Some(actual_value) => super::checker::matches_type(actual_value, field_type),
            None => *is_optional, // Missing field is OK only if optional
        }
    })
}

/// Check if a RealTensor matches a Tensor type annotation
pub(crate) fn check_real_tensor_type(
    tensor: &achronyme_types::tensor::RealTensor,
    element_type: &TypeAnnotation,
    expected_shape: Option<&Vec<Option<usize>>>,
) -> bool {
    // Check element type - RealTensor contains f64, so element type must be Number
    let element_type_matches = matches!(element_type, TypeAnnotation::Number | TypeAnnotation::Any);

    if !element_type_matches {
        return false;
    }

    // Check shape if specified
    match expected_shape {
        None => true, // No shape constraint
        Some(expected) => {
            let actual_shape = tensor.shape();
            // Rank must match
            if expected.len() != actual_shape.len() {
                return false;
            }
            // Each dimension must match (None means wildcard)
            expected.iter().zip(actual_shape).all(|(exp_dim, &act_dim)| {
                exp_dim.map_or(true, |e| e == act_dim)
            })
        }
    }
}

/// Check if a ComplexTensor matches a Tensor type annotation
pub(crate) fn check_complex_tensor_type(
    tensor: &achronyme_types::tensor::ComplexTensor,
    element_type: &TypeAnnotation,
    expected_shape: Option<&Vec<Option<usize>>>,
) -> bool {
    // Check element type - ComplexTensor contains Complex, so element type must be Complex
    let element_type_matches = matches!(element_type, TypeAnnotation::Complex | TypeAnnotation::Any);

    if !element_type_matches {
        return false;
    }

    // Check shape if specified
    match expected_shape {
        None => true, // No shape constraint
        Some(expected) => {
            let actual_shape = tensor.shape();
            // Rank must match
            if expected.len() != actual_shape.len() {
                return false;
            }
            // Each dimension must match (None means wildcard)
            expected.iter().zip(actual_shape).all(|(exp_dim, &act_dim)| {
                exp_dim.map_or(true, |e| e == act_dim)
            })
        }
    }
}

/// Check if a Function matches a Function type annotation
pub(crate) fn check_function_type(
    func: &achronyme_types::function::Function,
    expected_params: &Vec<Option<TypeAnnotation>>,
) -> bool {
    // Get the actual parameter count from the function
    let actual_param_count = func.arity();

    // If expected_params is empty, we don't check parameter count
    if expected_params.is_empty() {
        return true;
    }

    // Otherwise, check parameter count matches
    actual_param_count == expected_params.len()
}
