//! Type inference for runtime values

use achronyme_parser::TypeAnnotation;
use achronyme_types::value::Value;
use std::collections::HashMap;

/// Infer the TypeAnnotation from a runtime Value
///
/// This function attempts to infer the most specific type annotation
/// for a given runtime value. Useful for type inference in gradual typing.
///
/// # Arguments
/// * `value` - The runtime value to infer the type from
///
/// # Returns
/// The inferred TypeAnnotation
pub fn infer_type(value: &Value) -> TypeAnnotation {
    // Auto-dereference MutableRef
    let actual_value = match value {
        Value::MutableRef(rc) => &*rc.borrow(),
        v => v,
    };

    match actual_value {
        Value::Number(_) => TypeAnnotation::Number,
        Value::Boolean(_) => TypeAnnotation::Boolean,
        Value::String(_) => TypeAnnotation::String,
        Value::Complex(_) => TypeAnnotation::Complex,
        Value::Vector(_) => TypeAnnotation::Vector,
        Value::Null => TypeAnnotation::Null,
        Value::Function(_) => TypeAnnotation::Function {
            params: vec![],
            return_type: Box::new(TypeAnnotation::Any),
        },
        Value::Tensor(t) => TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(t.shape().iter().map(|&d| Some(d)).collect()),
        },
        Value::ComplexTensor(t) => TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Complex),
            shape: Some(t.shape().iter().map(|&d| Some(d)).collect()),
        },
        Value::Record(fields) => {
            // (is_mutable, is_optional, type) - inferred fields are not mutable and not optional
            let type_fields: HashMap<String, (bool, bool, TypeAnnotation)> = fields
                .iter()
                .map(|(name, value)| (name.clone(), (false, false, infer_type(value))))
                .collect();
            TypeAnnotation::Record {
                fields: type_fields,
            }
        }
        Value::Edge { .. } => TypeAnnotation::Edge,
        // Internal values - should not appear in user code
        Value::TailCall(_) => TypeAnnotation::Any,
        Value::EarlyReturn(_) => TypeAnnotation::Any,
        Value::MutableRef(_) => unreachable!("MutableRef should be dereferenced"),
        // Generator type - represents an iterator
        Value::Generator(_) => TypeAnnotation::Any, // TODO: Add Generator type annotation
        // GeneratorYield is internal marker - should not appear in type inference
        Value::GeneratorYield(_) => TypeAnnotation::Any,
        // Error type - represents an error value
        Value::Error { .. } => TypeAnnotation::Error,
        // Loop control flow markers - internal, should not appear in type inference
        Value::LoopBreak(_) => TypeAnnotation::Any,
        Value::LoopContinue => TypeAnnotation::Any,
    }
}
