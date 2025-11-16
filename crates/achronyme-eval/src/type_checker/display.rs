//! Display and conversion utilities for types

use achronyme_parser::TypeAnnotation;
use achronyme_types::value::Value;

/// Get a human-readable type name for a runtime Value
pub(crate) fn get_value_type_name(value: &Value) -> String {
    match value {
        Value::Number(_) => "Number".to_string(),
        Value::Boolean(_) => "Boolean".to_string(),
        Value::String(_) => "String".to_string(),
        Value::Complex(_) => "Complex".to_string(),
        Value::Vector(_) => "Vector".to_string(),
        Value::Tensor(t) => format!("Tensor<Number, [{:?}]>", t.shape()),
        Value::ComplexTensor(t) => format!("Tensor<Complex, [{:?}]>", t.shape()),
        Value::Function(_) => "Function".to_string(),
        Value::Record(fields) => {
            let field_names: Vec<_> = fields.keys().cloned().collect();
            format!("Record{{{}}}", field_names.join(", "))
        }
        Value::Edge { .. } => "Edge".to_string(),
        Value::TailCall(_) => "TailCall (internal)".to_string(),
        Value::EarlyReturn(_) => "EarlyReturn (internal)".to_string(),
        Value::MutableRef(_) => "MutableRef".to_string(),
        Value::Null => "null".to_string(),
        Value::Generator(_) => "Generator".to_string(),
        Value::GeneratorYield(_) => "GeneratorYield (internal)".to_string(),
        Value::Error { .. } => "Error".to_string(),
        Value::LoopBreak(_) => "LoopBreak (internal)".to_string(),
        Value::LoopContinue => "LoopContinue (internal)".to_string(),
    }
}

/// Get a human-readable string representation of a TypeAnnotation
pub(crate) fn type_annotation_to_string(ty: &TypeAnnotation) -> String {
    match ty {
        TypeAnnotation::Number => "Number".to_string(),
        TypeAnnotation::Boolean => "Boolean".to_string(),
        TypeAnnotation::String => "String".to_string(),
        TypeAnnotation::Complex => "Complex".to_string(),
        TypeAnnotation::Vector => "Vector".to_string(),
        TypeAnnotation::Edge => "Edge".to_string(),
        TypeAnnotation::Generator => "Generator".to_string(),
        TypeAnnotation::Error => "Error".to_string(),
        TypeAnnotation::AnyFunction => "Function".to_string(),
        TypeAnnotation::Null => "null".to_string(),
        TypeAnnotation::Any => "Any".to_string(),

        TypeAnnotation::Tensor {
            element_type,
            shape,
        } => {
            let elem_str = type_annotation_to_string(element_type);
            match shape {
                None => format!("Tensor<{}>", elem_str),
                Some(dims) => {
                    let dims_str = dims
                        .iter()
                        .map(|d| d.map_or("_".to_string(), |n| n.to_string()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("Tensor<{}, [{}]>", elem_str, dims_str)
                }
            }
        }

        TypeAnnotation::Record { fields } => {
            if fields.is_empty() {
                "{}".to_string()
            } else {
                let fields_str = fields
                    .iter()
                    .map(|(name, (is_mut, is_optional, ty))| {
                        let optional_marker = if *is_optional { "?" } else { "" };
                        if *is_mut {
                            format!("mut {}{}: {}", name, optional_marker, type_annotation_to_string(ty))
                        } else {
                            format!("{}{}: {}", name, optional_marker, type_annotation_to_string(ty))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{{{}}}", fields_str)
            }
        }

        TypeAnnotation::Function {
            params,
            return_type,
        } => {
            let params_str = params
                .iter()
                .map(|p| {
                    p.as_ref()
                        .map_or("Any".to_string(), type_annotation_to_string)
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "({}) -> {}",
                params_str,
                type_annotation_to_string(return_type)
            )
        }

        TypeAnnotation::Union(types) => types
            .iter()
            .map(type_annotation_to_string)
            .collect::<Vec<_>>()
            .join(" | "),

        TypeAnnotation::TypeReference(name) => {
            // Type references should be resolved before reaching here
            format!("<unresolved type: {}>", name)
        }
    }
}
