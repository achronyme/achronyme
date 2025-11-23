// Type Annotation System for Gradual Typing (AST representation)
//
// This module implements the type annotation representation in the AST.
// It is independent of runtime values (Value enum) to avoid circular dependencies.
// Type checking against runtime values happens in the VM runtime.
//
// Supports:
// - Simple types (Number, Boolean, String, Complex)
// - Tensor types with optional shape specifications
// - Union types (A | B | C) - CORE FEATURE
// - Record types with structural subtyping (duck typing)
// - Function types
// - Null type for optional values
// - Any type (opt-out of type checking)

use std::collections::HashMap;

/// Type annotation for gradual typing system (AST representation)
#[derive(Debug, Clone, PartialEq)]
pub enum TypeAnnotation {
    /// Number type (f64)
    Number,

    /// Boolean type
    Boolean,

    /// String type
    String,

    /// Complex number type
    Complex,

    /// Tensor type with optional element type and shape
    /// shape: None = unknown rank, Some(vec) = known rank with optional dimensions
    /// Example: Tensor<Number> has shape=None
    /// Example: Tensor<Number, [2, 3]> has shape=Some(vec![Some(2), Some(3)])
    /// Example: Tensor<Number, [_, _]> has shape=Some(vec![None, None])
    Tensor {
        element_type: Box<TypeAnnotation>,
        shape: Option<Vec<Option<usize>>>,
    },

    /// Vector type (heterogeneous array)
    Vector,

    /// Record type with structural typing
    /// HashMap<field_name, (is_mutable, is_optional, field_type)>
    /// is_optional: true means the field can be absent (uses ?)
    Record {
        fields: HashMap<String, (bool, bool, TypeAnnotation)>,
    },

    /// Function type
    /// params: parameter types (None for untyped parameters in gradual typing)
    /// return_type: return type
    Function {
        params: Vec<Option<TypeAnnotation>>,
        return_type: Box<TypeAnnotation>,
    },

    /// Edge type (graph edges: A -> B, A <> B)
    Edge,

    /// Generator type (opaque, does not track yield type)
    /// Represents a resumable function that can yield values
    /// Future: Generator<T> for typed generators
    Generator,

    /// Error type (opaque, represents any error value)
    /// Used for try/catch/throw error handling
    /// Error values have message, optional kind, and optional source
    Error,

    /// Opaque function type (accepts any function without checking signature)
    /// Use when you need to accept any callable, regardless of params/return
    /// Example: let higher: (AnyFunction, Number): Number = (f, n) => f(n)
    AnyFunction,

    /// Union type (CORE FEATURE)
    /// Represents "one of these types"
    /// Example: Number | String | null
    Union(Vec<TypeAnnotation>),

    /// Null type (for optional values)
    /// Example: Number | null for optional numbers
    Null,

    /// Any type (opt-out of type checking)
    /// Accepts any value
    Any,

    /// Type reference (alias to another type definition)
    /// Example: Point, Result, ApiResponse
    TypeReference(String),
}

impl std::fmt::Display for TypeAnnotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeAnnotation::Number => write!(f, "Number"),
            TypeAnnotation::Boolean => write!(f, "Boolean"),
            TypeAnnotation::String => write!(f, "String"),
            TypeAnnotation::Complex => write!(f, "Complex"),
            TypeAnnotation::Vector => write!(f, "Vector"),
            TypeAnnotation::Edge => write!(f, "Edge"),
            TypeAnnotation::Generator => write!(f, "Generator"),
            TypeAnnotation::Error => write!(f, "Error"),
            TypeAnnotation::AnyFunction => write!(f, "Function"),
            TypeAnnotation::Null => write!(f, "null"),
            TypeAnnotation::Any => write!(f, "Any"),

            TypeAnnotation::Tensor {
                element_type,
                shape,
            } => match shape {
                None => write!(f, "Tensor<{}>", element_type),
                Some(dims) => {
                    let dims_str = dims
                        .iter()
                        .map(|d| d.map_or("_".to_string(), |n| n.to_string()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    write!(f, "Tensor<{}, [{}]>", element_type, dims_str)
                }
            },

            TypeAnnotation::Record { fields } => {
                if fields.is_empty() {
                    write!(f, "{{}}")
                } else {
                    let fields_str = fields
                        .iter()
                        .map(|(name, (is_mut, is_optional, ty))| {
                            let optional_marker = if *is_optional { "?" } else { "" };
                            if *is_mut {
                                format!("mut {}{}: {}", name, optional_marker, ty)
                            } else {
                                format!("{}{}: {}", name, optional_marker, ty)
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    write!(f, "{{{}}}", fields_str)
                }
            }

            TypeAnnotation::Function {
                params,
                return_type,
            } => {
                let params_str = params
                    .iter()
                    .map(|p| p.as_ref().map_or("Any".to_string(), |t| t.to_string()))
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "({}) => {}", params_str, return_type)
            }

            TypeAnnotation::Union(types) => {
                let types_str = types
                    .iter()
                    .map(|t| t.to_string())
                    .collect::<Vec<_>>()
                    .join(" | ");
                write!(f, "{}", types_str)
            }

            TypeAnnotation::TypeReference(name) => write!(f, "{}", name),
        }
    }
}

impl TypeAnnotation {
    /// Check if this type is assignable from another type (for type checking)
    /// This is a simplified version - full checking happens in the evaluator
    pub fn is_assignable_from(&self, other: &TypeAnnotation) -> bool {
        // Same types are assignable
        if self == other {
            return true;
        }

        match (self, other) {
            // Any accepts anything
            (TypeAnnotation::Any, _) | (_, TypeAnnotation::Any) => true,

            // Union type matching
            (TypeAnnotation::Union(types), other) => {
                types.iter().any(|t| t.is_assignable_from(other))
            }
            (self_type, TypeAnnotation::Union(other_types)) => other_types
                .iter()
                .all(|ot| self_type.is_assignable_from(ot)),

            // Record structural subtyping (simplified)
            (
                TypeAnnotation::Record {
                    fields: self_fields,
                },
                TypeAnnotation::Record {
                    fields: other_fields,
                },
            ) => {
                self_fields
                    .iter()
                    .all(|(field_name, (self_mut, self_optional, self_type))| {
                        match other_fields.get(field_name) {
                            Some((other_mut, _other_optional, other_type)) => {
                                // Field exists - check mutability and type
                                self_mut == other_mut && self_type.is_assignable_from(other_type)
                            }
                            None => {
                                // Field doesn't exist - only OK if self expects it to be optional
                                *self_optional
                            }
                        }
                    })
            }

            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_to_string() {
        assert_eq!(TypeAnnotation::Number.to_string(), "Number");
        assert_eq!(TypeAnnotation::Boolean.to_string(), "Boolean");

        let union = TypeAnnotation::Union(vec![TypeAnnotation::Number, TypeAnnotation::String]);
        assert_eq!(union.to_string(), "Number | String");
    }

    #[test]
    fn test_union_assignability() {
        let union = TypeAnnotation::Union(vec![TypeAnnotation::Number, TypeAnnotation::String]);

        assert!(union.is_assignable_from(&TypeAnnotation::Number));
        assert!(union.is_assignable_from(&TypeAnnotation::String));
        assert!(!union.is_assignable_from(&TypeAnnotation::Boolean));
    }

    #[test]
    fn test_any_type() {
        assert!(TypeAnnotation::Any.is_assignable_from(&TypeAnnotation::Number));
        assert!(TypeAnnotation::Number.is_assignable_from(&TypeAnnotation::Any));
    }
}
