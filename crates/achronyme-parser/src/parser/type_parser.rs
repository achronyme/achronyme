// Type Annotation Parser
//
// This module handles parsing of type annotations from Pest pairs into TypeAnnotation AST nodes.
// Supports:
// - Simple types: Number, Boolean, String, Complex, Edge
// - Union types: Number | String | null
// - Tensor types: Tensor<Number>, Tensor<Complex, [2,3]>
// - Record types: {name: String, mut age: Number}
// - Function types: (Number, Number) => Number
// - Any and null types

use crate::ast::AstNode;
use crate::parser::AstParser;
use crate::pest_parser::Rule;
use crate::type_annotation::TypeAnnotation;
use pest::iterators::Pair;
use std::collections::HashMap;

impl AstParser {
    /// Parse a type annotation from a Pest pair
    /// Entry point for all type annotation parsing
    pub(super) fn parse_type_annotation(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<TypeAnnotation, String> {
        match pair.as_rule() {
            Rule::type_annotation => {
                // type_annotation can be either union_type or simple_type_with_optional
                let inner = pair.into_inner().next().ok_or("Empty type annotation")?;
                self.parse_type_annotation(inner)
            }
            Rule::simple_type_with_optional => {
                // simple_type_annotation optionally followed by ?
                let mut inner = pair.into_inner();
                let base_type_pair = inner.next().ok_or("Empty simple_type_with_optional")?;
                let base_type = self.parse_type_annotation(base_type_pair)?;

                // Check if there's an optional_type_suffix (?)
                if inner.next().is_some() {
                    // Has ?, make it T | null
                    if matches!(base_type, TypeAnnotation::Null) {
                        Ok(TypeAnnotation::Null)
                    } else if let TypeAnnotation::Union(types) = &base_type {
                        if types.iter().any(|t| matches!(t, TypeAnnotation::Null)) {
                            Ok(base_type) // Already contains null
                        } else {
                            let mut new_types = types.clone();
                            new_types.push(TypeAnnotation::Null);
                            Ok(TypeAnnotation::Union(new_types))
                        }
                    } else {
                        Ok(TypeAnnotation::Union(vec![base_type, TypeAnnotation::Null]))
                    }
                } else {
                    Ok(base_type)
                }
            }
            Rule::union_type => self.parse_union_type(pair),
            Rule::simple_type_annotation => {
                let inner = pair
                    .into_inner()
                    .next()
                    .ok_or("Empty simple type annotation")?;
                self.parse_type_annotation(inner)
            }
            Rule::simple_type => self.parse_simple_type(pair),
            Rule::tensor_type => self.parse_tensor_type(pair),
            Rule::vector_type => Ok(TypeAnnotation::Vector),
            Rule::record_type => self.parse_record_type(pair),
            Rule::function_type => self.parse_function_type(pair),
            Rule::grouped_type => {
                // Grouped type just unwraps: ((Number) => String) -> (Number) => String
                let inner = pair.into_inner().next().ok_or("Empty grouped type")?;
                self.parse_type_annotation(inner)
            }
            Rule::any_type => Ok(TypeAnnotation::Any),
            Rule::null_type => Ok(TypeAnnotation::Null),
            Rule::type_reference => {
                // Type reference: identifier for type aliases (e.g., Point, Result, ApiResponse)
                let name = pair
                    .into_inner()
                    .next()
                    .ok_or("Empty type reference")?
                    .as_str()
                    .to_string();

                // Block IEEE 754 special values from being used as types
                if name == "Infinity" {
                    return Err(
                        "'Infinity' is a value of type Number, not a type. Use 'Number' instead."
                            .to_string(),
                    );
                }
                if name == "NaN" {
                    return Err(
                        "'NaN' is a value of type Number, not a type. Use 'Number' instead."
                            .to_string(),
                    );
                }

                Ok(TypeAnnotation::TypeReference(name))
            }
            _ => Err(format!(
                "Unexpected type annotation rule: {:?}",
                pair.as_rule()
            )),
        }
    }

    /// Parse simple types: Number, Boolean, String, Complex, Generator, Edge, Error
    fn parse_simple_type(&mut self, pair: Pair<Rule>) -> Result<TypeAnnotation, String> {
        let type_str = pair.as_str();
        match type_str {
            "Number" => Ok(TypeAnnotation::Number),
            "Boolean" => Ok(TypeAnnotation::Boolean),
            "String" => Ok(TypeAnnotation::String),
            "Complex" => Ok(TypeAnnotation::Complex),
            "Generator" => Ok(TypeAnnotation::Generator),
            "Function" => Ok(TypeAnnotation::AnyFunction),
            "Error" => Ok(TypeAnnotation::Error),
            "Edge" => Ok(TypeAnnotation::Edge),
            _ => Err(format!("Unknown simple type: {}", type_str)),
        }
    }

    /// Parse union types: Number | String | null
    fn parse_union_type(&mut self, pair: Pair<Rule>) -> Result<TypeAnnotation, String> {
        let mut types = Vec::new();

        for inner in pair.into_inner() {
            let ty = self.parse_type_annotation(inner)?;
            types.push(ty);
        }

        if types.is_empty() {
            return Err("Union type must have at least one type".to_string());
        }

        // If only one type, return it directly (optimization)
        if types.len() == 1 {
            return Ok(types.into_iter().next().unwrap());
        }

        Ok(TypeAnnotation::Union(types))
    }

    /// Parse tensor types: Tensor<Number> or Tensor<Complex, [2,3]>
    fn parse_tensor_type(&mut self, pair: Pair<Rule>) -> Result<TypeAnnotation, String> {
        let mut inner = pair.into_inner();

        // First element is the element type
        let element_type = inner.next().ok_or("Missing element type in Tensor")?;
        let element_type = Box::new(self.parse_type_annotation(element_type)?);

        // Optional shape specification
        let shape = if let Some(shape_pair) = inner.next() {
            Some(self.parse_shape_spec(shape_pair)?)
        } else {
            None
        };

        Ok(TypeAnnotation::Tensor {
            element_type,
            shape,
        })
    }

    /// Parse shape specification: [2, 3] or [_, _]
    fn parse_shape_spec(&mut self, pair: Pair<Rule>) -> Result<Vec<Option<usize>>, String> {
        let mut dims = Vec::new();

        for dim_pair in pair.into_inner() {
            let dim = self.parse_dimension(dim_pair)?;
            dims.push(dim);
        }

        Ok(dims)
    }

    /// Parse a single dimension: number or _
    fn parse_dimension(&mut self, pair: Pair<Rule>) -> Result<Option<usize>, String> {
        let dim_str = pair.as_str();

        if dim_str == "_" {
            Ok(None) // Unknown dimension
        } else {
            // Parse as number
            dim_str
                .parse::<usize>()
                .map(Some)
                .map_err(|e| format!("Invalid dimension '{}': {}", dim_str, e))
        }
    }

    /// Parse record types: {name: String, mut age?: Number}
    fn parse_record_type(&mut self, pair: Pair<Rule>) -> Result<TypeAnnotation, String> {
        let mut fields = HashMap::new();

        for field_pair in pair.into_inner() {
            if field_pair.as_rule() != Rule::record_type_field {
                continue;
            }

            let mut field_inner = field_pair.into_inner();

            // Check for mut keyword
            let first = field_inner.next().ok_or("Empty record field")?;

            let (is_mutable, field_name, is_optional, field_type) = if first.as_rule()
                == Rule::mut_keyword
            {
                // Mutable field: mut name?: Type
                let name = field_inner
                    .next()
                    .ok_or("Missing field name after mut")?
                    .as_str()
                    .to_string();

                // Check for optional marker
                let next = field_inner
                    .next()
                    .ok_or("Missing field type or optional marker")?;
                let (is_optional, type_annotation) = if next.as_rule() == Rule::optional_marker {
                    let ta = field_inner
                        .next()
                        .ok_or("Missing field type after optional marker")?;
                    (true, ta)
                } else {
                    (false, next)
                };

                let ty = self.parse_type_annotation(type_annotation)?;
                (true, name, is_optional, ty)
            } else {
                // Immutable field: name?: Type
                let name = first.as_str().to_string();

                // Check for optional marker
                let next = field_inner
                    .next()
                    .ok_or("Missing field type or optional marker")?;
                let (is_optional, type_annotation) = if next.as_rule() == Rule::optional_marker {
                    let ta = field_inner
                        .next()
                        .ok_or("Missing field type after optional marker")?;
                    (true, ta)
                } else {
                    (false, next)
                };

                let ty = self.parse_type_annotation(type_annotation)?;
                (false, name, is_optional, ty)
            };

            fields.insert(field_name, (is_mutable, is_optional, field_type));
        }

        Ok(TypeAnnotation::Record { fields })
    }

    /// Parse function types: (Number, String): Boolean
    fn parse_function_type(&mut self, pair: Pair<Rule>) -> Result<TypeAnnotation, String> {
        let inner = pair.into_inner();

        // Collect all type annotations
        // Grammar: "(" ~ (type_annotation ~ ("," ~ type_annotation)*)? ~ ")" ~ ":" ~ type_annotation
        // All children are type_annotation pairs, the last one is the return type
        let mut params = Vec::new();
        let mut return_type_pair = None;

        for type_pair in inner {
            // The last one is the return type
            if return_type_pair.is_some() {
                // We already found return type, so previous one was a param
                let param_ty = self.parse_type_annotation(return_type_pair.take().unwrap())?;
                params.push(Some(param_ty));
            }
            return_type_pair = Some(type_pair);
        }

        // Parse return type (the last pair we collected)
        let return_type = if let Some(rt) = return_type_pair {
            Box::new(self.parse_type_annotation(rt)?)
        } else {
            return Err("Function type missing return type".to_string());
        };

        Ok(TypeAnnotation::Function {
            params,
            return_type,
        })
    }

    /// Parse typed parameter: x, x: Number, x = default, or x: Number = default
    /// Also supports optional parameters: x? (optional untyped) OR x?: Type (optional typed)
    /// Optional parameters are equivalent to having a default value of null, and their type
    /// becomes Type | null (or just null if untyped)
    pub(super) fn parse_typed_param(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<(String, Option<TypeAnnotation>, Option<Box<AstNode>>), String> {
        let mut inner = pair.into_inner();

        // First is always the identifier
        let identifier = inner
            .next()
            .ok_or("Missing identifier in typed parameter")?
            .as_str()
            .to_string();

        // Optional marker, type annotation and default value
        let mut is_optional = false;
        let mut type_annotation = None;
        let mut default_value = None;

        // Check remaining pairs
        for next_pair in inner {
            match next_pair.as_rule() {
                Rule::optional_marker => {
                    is_optional = true;
                }
                Rule::type_annotation => {
                    type_annotation = Some(self.parse_type_annotation(next_pair)?);
                }
                Rule::expr => {
                    default_value = Some(Box::new(self.build_ast_from_expr(next_pair)?));
                }
                _ => {}
            }
        }

        // Handle optional parameters: they get a null default and their type becomes T | null
        if is_optional {
            // If parameter is optional but already has a default, error
            if default_value.is_some() {
                return Err(format!(
                    "Parameter '{}' cannot be both optional (?) and have a default value",
                    identifier
                ));
            }

            // Set default value to null
            default_value = Some(Box::new(AstNode::Null));

            // Make type T | null (or null if no type specified)
            type_annotation = match type_annotation {
                Some(ty) => {
                    // Don't double-wrap if it's already a union containing null
                    if let TypeAnnotation::Union(types) = &ty {
                        if types.iter().any(|t| matches!(t, TypeAnnotation::Null)) {
                            Some(ty) // Already contains null
                        } else {
                            // Add null to the union
                            let mut new_types = types.clone();
                            new_types.push(TypeAnnotation::Null);
                            Some(TypeAnnotation::Union(new_types))
                        }
                    } else if matches!(ty, TypeAnnotation::Null) {
                        Some(TypeAnnotation::Null)
                    } else {
                        // Create union with null
                        Some(TypeAnnotation::Union(vec![ty, TypeAnnotation::Null]))
                    }
                }
                None => None, // Keep it untyped (dynamic)
            };
        }

        Ok((identifier, type_annotation, default_value))
    }

    /// Parse typed lambda parameters: x, (x, y), or (x: Number, y: String)
    /// Now supports default values: (x: Number = 10, y = "hello")
    pub(super) fn parse_typed_lambda_params(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<Vec<(String, Option<TypeAnnotation>, Option<Box<AstNode>>)>, String> {
        let mut params = Vec::new();
        let mut had_default = false;

        for param_pair in pair.into_inner() {
            if param_pair.as_rule() == Rule::typed_param {
                let (name, ty, default) = self.parse_typed_param(param_pair)?;

                // Check that parameters with defaults come after parameters without
                if default.is_some() {
                    had_default = true;
                } else if had_default {
                    return Err(format!(
                        "Parameter '{}' without default value cannot come after parameters with defaults",
                        name
                    ));
                }

                params.push((name, ty, default));
            }
        }

        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pest_parser::SOCParser;
    use pest::Parser;

    #[test]
    fn test_parse_simple_types() {
        let mut parser = AstParser::new();

        let pairs = SOCParser::parse(Rule::type_annotation, "Number").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();
        assert_eq!(ty, TypeAnnotation::Number);

        let pairs = SOCParser::parse(Rule::type_annotation, "Boolean").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();
        assert_eq!(ty, TypeAnnotation::Boolean);
    }

    #[test]
    fn test_parse_union_types() {
        let mut parser = AstParser::new();

        let pairs = SOCParser::parse(Rule::type_annotation, "Number | String").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Union(types) => {
                assert_eq!(types.len(), 2);
                assert_eq!(types[0], TypeAnnotation::Number);
                assert_eq!(types[1], TypeAnnotation::String);
            }
            _ => panic!("Expected Union type, got {:?}", ty),
        }
    }

    #[test]
    fn test_parse_tensor_types() {
        let mut parser = AstParser::new();

        // Tensor<Number>
        let pairs = SOCParser::parse(Rule::type_annotation, "Tensor<Number>").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Tensor {
                element_type,
                shape,
            } => {
                assert_eq!(*element_type, TypeAnnotation::Number);
                assert!(shape.is_none());
            }
            _ => panic!("Expected Tensor type, got {:?}", ty),
        }

        // Tensor<Number, [2, 3]>
        let pairs = SOCParser::parse(Rule::type_annotation, "Tensor<Number, [2, 3]>").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Tensor {
                element_type,
                shape,
            } => {
                assert_eq!(*element_type, TypeAnnotation::Number);
                assert_eq!(shape, Some(vec![Some(2), Some(3)]));
            }
            _ => panic!("Expected Tensor type, got {:?}", ty),
        }
    }

    #[test]
    fn test_parse_record_types() {
        let mut parser = AstParser::new();

        let pairs = SOCParser::parse(Rule::type_annotation, "{name: String, age: Number}").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Record { fields } => {
                assert_eq!(fields.len(), 2);
                // Fields are now (is_mutable, is_optional, type)
                assert_eq!(
                    fields.get("name"),
                    Some(&(false, false, TypeAnnotation::String))
                );
                assert_eq!(
                    fields.get("age"),
                    Some(&(false, false, TypeAnnotation::Number))
                );
            }
            _ => panic!("Expected Record type, got {:?}", ty),
        }
    }

    #[test]
    fn test_parse_null_and_any() {
        let mut parser = AstParser::new();

        let pairs = SOCParser::parse(Rule::type_annotation, "null").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();
        assert_eq!(ty, TypeAnnotation::Null);

        let pairs = SOCParser::parse(Rule::type_annotation, "Any").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();
        assert_eq!(ty, TypeAnnotation::Any);
    }

    #[test]
    fn test_parse_optional_fields() {
        let mut parser = AstParser::new();

        // Test optional field with ?
        let pairs =
            SOCParser::parse(Rule::type_annotation, "{name: String, age?: Number}").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Record { fields } => {
                assert_eq!(fields.len(), 2);
                // Fields are (is_mutable, is_optional, type)
                assert_eq!(
                    fields.get("name"),
                    Some(&(false, false, TypeAnnotation::String))
                );
                assert_eq!(
                    fields.get("age"),
                    Some(&(false, true, TypeAnnotation::Number))
                );
            }
            _ => panic!("Expected Record type, got {:?}", ty),
        }
    }

    #[test]
    fn test_parse_mutable_optional_field() {
        let mut parser = AstParser::new();

        // Test mutable optional field
        let pairs = SOCParser::parse(Rule::type_annotation, "{mut value?: Number}").unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Record { fields } => {
                assert_eq!(fields.len(), 1);
                // Fields are (is_mutable, is_optional, type)
                assert_eq!(
                    fields.get("value"),
                    Some(&(true, true, TypeAnnotation::Number))
                );
            }
            _ => panic!("Expected Record type, got {:?}", ty),
        }
    }

    #[test]
    fn test_parse_mixed_optional_fields() {
        let mut parser = AstParser::new();

        // Test mixed fields: required, optional, mutable optional
        let pairs = SOCParser::parse(
            Rule::type_annotation,
            "{id: Number, name?: String, mut count?: Number}",
        )
        .unwrap();
        let ty = parser
            .parse_type_annotation(pairs.into_iter().next().unwrap())
            .unwrap();

        match ty {
            TypeAnnotation::Record { fields } => {
                assert_eq!(fields.len(), 3);
                assert_eq!(
                    fields.get("id"),
                    Some(&(false, false, TypeAnnotation::Number))
                );
                assert_eq!(
                    fields.get("name"),
                    Some(&(false, true, TypeAnnotation::String))
                );
                assert_eq!(
                    fields.get("count"),
                    Some(&(true, true, TypeAnnotation::Number))
                );
            }
            _ => panic!("Expected Record type, got {:?}", ty),
        }
    }
}
