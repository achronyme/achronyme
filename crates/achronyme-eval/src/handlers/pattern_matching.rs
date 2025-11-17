use achronyme_parser::ast::{AstNode, Pattern, LiteralPattern, VectorPatternElement, MatchArm};
use achronyme_types::value::Value;
use std::collections::HashMap;

use crate::evaluator::Evaluator;

/// Evaluate a match expression
/// Tries each arm in order until one matches, then evaluates its body
pub fn evaluate_match(
    evaluator: &mut Evaluator,
    value: &AstNode,
    arms: &[MatchArm],
) -> Result<Value, String> {
    // Evaluate the value to match
    let match_value = evaluator.evaluate(value)?;

    // Try each arm in order
    for arm in arms {
        // Try to match the pattern
        if let Some(bindings) = match_pattern(&match_value, &arm.pattern)? {
            // Pattern matched! Check guard if present
            if let Some(guard) = &arm.guard {
                // Create scope with pattern bindings for guard evaluation
                evaluator.environment_mut().push_scope();
                for (name, val) in &bindings {
                    evaluator.environment_mut().define(name.clone(), val.clone())?;
                }

                // Evaluate the guard
                let guard_result = evaluator.evaluate(guard);

                // Check if guard passed
                let guard_passed = match guard_result {
                    Ok(Value::Boolean(b)) => b,
                    Ok(Value::Number(n)) => n != 0.0,
                    Ok(_) => {
                        evaluator.environment_mut().pop_scope();
                        return Err("Match guard must evaluate to boolean or number".to_string());
                    }
                    Err(e) => {
                        evaluator.environment_mut().pop_scope();
                        return Err(e);
                    }
                };

                if !guard_passed {
                    // Guard failed, try next arm
                    evaluator.environment_mut().pop_scope();
                    continue;
                }

                // Guard passed, evaluate body with bindings already in scope
                let result = evaluator.evaluate(&arm.body);
                evaluator.environment_mut().pop_scope();
                return result;
            } else {
                // No guard, just evaluate the body with bindings
                evaluator.environment_mut().push_scope();
                for (name, val) in bindings {
                    evaluator.environment_mut().define(name, val)?;
                }

                let result = evaluator.evaluate(&arm.body);
                evaluator.environment_mut().pop_scope();
                return result;
            }
        }
    }

    // No pattern matched
    Err("Match expression: no pattern matched the value".to_string())
}

/// Try to match a value against a pattern
/// Returns Some(bindings) if matched, None if not matched
/// Returns Err for errors during matching
pub fn match_pattern(value: &Value, pattern: &Pattern) -> Result<Option<HashMap<String, Value>>, String> {
    match pattern {
        Pattern::Wildcard => {
            // Wildcard matches anything
            Ok(Some(HashMap::new()))
        }

        Pattern::Variable(name) => {
            // Variable binds the value
            let mut bindings = HashMap::new();
            bindings.insert(name.clone(), value.clone());
            Ok(Some(bindings))
        }

        Pattern::Literal(lit) => match_literal(value, lit),

        Pattern::Type(type_name) => match_type(value, type_name),

        Pattern::Record { fields } => match_record_no_defaults(value, fields),

        Pattern::Vector { elements } => match_vector_no_defaults(value, elements),
    }
}

/// Try to match a value against a pattern with default support
/// This version uses the evaluator to lazily evaluate defaults when needed
/// Returns Some(bindings) if matched, None if not matched
/// Returns Err for errors during matching
pub fn match_pattern_with_defaults(
    evaluator: &mut Evaluator,
    value: &Value,
    pattern: &Pattern,
) -> Result<Option<HashMap<String, Value>>, String> {
    match pattern {
        Pattern::Wildcard => {
            // Wildcard matches anything
            Ok(Some(HashMap::new()))
        }

        Pattern::Variable(name) => {
            // Variable binds the value
            let mut bindings = HashMap::new();
            bindings.insert(name.clone(), value.clone());
            Ok(Some(bindings))
        }

        Pattern::Literal(lit) => match_literal(value, lit),

        Pattern::Type(type_name) => match_type(value, type_name),

        Pattern::Record { fields } => match_record_with_defaults(evaluator, value, fields),

        Pattern::Vector { elements } => match_vector_with_defaults(evaluator, value, elements),
    }
}

/// Match a value against a literal pattern
fn match_literal(value: &Value, lit: &LiteralPattern) -> Result<Option<HashMap<String, Value>>, String> {
    let matched = match (value, lit) {
        (Value::Number(n), LiteralPattern::Number(expected)) => {
            // Use approximate equality for floating point
            (n - expected).abs() < f64::EPSILON
        }
        (Value::String(s), LiteralPattern::String(expected)) => s == expected,
        (Value::Boolean(b), LiteralPattern::Boolean(expected)) => b == expected,
        (Value::Null, LiteralPattern::Null) => true,
        _ => false,
    };

    if matched {
        Ok(Some(HashMap::new()))
    } else {
        Ok(None)
    }
}

/// Match a value against a type pattern
fn match_type(value: &Value, type_name: &str) -> Result<Option<HashMap<String, Value>>, String> {
    let matched = match (value, type_name) {
        (Value::Number(_), "Number") => true,
        (Value::Boolean(_), "Boolean") => true,
        (Value::String(_), "String") => true,
        (Value::Complex(_), "Complex") => true,
        (Value::Vector(_), "Vector") => true,
        (Value::Tensor(_), "Tensor") => true,
        (Value::ComplexTensor(_), "Tensor") => true,
        (Value::Function(_), "Function") => true,
        (Value::Record(_), "Record") => true,
        (Value::Edge { .. }, "Edge") => true,
        (Value::Generator(_), "Generator") => true,
        (Value::Error { .. }, "Error") => true,
        (Value::Null, "Null") => true,
        _ => false,
    };

    if matched {
        Ok(Some(HashMap::new()))
    } else {
        Ok(None)
    }
}

/// Match a value against a record pattern (without defaults, for match expressions)
fn match_record_no_defaults(value: &Value, fields: &[(String, Pattern, Option<Box<AstNode>>)]) -> Result<Option<HashMap<String, Value>>, String> {
    let record_map = match value {
        Value::Record(map) => map,
        // Also handle Error values as they have named fields
        Value::Error { message, kind, source } => {
            // Create a temporary map for error fields
            let mut map = HashMap::new();
            map.insert("message".to_string(), Value::String(message.clone()));
            if let Some(k) = kind {
                map.insert("kind".to_string(), Value::String(k.clone()));
            }
            if let Some(src) = source {
                map.insert("source".to_string(), (**src).clone());
            }
            // We need to return early here because we're creating a temporary
            return match_record_fields_no_defaults(&map, fields);
        }
        _ => return Ok(None),
    };

    match_record_fields_no_defaults(record_map, fields)
}

/// Match a value against a record pattern with defaults (for destructuring)
fn match_record_with_defaults(
    evaluator: &mut Evaluator,
    value: &Value,
    fields: &[(String, Pattern, Option<Box<AstNode>>)],
) -> Result<Option<HashMap<String, Value>>, String> {
    let record_map = match value {
        Value::Record(map) => map,
        // Also handle Error values as they have named fields
        Value::Error { message, kind, source } => {
            // Create a temporary map for error fields
            let mut map = HashMap::new();
            map.insert("message".to_string(), Value::String(message.clone()));
            if let Some(k) = kind {
                map.insert("kind".to_string(), Value::String(k.clone()));
            }
            if let Some(src) = source {
                map.insert("source".to_string(), (**src).clone());
            }
            // We need to return early here because we're creating a temporary
            return match_record_fields_with_defaults(evaluator, &map, fields);
        }
        _ => return Ok(None),
    };

    match_record_fields_with_defaults(evaluator, record_map, fields)
}

/// Helper to match record fields against pattern fields (no defaults)
fn match_record_fields_no_defaults(
    record_map: &HashMap<String, Value>,
    fields: &[(String, Pattern, Option<Box<AstNode>>)],
) -> Result<Option<HashMap<String, Value>>, String> {
    let mut all_bindings = HashMap::new();

    for (field_name, field_pattern, _default) in fields {
        // Check if the field exists in the record
        let field_value = match record_map.get(field_name) {
            Some(v) => v.deref()?,
            None => return Ok(None), // Field not found, pattern doesn't match
        };

        // Try to match the field value against the field pattern
        match match_pattern(&field_value, field_pattern)? {
            Some(bindings) => {
                // Check if this is a non-binding pattern (Type, Wildcard, Literal)
                // In that case, we need to bind the field name to the value
                let needs_field_binding = match field_pattern {
                    Pattern::Type(_) | Pattern::Wildcard | Pattern::Literal(_) => true,
                    _ => false,
                };

                if needs_field_binding {
                    // Bind the field name to the value (the pattern only checks type/value)
                    all_bindings.insert(field_name.clone(), field_value.clone());
                }

                // Merge bindings from the pattern (for Variable, Record, Vector patterns)
                for (name, val) in bindings {
                    all_bindings.insert(name, val);
                }
            }
            None => return Ok(None), // Field pattern didn't match
        }
    }

    Ok(Some(all_bindings))
}

/// Helper to match record fields against pattern fields with default support
fn match_record_fields_with_defaults(
    evaluator: &mut Evaluator,
    record_map: &HashMap<String, Value>,
    fields: &[(String, Pattern, Option<Box<AstNode>>)],
) -> Result<Option<HashMap<String, Value>>, String> {
    let mut all_bindings = HashMap::new();

    for (field_name, field_pattern, default_expr) in fields {
        // Check if the field exists in the record or if it's null
        let field_value = match record_map.get(field_name) {
            Some(v) => {
                let derefed = v.deref()?;
                // Use default if the value is null and we have a default
                if matches!(derefed, Value::Null) && default_expr.is_some() {
                    // Lazy evaluation: only evaluate default when needed
                    evaluator.evaluate(default_expr.as_ref().unwrap())?
                } else {
                    derefed
                }
            }
            None => {
                // Field not found, use default if available
                if let Some(default) = default_expr {
                    // Lazy evaluation: only evaluate default when needed
                    evaluator.evaluate(default)?
                } else {
                    return Ok(None); // Field not found and no default
                }
            }
        };

        // Try to match the field value against the field pattern
        match match_pattern_with_defaults(evaluator, &field_value, field_pattern)? {
            Some(bindings) => {
                // Check if this is a non-binding pattern (Type, Wildcard, Literal)
                // In that case, we need to bind the field name to the value
                let needs_field_binding = match field_pattern {
                    Pattern::Type(_) | Pattern::Wildcard | Pattern::Literal(_) => true,
                    _ => false,
                };

                if needs_field_binding {
                    // Bind the field name to the value (the pattern only checks type/value)
                    all_bindings.insert(field_name.clone(), field_value.clone());
                }

                // Merge bindings from the pattern (for Variable, Record, Vector patterns)
                for (name, val) in bindings {
                    all_bindings.insert(name, val);
                }
            }
            None => return Ok(None), // Field pattern didn't match
        }
    }

    Ok(Some(all_bindings))
}

/// Match a value against a vector pattern (without defaults, for match expressions)
fn match_vector_no_defaults(value: &Value, elements: &[VectorPatternElement]) -> Result<Option<HashMap<String, Value>>, String> {
    let vec = match value {
        Value::Vector(v) => v,
        // Also handle Tensor as a vector if it's 1D
        Value::Tensor(t) if t.is_vector() => {
            // Convert tensor to vector of values
            let values: Vec<Value> = t.data().iter().map(|n| Value::Number(*n)).collect();
            return match_vector_elements_no_defaults(&values, elements);
        }
        _ => return Ok(None),
    };

    match_vector_elements_no_defaults(vec, elements)
}

/// Match a value against a vector pattern with defaults (for destructuring)
fn match_vector_with_defaults(
    evaluator: &mut Evaluator,
    value: &Value,
    elements: &[VectorPatternElement],
) -> Result<Option<HashMap<String, Value>>, String> {
    let vec = match value {
        Value::Vector(v) => v,
        // Also handle Tensor as a vector if it's 1D
        Value::Tensor(t) if t.is_vector() => {
            // Convert tensor to vector of values
            let values: Vec<Value> = t.data().iter().map(|n| Value::Number(*n)).collect();
            return match_vector_elements_with_defaults(evaluator, &values, elements);
        }
        _ => return Ok(None),
    };

    match_vector_elements_with_defaults(evaluator, vec, elements)
}

/// Helper to match vector elements against pattern elements (no defaults)
fn match_vector_elements_no_defaults(
    vec: &[Value],
    elements: &[VectorPatternElement],
) -> Result<Option<HashMap<String, Value>>, String> {
    let mut all_bindings = HashMap::new();

    // Check if there's a rest pattern
    let rest_index = elements.iter().position(|e| matches!(e, VectorPatternElement::Rest(_)));

    if let Some(rest_idx) = rest_index {
        // We have a rest pattern
        // Elements before rest must match exactly
        // Rest captures all remaining elements
        // Elements after rest must match the end

        let patterns_before_rest = &elements[..rest_idx];
        let patterns_after_rest = &elements[rest_idx + 1..];

        // Check if vector has enough elements
        let min_required = patterns_before_rest.len() + patterns_after_rest.len();
        if vec.len() < min_required {
            return Ok(None);
        }

        // Match elements before rest
        for (i, pattern_elem) in patterns_before_rest.iter().enumerate() {
            match pattern_elem {
                VectorPatternElement::Pattern(p, _default) => {
                    match match_pattern(&vec[i], p)? {
                        Some(bindings) => {
                            for (name, val) in bindings {
                                all_bindings.insert(name, val);
                            }
                        }
                        None => return Ok(None),
                    }
                }
                VectorPatternElement::Rest(_) => {
                    // This shouldn't happen since we found rest at rest_idx
                    return Err("Internal error: unexpected rest pattern".to_string());
                }
            }
        }

        // Match elements after rest (from the end)
        let rest_end = vec.len() - patterns_after_rest.len();
        for (i, pattern_elem) in patterns_after_rest.iter().enumerate() {
            match pattern_elem {
                VectorPatternElement::Pattern(p, _default) => {
                    match match_pattern(&vec[rest_end + i], p)? {
                        Some(bindings) => {
                            for (name, val) in bindings {
                                all_bindings.insert(name, val);
                            }
                        }
                        None => return Ok(None),
                    }
                }
                VectorPatternElement::Rest(_) => {
                    return Err("Vector pattern can only have one rest element".to_string());
                }
            }
        }

        // Capture rest elements
        if let VectorPatternElement::Rest(rest_name) = &elements[rest_idx] {
            let rest_values: Vec<Value> = vec[patterns_before_rest.len()..rest_end].to_vec();
            all_bindings.insert(rest_name.clone(), Value::Vector(rest_values));
        }
    } else {
        // No rest pattern, exact match required
        if vec.len() != elements.len() {
            return Ok(None);
        }

        for (i, pattern_elem) in elements.iter().enumerate() {
            match pattern_elem {
                VectorPatternElement::Pattern(p, _default) => {
                    match match_pattern(&vec[i], p)? {
                        Some(bindings) => {
                            for (name, val) in bindings {
                                all_bindings.insert(name, val);
                            }
                        }
                        None => return Ok(None),
                    }
                }
                VectorPatternElement::Rest(_) => {
                    // This shouldn't happen since we checked rest_index is None
                    return Err("Internal error: unexpected rest pattern".to_string());
                }
            }
        }
    }

    Ok(Some(all_bindings))
}

/// Helper to match vector elements against pattern elements with default support
fn match_vector_elements_with_defaults(
    evaluator: &mut Evaluator,
    vec: &[Value],
    elements: &[VectorPatternElement],
) -> Result<Option<HashMap<String, Value>>, String> {
    let mut all_bindings = HashMap::new();

    // Check if there's a rest pattern
    let rest_index = elements.iter().position(|e| matches!(e, VectorPatternElement::Rest(_)));

    if let Some(rest_idx) = rest_index {
        // We have a rest pattern
        // Elements before rest must match exactly
        // Rest captures all remaining elements
        // Elements after rest must match the end

        let patterns_before_rest = &elements[..rest_idx];
        let patterns_after_rest = &elements[rest_idx + 1..];

        // Check if vector has enough elements (with defaults, we're more lenient)
        let min_required = patterns_before_rest.len() + patterns_after_rest.len();
        if vec.len() < min_required {
            // Even with defaults, we can't satisfy the minimum structure
            return Ok(None);
        }

        // Match elements before rest
        for (i, pattern_elem) in patterns_before_rest.iter().enumerate() {
            match pattern_elem {
                VectorPatternElement::Pattern(p, _default) => {
                    match match_pattern_with_defaults(evaluator, &vec[i], p)? {
                        Some(bindings) => {
                            for (name, val) in bindings {
                                all_bindings.insert(name, val);
                            }
                        }
                        None => return Ok(None),
                    }
                }
                VectorPatternElement::Rest(_) => {
                    // This shouldn't happen since we found rest at rest_idx
                    return Err("Internal error: unexpected rest pattern".to_string());
                }
            }
        }

        // Match elements after rest (from the end)
        let rest_end = vec.len() - patterns_after_rest.len();
        for (i, pattern_elem) in patterns_after_rest.iter().enumerate() {
            match pattern_elem {
                VectorPatternElement::Pattern(p, _default) => {
                    match match_pattern_with_defaults(evaluator, &vec[rest_end + i], p)? {
                        Some(bindings) => {
                            for (name, val) in bindings {
                                all_bindings.insert(name, val);
                            }
                        }
                        None => return Ok(None),
                    }
                }
                VectorPatternElement::Rest(_) => {
                    return Err("Vector pattern can only have one rest element".to_string());
                }
            }
        }

        // Capture rest elements
        if let VectorPatternElement::Rest(rest_name) = &elements[rest_idx] {
            let rest_values: Vec<Value> = vec[patterns_before_rest.len()..rest_end].to_vec();
            all_bindings.insert(rest_name.clone(), Value::Vector(rest_values));
        }
    } else {
        // No rest pattern
        // With defaults, we can have fewer elements in the vector than patterns
        // But not more elements than patterns (unless we match all)

        for (i, pattern_elem) in elements.iter().enumerate() {
            match pattern_elem {
                VectorPatternElement::Pattern(p, default_expr) => {
                    // Get the value from the vector, or use default if missing
                    let element_value = if i < vec.len() {
                        vec[i].clone()
                    } else if let Some(default) = default_expr {
                        // Lazy evaluation: only evaluate default when needed
                        evaluator.evaluate(default)?
                    } else {
                        // No value and no default
                        return Ok(None);
                    };

                    match match_pattern_with_defaults(evaluator, &element_value, p)? {
                        Some(bindings) => {
                            for (name, val) in bindings {
                                all_bindings.insert(name, val);
                            }
                        }
                        None => return Ok(None),
                    }
                }
                VectorPatternElement::Rest(_) => {
                    // This shouldn't happen since we checked rest_index is None
                    return Err("Internal error: unexpected rest pattern".to_string());
                }
            }
        }
    }

    Ok(Some(all_bindings))
}
