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

        Pattern::Record { fields } => match_record(value, fields),

        Pattern::Vector { elements } => match_vector(value, elements),
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

/// Match a value against a record pattern
fn match_record(value: &Value, fields: &[(String, Pattern)]) -> Result<Option<HashMap<String, Value>>, String> {
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
            return match_record_fields(&map, fields);
        }
        _ => return Ok(None),
    };

    match_record_fields(record_map, fields)
}

/// Helper to match record fields against pattern fields
fn match_record_fields(
    record_map: &HashMap<String, Value>,
    fields: &[(String, Pattern)],
) -> Result<Option<HashMap<String, Value>>, String> {
    let mut all_bindings = HashMap::new();

    for (field_name, field_pattern) in fields {
        // Check if the field exists in the record
        let field_value = match record_map.get(field_name) {
            Some(v) => v.deref()?,
            None => return Ok(None), // Field not found, pattern doesn't match
        };

        // Try to match the field value against the field pattern
        match match_pattern(&field_value, field_pattern)? {
            Some(bindings) => {
                // Merge bindings
                for (name, val) in bindings {
                    all_bindings.insert(name, val);
                }
            }
            None => return Ok(None), // Field pattern didn't match
        }
    }

    Ok(Some(all_bindings))
}

/// Match a value against a vector pattern
fn match_vector(value: &Value, elements: &[VectorPatternElement]) -> Result<Option<HashMap<String, Value>>, String> {
    let vec = match value {
        Value::Vector(v) => v,
        // Also handle Tensor as a vector if it's 1D
        Value::Tensor(t) if t.is_vector() => {
            // Convert tensor to vector of values
            let values: Vec<Value> = t.data().iter().map(|n| Value::Number(*n)).collect();
            return match_vector_elements(&values, elements);
        }
        _ => return Ok(None),
    };

    match_vector_elements(vec, elements)
}

/// Helper to match vector elements against pattern elements
fn match_vector_elements(
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
                VectorPatternElement::Pattern(p) => {
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
                VectorPatternElement::Pattern(p) => {
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
                VectorPatternElement::Pattern(p) => {
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
