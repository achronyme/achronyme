use achronyme_parser::ast::AstNode;
use achronyme_parser::TypeAnnotation;
use achronyme_types::complex::Complex;
use achronyme_types::function::Function;
use achronyme_types::value::Value;

use crate::evaluator::Evaluator;
use crate::type_checker;

/// Evaluate a variable declaration (let statement) with optional type checking
pub fn evaluate_declaration(
    evaluator: &mut Evaluator,
    name: &str,
    type_annotation: &Option<TypeAnnotation>,
    initializer: &AstNode,
) -> Result<Value, String> {
    // Evaluate the initializer
    let mut value = evaluator.evaluate(initializer)?;

    // Type check if annotation is provided
    if let Some(expected_type) = type_annotation {
        // Resolve type aliases before checking
        let resolved_type = evaluator.resolve_type(expected_type);

        // Special case: if type is Function and value is a function, enrich with type info
        value = enrich_function_with_type(value, &resolved_type);

        type_checker::check_type(&value, &resolved_type).map_err(|err| {
            format!("Type error: variable '{}' {}", name, err.replace("Type mismatch: ", ""))
        })?;
    }

    // Define the variable in the environment (immutable)
    evaluator.environment_mut().define(name.to_string(), value.clone())?;

    Ok(value)
}

/// Enrich a function value with type information from the annotation
/// This implements type inference from the variable's type to the lambda's parameters
fn enrich_function_with_type(value: Value, expected_type: &TypeAnnotation) -> Value {
    // Only enrich if the expected type is a Function type
    if let TypeAnnotation::Function { params: expected_params, return_type: expected_return } = expected_type {
        if let Value::Function(ref func) = value {
            if let Function::UserDefined { params, param_types, param_defaults, return_type, body, closure_env } = func {
                // Check if we need to enrich the parameter types
                let needs_enrichment = param_types.iter().any(|t| t.is_none()) || return_type.is_none();

                if needs_enrichment && params.len() == expected_params.len() {
                    // Merge: use expected types where param_types has None
                    let enriched_param_types: Vec<Option<TypeAnnotation>> = param_types
                        .iter()
                        .zip(expected_params.iter())
                        .map(|(actual, expected)| {
                            if actual.is_none() {
                                expected.clone()
                            } else {
                                actual.clone()
                            }
                        })
                        .collect();

                    // Enrich return type if not specified
                    let enriched_return_type = if return_type.is_none() {
                        Some((**expected_return).clone())
                    } else {
                        return_type.clone()
                    };

                    // Create enriched function
                    let enriched_func = Function::new_typed_with_defaults(
                        params.clone(),
                        enriched_param_types,
                        param_defaults.clone(),
                        enriched_return_type,
                        (**body).clone(),
                        closure_env.clone(),
                    );

                    return Value::Function(enriched_func);
                }
            }
        }
    }

    // Return original value if no enrichment needed
    value
}

/// Evaluate a mutable variable declaration (mut statement) with optional type checking
pub fn evaluate_mutable_declaration(
    evaluator: &mut Evaluator,
    name: &str,
    type_annotation: &Option<TypeAnnotation>,
    initializer: &AstNode,
) -> Result<Value, String> {
    // Evaluate the initializer
    let mut value = evaluator.evaluate(initializer)?;

    // Type check if annotation is provided
    if let Some(expected_type) = type_annotation {
        // Resolve type aliases before checking
        let resolved_type = evaluator.resolve_type(expected_type);

        // Special case: if type is Function and value is a function, enrich with type info
        value = enrich_function_with_type(value, &resolved_type);

        type_checker::check_type(&value, &resolved_type).map_err(|err| {
            format!("Type error: variable '{}' {}", name, err.replace("Type mismatch: ", ""))
        })?;

        // Define as mutable variable with resolved type annotation (enforced on assignment)
        evaluator.environment_mut().define_mutable_typed(
            name.to_string(),
            value.clone(),
            resolved_type,
        )?;
    } else {
        // Define as mutable variable without type annotation
        evaluator.environment_mut().define_mutable(name.to_string(), value.clone())?;
    }

    // Return the value (not the MutableRef wrapper)
    Ok(value)
}

/// Evaluate a variable reference
pub fn evaluate_reference(evaluator: &Evaluator, name: &str) -> Result<Value, String> {
    // Check if it's a variable first
    if evaluator.environment().has(name) {
        return evaluator.environment().get(name);
    }

    // Special case for imaginary unit 'i'
    if name.to_lowercase() == "i" {
        return Ok(Value::Complex(Complex::new(0.0, 1.0)));
    }

    // Check if it's a constant
    if evaluator.constants().has(name) {
        return Ok(Value::Number(evaluator.constants().get(name)?));
    }

    // Check if it's a built-in function (dynamic check from registry)
    if evaluator.functions().has(name) {
        use achronyme_types::function::Function;
        return Ok(Value::Function(Function::builtin(name.to_string())));
    }

    // Check if it's a special form function (functions that require special evaluation)
    if is_special_form(name) {
        use achronyme_types::function::Function;
        return Ok(Value::Function(Function::builtin(name.to_string())));
    }

    // Not found
    Err(format!("Undefined variable or constant: {}", name))
}

/// Check if a name corresponds to a special form function
/// These are functions that require special evaluation (lazy evaluation, evaluator access, etc.)
/// and are not registered in the standard FunctionRegistry
fn is_special_form(name: &str) -> bool {
    matches!(
        name,
        // Higher-order functions (require lazy evaluation)
        "map" | "filter" | "reduce" | "pipe" |
        // Tier 2 array predicates (require lambda evaluation)
        "any" | "all" | "find" | "findIndex" | "count" |
        // Numerical calculus functions (require evaluator for lambda evaluation)
        "diff" | "diff2" | "diff3" | "gradient" | "integral" | "trapz" |
        "simpson" | "romberg" | "quad" | "solve" | "bisect" | "newton" | "secant" | "derivative" |
        // Debug functions
        "describe" |
        // Optimization functions
        "simplex" | "linprog" | "dual_simplex" | "two_phase_simplex" | "revised_simplex" |
        "objective_value" | "shadow_price" | "sensitivity_c" | "sensitivity_b" |
        "reduced_costs" | "basic_variables" | "nonbasic_variables"
    )
}

/// Evaluate a let destructuring statement (let { x, y } = value)
/// Uses pattern matching to bind variables from the destructured value
/// Now supports default values: let { x, y = 0 } = value
pub fn evaluate_let_destructuring(
    evaluator: &mut Evaluator,
    pattern: &achronyme_parser::ast::Pattern,
    type_annotation: &Option<TypeAnnotation>,
    initializer: &AstNode,
) -> Result<Value, String> {
    // Evaluate the initializer
    let value = evaluator.evaluate(initializer)?;

    // Type check if annotation is provided
    if let Some(expected_type) = type_annotation {
        // Resolve type aliases before checking
        let resolved_type = evaluator.resolve_type(expected_type);

        type_checker::check_type(&value, &resolved_type).map_err(|err| {
            format!("Type error in destructuring: {}", err.replace("Type mismatch: ", ""))
        })?;
    }

    // Use pattern matching with default support to extract bindings
    let bindings = crate::handlers::pattern_matching::match_pattern_with_defaults(evaluator, &value, pattern)?
        .ok_or_else(|| "Destructuring pattern does not match value".to_string())?;

    // Bind all variables in the environment (immutable)
    for (name, bound_value) in bindings {
        evaluator.environment_mut().define(name, bound_value)?;
    }

    Ok(value)
}

/// Evaluate a mutable destructuring statement (mut { x, y } = value)
/// Uses pattern matching to bind mutable variables from the destructured value
/// Now supports default values: mut { x, y = 0 } = value
pub fn evaluate_mutable_destructuring(
    evaluator: &mut Evaluator,
    pattern: &achronyme_parser::ast::Pattern,
    type_annotation: &Option<TypeAnnotation>,
    initializer: &AstNode,
) -> Result<Value, String> {
    // Evaluate the initializer
    let value = evaluator.evaluate(initializer)?;

    // Type check if annotation is provided
    if let Some(expected_type) = type_annotation {
        // Resolve type aliases before checking
        let resolved_type = evaluator.resolve_type(expected_type);

        type_checker::check_type(&value, &resolved_type).map_err(|err| {
            format!("Type error in destructuring: {}", err.replace("Type mismatch: ", ""))
        })?;
    }

    // Use pattern matching with default support to extract bindings
    let bindings = crate::handlers::pattern_matching::match_pattern_with_defaults(evaluator, &value, pattern)?
        .ok_or_else(|| "Destructuring pattern does not match value".to_string())?;

    // Bind all variables in the environment (mutable)
    for (name, bound_value) in bindings {
        evaluator.environment_mut().define_mutable(name, bound_value)?;
    }

    Ok(value)
}
