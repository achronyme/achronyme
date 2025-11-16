use achronyme_parser::ast::AstNode;
use achronyme_parser::type_annotation::TypeAnnotation;
use achronyme_types::function::Function;
use achronyme_types::value::Value;
use std::rc::Rc;

use crate::evaluator::Evaluator;
use crate::tco;

/// Evaluate a lambda expression with typed parameters and return type
pub fn evaluate_lambda_with_return_type(
    evaluator: &Evaluator,
    params: &[(String, Option<TypeAnnotation>, Option<Box<AstNode>>)],
    return_type: Option<TypeAnnotation>,
    body: &AstNode,
) -> Result<Value, String> {
    let closure_env = evaluator.environment().to_rc();

    // Extract parameter names, type annotations, and default values
    let param_names: Vec<String> = params.iter().map(|(name, _, _)| name.clone()).collect();
    let param_types: Vec<Option<TypeAnnotation>> = params.iter().map(|(_, ty, _)| ty.clone()).collect();
    let param_defaults: Vec<Option<Rc<AstNode>>> = params
        .iter()
        .map(|(_, _, default)| default.as_ref().map(|d| Rc::new((**d).clone())))
        .collect();

    // Create a Function value with type annotations, defaults, and return type
    let function = Function::new_typed_with_defaults(
        param_names,
        param_types,
        param_defaults,
        return_type,
        body.clone(),
        closure_env,
    );

    Ok(Value::Function(function))
}

/// Apply a lambda function to arguments
pub fn apply_lambda(
    evaluator: &mut Evaluator,
    function: &Function,
    args: Vec<Value>,
) -> Result<Value, String> {
    match function {
        Function::UserDefined { params, param_types, param_defaults, return_type, body, closure_env } => {
            // Fill in missing arguments with defaults
            let args_len = args.len();
            let mut final_args = args;

            // Check if we have too many arguments
            if final_args.len() > params.len() {
                return Err(format!(
                    "Lambda expects at most {} arguments, got {}",
                    params.len(),
                    final_args.len()
                ));
            }

            // Fill in missing arguments with defaults
            if final_args.len() < params.len() {
                // We need to evaluate default values in the closure environment
                let saved_env = evaluator.environment().clone();
                *evaluator.environment_mut() = closure_env.borrow().clone();

                for i in final_args.len()..params.len() {
                    if let Some(default_ast) = &param_defaults[i] {
                        // Evaluate the default value in the closure environment
                        let default_value = evaluator.evaluate(default_ast)?;
                        final_args.push(default_value);
                    } else {
                        // Restore environment before returning error
                        *evaluator.environment_mut() = saved_env;
                        return Err(format!(
                            "Lambda expects {} arguments, got {} (parameter '{}' has no default)",
                            params.len(),
                            args_len,
                            params[i]
                        ));
                    }
                }

                // Restore environment
                *evaluator.environment_mut() = saved_env;
            }

            // Type check arguments
            for (i, (arg, param_type)) in final_args.iter().zip(param_types.iter()).enumerate() {
                if let Some(expected_type) = param_type {
                    crate::type_checker::check_type(arg, expected_type)
                        .map_err(|_| format!(
                            "Type error: argument {} (parameter '{}') expected {}, got {}",
                            i + 1,
                            params[i],
                            expected_type.to_string(),
                            crate::type_checker::infer_type(arg).to_string()
                        ))?;
                }
            }

            // TAIL CALL OPTIMIZATION (TCO):
            // Check if this function is tail-recursive
            let is_tail_recursive = tco::is_tail_recursive_function(body);

            let result = if is_tail_recursive {
                // Use iterative execution for tail-recursive functions
                apply_lambda_tco(evaluator, function, final_args)
            } else {
                // Use regular recursive execution
                apply_lambda_regular(evaluator, params, param_types, param_defaults, return_type, body, closure_env, final_args)
            }?;

            // Type check return value
            if let Some(expected_return) = return_type {
                crate::type_checker::check_type(&result, expected_return)
                    .map_err(|_| format!(
                        "Type error: function return type expected {}, got {}",
                        expected_return.to_string(),
                        crate::type_checker::infer_type(&result).to_string()
                    ))?;
            }

            Ok(result)
        }
        Function::Builtin(name) => {
            // Built-in functions can be called directly through the registry
            // Try module system first, then fall back to global FunctionRegistry
            let function_info = if let Some((func, arity)) = evaluator.module_registry().resolve(name, evaluator.imported_modules()) {
                Some((func, arity))
            } else if evaluator.functions().has(name) {
                evaluator.functions().get(name)
            } else {
                None
            };

            if let Some((func, expected_arity)) = function_info {
                // Check arity (if not variadic)
                if expected_arity >= 0 && args.len() != expected_arity as usize {
                    return Err(format!(
                        "Function {} expects {} arguments, got {}",
                        name,
                        expected_arity,
                        args.len()
                    ));
                }

                // Call the builtin function directly with the evaluated arguments
                func(&args, evaluator.environment_mut())
            } else {
                Err(format!("Unknown built-in function: {}", name))
            }
        }
    }
}

/// Regular (non-TCO) lambda application
/// This is the original implementation, used when TCO doesn't apply
fn apply_lambda_regular(
    evaluator: &mut Evaluator,
    params: &[String],
    param_types: &[Option<TypeAnnotation>],
    _param_defaults: &[Option<Rc<AstNode>>],  // Already resolved in apply_lambda
    return_type: &Option<TypeAnnotation>,
    body: &AstNode,
    closure_env: &std::rc::Rc<std::cell::RefCell<achronyme_types::Environment>>,
    args: Vec<Value>,
) -> Result<Value, String> {
    // OPTIMIZATION: Instead of cloning the entire environment,
    // we just save a reference to it and swap it with the closure environment.
    // This is much faster, especially with large environments.
    let saved_env = evaluator.environment().clone();

    // Check if 'self' is defined in the current environment (for record methods)
    let self_value = saved_env.get("self").ok();

    // Set environment to the closure's captured environment
    // Since closure_env is an Rc<RefCell<>>, we need to borrow and clone
    *evaluator.environment_mut() = closure_env.borrow().clone();

    // Inject the current function as 'rec' for recursive calls
    // We need to reconstruct the function for rec binding
    let function = Function::new_typed_with_defaults(
        params.to_vec(),
        param_types.to_vec(),
        _param_defaults.to_vec(),
        return_type.clone(),
        body.clone(),
        closure_env.clone(),
    );
    evaluator.environment_mut().define("rec".to_string(), Value::Function(function))?;

    // If 'self' was available in the calling context, inject it (for record methods)
    if let Some(self_val) = self_value {
        evaluator.environment_mut().define("self".to_string(), self_val)?;
    }

    // Push a new scope for lambda parameters (enables shadowing)
    evaluator.environment_mut().push_scope();

    // Bind parameters to arguments in the new scope
    for (param, arg) in params.iter().zip(args.iter()) {
        evaluator.environment_mut().define(param.clone(), arg.clone())?;
    }

    // Evaluate the body
    let result = evaluator.evaluate(body);

    // Pop the parameter scope
    evaluator.environment_mut().pop_scope();

    // Restore environment
    *evaluator.environment_mut() = saved_env;

    // Check if the result is an EarlyReturn - unwrap it
    match result {
        Ok(Value::EarlyReturn(value)) => Ok(*value),
        other => other,
    }
}

/// Tail-Call Optimized lambda application
/// Uses an iterative loop instead of recursion for tail-recursive functions
fn apply_lambda_tco(
    evaluator: &mut Evaluator,
    function: &Function,
    mut args: Vec<Value>,
) -> Result<Value, String> {
    let (params, body, closure_env) = match function {
        Function::UserDefined { params, body, closure_env, .. } => (params, body, closure_env),
        _ => return Err("TCO only applies to user-defined functions".to_string()),
    };

    // Save the original environment
    let saved_env = evaluator.environment().clone();
    let self_value = saved_env.get("self").ok();

    // Set environment to closure's captured environment
    *evaluator.environment_mut() = closure_env.borrow().clone();

    // Inject 'rec' for recursive calls
    evaluator.environment_mut().define("rec".to_string(), Value::Function(function.clone()))?;

    // Inject 'self' if available
    if let Some(self_val) = self_value {
        evaluator.environment_mut().define("self".to_string(), self_val)?;
    }

    // Enable TCO mode so CallExpression with rec returns TailCall markers
    evaluator.set_tco_mode(true);

    // TCO Loop: instead of recursing, we loop and update parameters
    let result = loop {
        // Push new scope for parameters
        evaluator.environment_mut().push_scope();

        // Bind current arguments to parameters
        for (param, arg) in params.iter().zip(args.iter()) {
            evaluator.environment_mut().define(param.clone(), arg.clone())?;
        }

        // Evaluate the body with TCO mode enabled
        let value = evaluator.evaluate(body)?;

        // Pop parameter scope
        evaluator.environment_mut().pop_scope();

        // Check if the result is a tail call marker or early return
        match value {
            Value::TailCall(new_args) => {
                // Tail call detected! Update arguments and continue loop
                // This replaces the recursive call with iteration
                if new_args.len() != params.len() {
                    break Err(format!(
                        "Tail call arity mismatch: expected {} arguments, got {}",
                        params.len(),
                        new_args.len()
                    ));
                }
                args = new_args;
                // Continue loop with new arguments
            }
            Value::EarlyReturn(value) => {
                // Early return - unwrap and break immediately
                break Ok(*value);
            }
            other => {
                // Base case reached - return the value
                break Ok(other);
            }
        }
    };

    // Disable TCO mode
    evaluator.set_tco_mode(false);

    // Restore environment
    *evaluator.environment_mut() = saved_env;

    result
}

/// Helper to evaluate a lambda function at a single point
/// Used by LambdaEvaluator trait implementation
pub fn eval_lambda_at(evaluator: &mut Evaluator, func: &Function, x: f64) -> Result<f64, String> {
    let result = apply_lambda(evaluator, func, vec![Value::Number(x)])?;
    match result {
        Value::Number(n) => Ok(n),
        _ => Err("Lambda must return a number".to_string()),
    }
}
