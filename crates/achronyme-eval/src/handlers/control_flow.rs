use achronyme_parser::ast::AstNode;
use achronyme_types::value::{Value, GeneratorState};
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;

use crate::evaluator::Evaluator;

/// Evaluate an if expression
pub fn evaluate_if(
    evaluator: &mut Evaluator,
    condition: &AstNode,
    then_expr: &AstNode,
    else_expr: &AstNode,
) -> Result<Value, String> {
    // Evaluate condition
    let cond_val = evaluator.evaluate(condition)?;

    // Convert to boolean
    let cond_bool = value_to_bool(&cond_val)?;

    // Evaluate appropriate branch (short-circuit)
    if cond_bool {
        evaluator.evaluate(then_expr)
    } else {
        evaluator.evaluate(else_expr)
    }
}

/// Evaluate a while loop
pub fn evaluate_while(
    evaluator: &mut Evaluator,
    condition: &AstNode,
    body: &AstNode,
) -> Result<Value, String> {
    let mut last_value = Value::Number(0.0);

    // Track that we're inside a loop
    evaluator.loop_depth += 1;

    let result = loop {
        // Evaluate condition
        let cond_val = evaluator.evaluate(condition)?;
        let cond_bool = value_to_bool(&cond_val)?;

        // If condition is false, exit loop
        if !cond_bool {
            break Ok(last_value);
        }

        // Execute body
        let body_result = evaluator.evaluate(body)?;

        // Check for control flow markers
        match body_result {
            // Break: exit the loop immediately
            Value::LoopBreak(break_value) => {
                last_value = break_value.map(|v| *v).unwrap_or(Value::Number(0.0));
                break Ok(last_value);
            }
            // Continue: skip to next iteration
            Value::LoopContinue => {
                // Just continue to next iteration
                continue;
            }
            // Early return: propagate it immediately
            Value::EarlyReturn(_) => {
                evaluator.loop_depth -= 1;
                return Ok(body_result);
            }
            // Generator yield: propagate it immediately
            Value::GeneratorYield(_) => {
                evaluator.loop_depth -= 1;
                return Ok(body_result);
            }
            // Normal value: store it
            _ => {
                last_value = body_result;
            }
        }
    };

    // Restore loop depth
    evaluator.loop_depth -= 1;

    result
}

/// Evaluate a piecewise function
pub fn evaluate_piecewise(
    evaluator: &mut Evaluator,
    cases: &[(Box<AstNode>, Box<AstNode>)],
    default: &Option<Box<AstNode>>,
) -> Result<Value, String> {
    // Evaluate cases in order (short-circuit)
    for (condition, expression) in cases {
        let cond_val = evaluator.evaluate(condition)?;
        let cond_bool = value_to_bool(&cond_val)?;

        if cond_bool {
            return evaluator.evaluate(expression);
        }
    }

    // If no condition was true, evaluate default if present
    if let Some(default_expr) = default {
        return evaluator.evaluate(default_expr);
    }

    // No condition was true and no default provided
    Err("piecewise: no condition was true and no default value provided".to_string())
}

/// Helper to convert Value to bool
/// Boolean values map directly, numbers: 0 = false, != 0 = true
fn value_to_bool(value: &Value) -> Result<bool, String> {
    match value {
        Value::Boolean(b) => Ok(*b),
        Value::Number(n) => Ok(*n != 0.0),
        _ => Err(format!("Cannot convert {:?} to boolean", value)),
    }
}

/// Evaluate a generate block: () => generate { ... }
/// This creates a generator value that can be resumed with .next()
pub fn evaluate_generate_block(
    evaluator: &mut Evaluator,
    statements: &[AstNode],
) -> Result<Value, String> {
    // Capture current environment for the generator
    let captured_env = evaluator.environment().clone();

    // Create generator state with original environment preserved
    let mut state = GeneratorState::new(captured_env.clone(), statements.to_vec());
    // Store the original environment for re-execution
    state.original_env = Some(captured_env);

    // Return generator value
    let gen_rc = Rc::new(RefCell::new(state));
    Ok(Value::Generator(gen_rc))
}

/// Evaluate a for-in loop: for(variable in iterable) { body }
/// Iterates over an iterator (object with next() method), vector, or tensor
pub fn evaluate_for_in(
    evaluator: &mut Evaluator,
    variable: &str,
    iterable: &AstNode,
    body: &AstNode,
) -> Result<Value, String> {
    // Evaluate iterable expression
    let iter_value = evaluator.evaluate(iterable)?;

    // Check the type of iterable and dispatch to appropriate handler
    match &iter_value {
        // Vector: iterate directly over elements
        Value::Vector(elements) => {
            return evaluate_for_in_vector(evaluator, variable, elements.clone(), body);
        }
        // Tensor: iterate over elements (flattened for 1D, or rows for 2D+)
        Value::Tensor(tensor) => {
            return evaluate_for_in_tensor(evaluator, variable, tensor.clone(), body);
        }
        // ComplexTensor: iterate over complex elements
        Value::ComplexTensor(tensor) => {
            return evaluate_for_in_complex_tensor(evaluator, variable, tensor.clone(), body);
        }
        // Generator: use special generator iteration
        Value::Generator(gen_rc) => {
            return evaluate_generator_for_in(evaluator, variable, gen_rc.clone(), body);
        }
        // Record with next() method: iterator protocol
        Value::Record(map) => {
            let next_fn = map.get("next")
                .cloned()
                .ok_or_else(|| "Record must have a 'next' method to be iterable".to_string())?;
            return evaluate_iterator_for_in(evaluator, variable, next_fn, body);
        }
        _ => {
            return Err(format!(
                "Cannot iterate over {}: expected Vector, Tensor, Generator, or iterator (object with next method)",
                get_type_name(&iter_value)
            ));
        }
    }
}

/// Helper function to get type name for error messages
fn get_type_name(value: &Value) -> &'static str {
    match value {
        Value::Number(_) => "Number",
        Value::Boolean(_) => "Boolean",
        Value::String(_) => "String",
        Value::Vector(_) => "Vector",
        Value::Tensor(_) => "Tensor",
        Value::ComplexTensor(_) => "ComplexTensor",
        Value::Complex(_) => "Complex",
        Value::Function(_) => "Function",
        Value::Record(_) => "Record",
        Value::Edge { .. } => "Edge",
        Value::Generator(_) => "Generator",
        Value::Null => "Null",
        Value::Error { .. } => "Error",
        Value::EarlyReturn(_) => "EarlyReturn",
        Value::TailCall(_) => "TailCall",
        Value::GeneratorYield(_) => "GeneratorYield",
        Value::LoopBreak(_) => "LoopBreak",
        Value::LoopContinue => "LoopContinue",
        Value::MutableRef(_) => "MutableRef",
    }
}

/// Evaluate for-in loop over a Vector
fn evaluate_for_in_vector(
    evaluator: &mut Evaluator,
    variable: &str,
    elements: Vec<Value>,
    body: &AstNode,
) -> Result<Value, String> {
    // Create new scope for loop
    evaluator.environment_mut().push_scope();

    // Track that we're inside a loop
    evaluator.loop_depth += 1;

    let mut last_value = Value::Null;

    let result = 'outer: {
        for element in elements {
            // Bind loop variable
            evaluator.environment_mut().define(variable.to_string(), element)?;

            // Execute body
            let body_result = evaluator.evaluate(body)?;

            // Check for control flow markers
            match body_result {
                Value::LoopBreak(break_value) => {
                    last_value = break_value.map(|v| *v).unwrap_or(Value::Null);
                    break 'outer Ok(last_value);
                }
                Value::LoopContinue => {
                    continue;
                }
                Value::EarlyReturn(_) => {
                    evaluator.loop_depth -= 1;
                    evaluator.environment_mut().pop_scope();
                    return Ok(body_result);
                }
                Value::GeneratorYield(_) => {
                    evaluator.loop_depth -= 1;
                    evaluator.environment_mut().pop_scope();
                    return Ok(body_result);
                }
                _ => {
                    last_value = body_result;
                }
            }
        }
        Ok(last_value)
    };

    evaluator.loop_depth -= 1;
    evaluator.environment_mut().pop_scope();
    result
}

/// Evaluate for-in loop over a RealTensor
fn evaluate_for_in_tensor(
    evaluator: &mut Evaluator,
    variable: &str,
    tensor: achronyme_types::tensor::RealTensor,
    body: &AstNode,
) -> Result<Value, String> {
    // Create new scope for loop
    evaluator.environment_mut().push_scope();

    // Track that we're inside a loop
    evaluator.loop_depth += 1;

    let mut last_value = Value::Null;

    // Get tensor data (flattened view)
    let data = tensor.data();

    let result = 'outer: {
        for &value in data {
            // Bind loop variable as Number
            evaluator.environment_mut().define(variable.to_string(), Value::Number(value))?;

            // Execute body
            let body_result = evaluator.evaluate(body)?;

            // Check for control flow markers
            match body_result {
                Value::LoopBreak(break_value) => {
                    last_value = break_value.map(|v| *v).unwrap_or(Value::Null);
                    break 'outer Ok(last_value);
                }
                Value::LoopContinue => {
                    continue;
                }
                Value::EarlyReturn(_) => {
                    evaluator.loop_depth -= 1;
                    evaluator.environment_mut().pop_scope();
                    return Ok(body_result);
                }
                Value::GeneratorYield(_) => {
                    evaluator.loop_depth -= 1;
                    evaluator.environment_mut().pop_scope();
                    return Ok(body_result);
                }
                _ => {
                    last_value = body_result;
                }
            }
        }
        Ok(last_value)
    };

    evaluator.loop_depth -= 1;
    evaluator.environment_mut().pop_scope();
    result
}

/// Evaluate for-in loop over a ComplexTensor
fn evaluate_for_in_complex_tensor(
    evaluator: &mut Evaluator,
    variable: &str,
    tensor: achronyme_types::tensor::ComplexTensor,
    body: &AstNode,
) -> Result<Value, String> {
    // Create new scope for loop
    evaluator.environment_mut().push_scope();

    // Track that we're inside a loop
    evaluator.loop_depth += 1;

    let mut last_value = Value::Null;

    // Get tensor data (flattened view)
    let data = tensor.data();

    let result = 'outer: {
        for &value in data {
            // Bind loop variable as Complex
            evaluator.environment_mut().define(variable.to_string(), Value::Complex(value))?;

            // Execute body
            let body_result = evaluator.evaluate(body)?;

            // Check for control flow markers
            match body_result {
                Value::LoopBreak(break_value) => {
                    last_value = break_value.map(|v| *v).unwrap_or(Value::Null);
                    break 'outer Ok(last_value);
                }
                Value::LoopContinue => {
                    continue;
                }
                Value::EarlyReturn(_) => {
                    evaluator.loop_depth -= 1;
                    evaluator.environment_mut().pop_scope();
                    return Ok(body_result);
                }
                Value::GeneratorYield(_) => {
                    evaluator.loop_depth -= 1;
                    evaluator.environment_mut().pop_scope();
                    return Ok(body_result);
                }
                _ => {
                    last_value = body_result;
                }
            }
        }
        Ok(last_value)
    };

    evaluator.loop_depth -= 1;
    evaluator.environment_mut().pop_scope();
    result
}

/// Evaluate for-in loop with a record-based iterator (has next() method)
fn evaluate_iterator_for_in(
    evaluator: &mut Evaluator,
    variable: &str,
    next_fn: Value,
    body: &AstNode,
) -> Result<Value, String> {
    // Create new scope for loop
    evaluator.environment_mut().push_scope();

    // Track that we're inside a loop
    evaluator.loop_depth += 1;

    let mut last_value = Value::Null;

    let result = loop {
        // Call next() on the iterator
        let result = match &next_fn {
            Value::Function(func) => {
                evaluator.apply_lambda(func, vec![])?
            }
            _ => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Err("next must be a function".to_string());
            }
        };

        // Check if it's a valid iterator result {value, done}
        let result_record = match &result {
            Value::Record(map) => map,
            _ => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Err("next() must return {value: T, done: Boolean}".to_string());
            }
        };

        let done = match result_record.get("done") {
            Some(Value::Boolean(b)) => *b,
            _ => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Err("next() must return {done: Boolean}".to_string());
            }
        };

        if done {
            break Ok(last_value);
        }

        let value = result_record
            .get("value")
            .cloned()
            .ok_or_else(|| "next() must return {value: T}".to_string())?;

        // Bind loop variable in current scope
        evaluator.environment_mut().define(variable.to_string(), value)?;

        // Execute body
        let body_result = evaluator.evaluate(body)?;

        // Check for control flow markers
        match body_result {
            Value::LoopBreak(break_value) => {
                last_value = break_value.map(|v| *v).unwrap_or(Value::Null);
                break Ok(last_value);
            }
            Value::LoopContinue => {
                continue;
            }
            Value::EarlyReturn(_) => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Ok(body_result);
            }
            Value::GeneratorYield(_) => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Ok(body_result);
            }
            _ => {
                last_value = body_result;
            }
        }
    };

    evaluator.loop_depth -= 1;
    evaluator.environment_mut().pop_scope();
    result
}

/// Helper to evaluate for-in loop with a generator
fn evaluate_generator_for_in(
    evaluator: &mut Evaluator,
    variable: &str,
    gen_rc: Rc<RefCell<GeneratorState>>,
    body: &AstNode,
) -> Result<Value, String> {
    // Create new scope for loop
    evaluator.environment_mut().push_scope();

    // Track that we're inside a loop
    evaluator.loop_depth += 1;

    let mut last_value = Value::Null;

    let result = loop {
        // Resume the generator
        let result = resume_generator(evaluator, &gen_rc)?;

        // Check if done
        let result_record = match &result {
            Value::Record(map) => map,
            _ => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Err("Generator next() must return {value: T, done: Boolean}".to_string());
            }
        };

        let done = match result_record.get("done") {
            Some(Value::Boolean(b)) => *b,
            _ => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Err("Generator next() must return {done: Boolean}".to_string());
            }
        };

        if done {
            break Ok(last_value);
        }

        let value = result_record
            .get("value")
            .cloned()
            .ok_or_else(|| "Generator next() must return {value: T}".to_string())?;

        // Bind loop variable
        evaluator.environment_mut().define(variable.to_string(), value)?;

        // Execute body
        let body_result = evaluator.evaluate(body)?;

        // Check for control flow markers
        match body_result {
            // Break: exit the loop immediately
            Value::LoopBreak(break_value) => {
                last_value = break_value.map(|v| *v).unwrap_or(Value::Null);
                break Ok(last_value);
            }
            // Continue: skip to next iteration
            Value::LoopContinue => {
                // Just continue to next iteration
                continue;
            }
            // Early return: propagate it immediately
            Value::EarlyReturn(_) => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Ok(body_result);
            }
            // Generator yield: propagate it immediately
            Value::GeneratorYield(_) => {
                evaluator.loop_depth -= 1;
                evaluator.environment_mut().pop_scope();
                return Ok(body_result);
            }
            // Normal value: store it
            _ => {
                last_value = body_result;
            }
        }
    };

    evaluator.loop_depth -= 1;
    evaluator.environment_mut().pop_scope();
    result
}

/// Resume a generator and return the next {value, done} result
pub fn resume_generator(
    evaluator: &mut Evaluator,
    gen: &Rc<RefCell<GeneratorState>>,
) -> Result<Value, String> {
    let mut state = gen.borrow_mut();

    // If already done, return sticky value
    if state.done {
        let return_val = state.return_value.as_ref()
            .map(|v| (**v).clone())
            .unwrap_or(Value::Null);
        return Ok(make_iterator_result(return_val, true));
    }

    // For re-execution approach: reset to original environment
    // This allows nested control flow to work correctly
    let env_to_use = if let Some(ref orig_env) = state.original_env {
        orig_env.clone()
    } else {
        state.env.clone()
    };

    // Swap environments: save evaluator's current env, use generator's env
    let saved_env = std::mem::replace(evaluator.environment_mut(), env_to_use);

    // Save and set generator context
    let saved_in_generator = evaluator.in_generator;
    evaluator.in_generator = true;

    // Save and set yield tracking
    let saved_yield_count = evaluator.generator_yield_count;
    let saved_yield_target = evaluator.generator_yield_target;
    evaluator.generator_yield_count = 0;
    evaluator.generator_yield_target = state.current_yield_target;

    // Execute until yield or end (re-execute from start, skipping already processed yields)
    let result = execute_until_yield_new(evaluator, &mut state);

    // Update state based on result
    if result.is_ok() {
        // Increment target for next resume
        state.current_yield_target += 1;
    }

    // Restore yield tracking
    evaluator.generator_yield_count = saved_yield_count;
    evaluator.generator_yield_target = saved_yield_target;

    // Restore generator context
    evaluator.in_generator = saved_in_generator;

    // Restore saved environment (don't save generator's env - we re-execute from original each time)
    let _ = std::mem::replace(evaluator.environment_mut(), saved_env);

    result
}

/// Execute generator statements using yield counting for nested control flow support
/// This approach re-executes the generator from the beginning each time,
/// but skips yields that have already been processed.
fn execute_until_yield_new(
    evaluator: &mut Evaluator,
    state: &mut GeneratorState,
) -> Result<Value, String> {
    // Re-execute all statements from the beginning
    // The environment is already set up by resume_generator with the captured state
    for stmt in state.statements.iter() {
        let result = evaluator.evaluate(stmt)?;

        // Check for generator yield marker
        if let Value::GeneratorYield(yielded_value) = result {
            // This is a yield we should stop at - save current environment state
            state.env = evaluator.environment().clone();
            return Ok(make_iterator_result(*yielded_value, false));
        }

        // Check for early return in nested code
        if let Value::EarlyReturn(inner) = result {
            state.mark_done(Some(*inner.clone()));
            return Ok(make_iterator_result(*inner, true));
        }
    }

    // Generator exhausted naturally (no explicit return)
    state.mark_done(Some(Value::Null));
    Ok(make_iterator_result(Value::Null, true))
}

/// Create an iterator result record {value: T, done: Boolean}
fn make_iterator_result(value: Value, done: bool) -> Value {
    let mut map = HashMap::new();
    map.insert("value".to_string(), value);
    map.insert("done".to_string(), Value::Boolean(done));
    Value::Record(map)
}

/// Evaluate a throw statement
/// Converts the thrown value into an Error and returns Err() to propagate
pub fn evaluate_throw(
    evaluator: &mut Evaluator,
    value: &AstNode,
) -> Result<Value, String> {
    let thrown_value = evaluator.evaluate(value)?;

    // Convert the thrown value into a Value::Error
    let error_value = match thrown_value {
        // If it's already an Error, preserve it (for re-throws)
        Value::Error { message, kind, source } => {
            Value::Error { message, kind, source }
        }
        // If it's a String, wrap in Error with no kind
        Value::String(msg) => {
            Value::Error {
                message: msg,
                kind: None,
                source: None,
            }
        }
        // If it's a Record, try to extract message and kind fields
        Value::Record(ref map) => {
            let message = match map.get("message") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => format!("{:?}", other),
                None => "Unknown error".to_string(),
            };
            let kind = match map.get("kind") {
                Some(Value::String(s)) => Some(s.clone()),
                _ => None,
            };
            Value::Error {
                message,
                kind,
                source: None,
            }
        }
        // For other values, convert to string
        other => {
            Value::Error {
                message: format!("{:?}", other),
                kind: None,
                source: None,
            }
        }
    };

    // Format the error for propagation
    let error_string = match &error_value {
        Value::Error { message, kind, .. } => {
            match kind {
                Some(k) => format!("Thrown: {} - {}", k, message),
                None => format!("Thrown: {}", message),
            }
        }
        _ => "Thrown: Unknown error".to_string(),
    };

    // Return the error as Err to propagate up the call stack
    // We encode the error value in the string for try_catch to parse
    Err(error_string)
}

/// Evaluate a try-catch expression
/// Catches errors thrown in the try block and binds them to the error parameter
pub fn evaluate_try_catch(
    evaluator: &mut Evaluator,
    try_block: &AstNode,
    error_param: &str,
    catch_block: &AstNode,
) -> Result<Value, String> {
    // Evaluate the try block
    match evaluator.evaluate(try_block) {
        Ok(value) => {
            // Check for special internal markers that should propagate
            match value {
                // EarlyReturn should propagate through try/catch
                Value::EarlyReturn(_) => Ok(value),
                // GeneratorYield should propagate (generators can't span try/catch)
                Value::GeneratorYield(_) => Ok(value),
                // Normal value - return it
                _ => Ok(value),
            }
        }
        Err(error_string) => {
            // An error was thrown - handle it in the catch block

            // Parse the error string to create an Error value
            let error_value = parse_error_string(&error_string);

            // Create a new scope for the catch block
            evaluator.environment_mut().push_scope();

            // Bind the error value to the error parameter
            if let Err(e) = evaluator.environment_mut().define(error_param.to_string(), error_value) {
                evaluator.environment_mut().pop_scope();
                return Err(e);
            }

            // Evaluate the catch block
            let result = evaluator.evaluate(catch_block);

            // Pop the catch scope
            evaluator.environment_mut().pop_scope();

            result
        }
    }
}

/// Parse an error string into a Value::Error
/// Handles the "Thrown: " prefix format from evaluate_throw
fn parse_error_string(error_string: &str) -> Value {
    if let Some(rest) = error_string.strip_prefix("Thrown: ") {
        // Check if it has a kind prefix (e.g., "TypeError - message")
        if let Some(dash_pos) = rest.find(" - ") {
            let kind = rest[..dash_pos].to_string();
            let message = rest[dash_pos + 3..].to_string();
            Value::Error {
                message,
                kind: Some(kind),
                source: None,
            }
        } else {
            Value::Error {
                message: rest.to_string(),
                kind: None,
                source: None,
            }
        }
    } else {
        // Generic error (not from throw)
        Value::Error {
            message: error_string.to_string(),
            kind: Some("RuntimeError".to_string()),
            source: None,
        }
    }
}
