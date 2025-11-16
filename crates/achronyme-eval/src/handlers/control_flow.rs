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

    loop {
        // Evaluate condition
        let cond_val = evaluator.evaluate(condition)?;
        let cond_bool = value_to_bool(&cond_val)?;

        // If condition is false, exit loop
        if !cond_bool {
            break;
        }

        // Execute body
        last_value = evaluator.evaluate(body)?;

        // Check for early return - propagate it immediately
        if matches!(last_value, Value::EarlyReturn(_)) {
            return Ok(last_value);
        }

        // Check for generator yield - propagate it immediately
        if matches!(last_value, Value::GeneratorYield(_)) {
            return Ok(last_value);
        }
    }

    Ok(last_value)
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

    // Create generator state
    let state = GeneratorState::new(captured_env, statements.to_vec());

    // Return generator value
    let gen_rc = Rc::new(RefCell::new(state));
    Ok(Value::Generator(gen_rc))
}

/// Evaluate a for-in loop: for(variable in iterable) { body }
/// Iterates over an iterator (object with next() method)
pub fn evaluate_for_in(
    evaluator: &mut Evaluator,
    variable: &str,
    iterable: &AstNode,
    body: &AstNode,
) -> Result<Value, String> {
    // Evaluate iterable expression
    let iter_value = evaluator.evaluate(iterable)?;

    // Check if it has a next() method (must be a record or generator)
    let next_fn = match &iter_value {
        Value::Record(map) => {
            map.get("next")
                .cloned()
                .ok_or_else(|| "Iterable must have a 'next' method".to_string())?
        }
        Value::Generator(gen_rc) => {
            // For generators, we create a wrapper that calls resume_generator
            // Return the generator itself - we'll handle .next() specially
            return evaluate_generator_for_in(evaluator, variable, gen_rc.clone(), body);
        }
        _ => {
            return Err("for-in requires an iterable (object with next method or generator)".to_string());
        }
    };

    // Create new scope for loop
    evaluator.environment_mut().push_scope();

    let mut last_value = Value::Null;

    loop {
        // Call next() on the iterator
        let result = match &next_fn {
            Value::Function(func) => {
                evaluator.apply_lambda(func, vec![])?
            }
            _ => {
                evaluator.environment_mut().pop_scope();
                return Err("next must be a function".to_string());
            }
        };

        // Check if it's a valid iterator result {value, done}
        let result_record = match &result {
            Value::Record(map) => map,
            _ => {
                evaluator.environment_mut().pop_scope();
                return Err("next() must return {value: T, done: Boolean}".to_string());
            }
        };

        let done = match result_record.get("done") {
            Some(Value::Boolean(b)) => *b,
            _ => {
                evaluator.environment_mut().pop_scope();
                return Err("next() must return {done: Boolean}".to_string());
            }
        };

        if done {
            break;
        }

        let value = result_record
            .get("value")
            .cloned()
            .ok_or_else(|| "next() must return {value: T}".to_string())?;

        // Bind loop variable in current scope
        evaluator.environment_mut().define(variable.to_string(), value)?;

        // Execute body
        last_value = evaluator.evaluate(body)?;

        // Check for early return - propagate it immediately
        if matches!(last_value, Value::EarlyReturn(_)) {
            evaluator.environment_mut().pop_scope();
            return Ok(last_value);
        }
    }

    evaluator.environment_mut().pop_scope();
    Ok(last_value)
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

    let mut last_value = Value::Null;

    loop {
        // Resume the generator
        let result = resume_generator(evaluator, &gen_rc)?;

        // Check if done
        let result_record = match &result {
            Value::Record(map) => map,
            _ => {
                evaluator.environment_mut().pop_scope();
                return Err("Generator next() must return {value: T, done: Boolean}".to_string());
            }
        };

        let done = match result_record.get("done") {
            Some(Value::Boolean(b)) => *b,
            _ => {
                evaluator.environment_mut().pop_scope();
                return Err("Generator next() must return {done: Boolean}".to_string());
            }
        };

        if done {
            break;
        }

        let value = result_record
            .get("value")
            .cloned()
            .ok_or_else(|| "Generator next() must return {value: T}".to_string())?;

        // Bind loop variable
        evaluator.environment_mut().define(variable.to_string(), value)?;

        // Execute body
        last_value = evaluator.evaluate(body)?;

        // Check for early return
        if matches!(last_value, Value::EarlyReturn(_)) {
            evaluator.environment_mut().pop_scope();
            return Ok(last_value);
        }
    }

    evaluator.environment_mut().pop_scope();
    Ok(last_value)
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

    // Swap environments: save evaluator's current env, use generator's env
    let saved_env = std::mem::replace(evaluator.environment_mut(), state.env.clone());

    // Save and set generator context
    let saved_in_generator = evaluator.in_generator;
    evaluator.in_generator = true;

    // Execute until yield or end
    let result = execute_until_yield(evaluator, &mut state);

    // Restore generator context
    evaluator.in_generator = saved_in_generator;

    // Restore saved environment
    state.env = std::mem::replace(evaluator.environment_mut(), saved_env);

    result
}

/// Execute generator statements until a yield, return, or end
fn execute_until_yield(
    evaluator: &mut Evaluator,
    state: &mut GeneratorState,
) -> Result<Value, String> {
    // Continue execution from current position
    while state.position < state.statements.len() {
        let stmt = state.statements[state.position].clone();
        state.position += 1;

        let result = evaluator.evaluate(&stmt)?;

        // Check for generator yield marker
        if let Value::GeneratorYield(yielded_value) = result {
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
