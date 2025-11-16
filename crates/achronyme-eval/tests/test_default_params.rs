//! Test suite for default parameter values in function definitions
//!
//! This tests the feature that allows parameters to have default values:
//! - (x = 10) => x * 2
//! - (name: String, greeting = "Hello") => greeting + ", " + name
//! - (url: String, timeout: Number = 5000) => ...

use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

#[test]
fn test_simple_default_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = 10) => x * 2
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(20.0));
}

#[test]
fn test_default_value_with_explicit_arg() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = 10) => x * 2
        f(5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_multiple_defaults() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (a = 1, b = 2, c = 3) => a + b + c
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(6.0));
}

#[test]
fn test_partial_defaults() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (a = 1, b = 2, c = 3) => a + b + c
        f(10)
    "#);
    assert_eq!(result.unwrap(), Value::Number(15.0));
}

#[test]
fn test_partial_defaults_two_args() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (a = 1, b = 2, c = 3) => a + b + c
        f(10, 20)
    "#);
    assert_eq!(result.unwrap(), Value::Number(33.0));
}

#[test]
fn test_all_args_provided() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (a = 1, b = 2, c = 3) => a + b + c
        f(10, 20, 30)
    "#);
    assert_eq!(result.unwrap(), Value::Number(60.0));
}

#[test]
fn test_mixed_required_and_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let greet = (name, greeting = "Hello") => greeting + ", " + name
        greet("Alice")
    "#);
    assert_eq!(result.unwrap(), Value::String("Hello, Alice".to_string()));
}

#[test]
fn test_mixed_required_and_default_with_all_args() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let greet = (name, greeting = "Hello") => greeting + ", " + name
        greet("Bob", "Hi")
    "#);
    assert_eq!(result.unwrap(), Value::String("Hi, Bob".to_string()));
}

#[test]
fn test_typed_parameter_with_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let fetch = (url: String, timeout: Number = 5000) => timeout
        fetch("api.com")
    "#);
    assert_eq!(result.unwrap(), Value::Number(5000.0));
}

#[test]
fn test_typed_parameter_with_default_overridden() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let fetch = (url: String, timeout: Number = 5000) => timeout
        fetch("api.com", 10000)
    "#);
    assert_eq!(result.unwrap(), Value::Number(10000.0));
}

#[test]
fn test_default_expression() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = 2 + 3) => x * 2
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_default_uses_closure_env() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let base = 100
        let f = (x = base) => x * 2
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(200.0));
}

#[test]
fn test_complex_default_expression() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = [1, 2, 3]) => x[0] + x[1] + x[2]
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(6.0));
}

#[test]
fn test_boolean_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = true) => if(x, 1, 0)
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(1.0));
}

#[test]
fn test_boolean_default_overridden() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = true) => if(x, 1, 0)
        f(false)
    "#);
    assert_eq!(result.unwrap(), Value::Number(0.0));
}

#[test]
fn test_string_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (msg = "default") => msg
        f()
    "#);
    assert_eq!(result.unwrap(), Value::String("default".to_string()));
}

#[test]
fn test_record_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (config = { timeout: 5000, retries: 3 }) => config.timeout + config.retries
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(5003.0));
}

#[test]
fn test_error_on_missing_required_param() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x, y = 10) => x + y
        f()
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("expects") || err.contains("arguments"));
}

#[test]
fn test_error_on_too_many_args() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x = 10) => x * 2
        f(1, 2, 3)
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("expects at most"));
}

#[test]
fn test_full_typed_function_with_defaults() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let calc = (a: Number, b: Number = 0, c: Number = 1): Number => (a + b) * c
        calc(10)
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_full_typed_function_with_defaults_partial() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let calc = (a: Number, b: Number = 0, c: Number = 1): Number => (a + b) * c
        calc(10, 5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(15.0));
}

#[test]
fn test_full_typed_function_with_defaults_all_args() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let calc = (a: Number, b: Number = 0, c: Number = 1): Number => (a + b) * c
        calc(10, 5, 2)
    "#);
    assert_eq!(result.unwrap(), Value::Number(30.0));
}

#[test]
fn test_type_check_on_default_value() {
    let mut eval = Evaluator::new();
    // Default value should type-check when used
    let result = eval.eval_str(r#"
        let f = (x: Number = 42) => x * 2
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(84.0));
}

#[test]
fn test_higher_order_function_with_defaults() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let makeAdder = (n = 10) => x => x + n
        let add10 = makeAdder()
        add10(5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(15.0));
}

#[test]
fn test_higher_order_function_with_defaults_custom() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let makeAdder = (n = 10) => x => x + n
        let add20 = makeAdder(20)
        add20(5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(25.0));
}

#[test]
fn test_iife_with_defaults() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        ((x = 5, y = 10) => x * y)()
    "#);
    assert_eq!(result.unwrap(), Value::Number(50.0));
}

#[test]
fn test_iife_with_defaults_partial() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        ((x = 5, y = 10) => x * y)(3)
    "#);
    assert_eq!(result.unwrap(), Value::Number(30.0));
}

#[test]
fn test_recursive_function_with_defaults() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let factorial = (n, acc = 1) => if(n <= 1, acc, rec(n - 1, acc * n))
        factorial(5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(120.0));
}

#[test]
fn test_null_default() {
    let mut eval = Evaluator::new();
    // Use match for null comparison instead of ==
    let result = eval.eval_str(r#"
        let f = (x = null) => match x {
            Null => "none",
            _ => "some"
        }
        f()
    "#);
    assert_eq!(result.unwrap(), Value::String("none".to_string()));
}

#[test]
fn test_null_default_overridden() {
    let mut eval = Evaluator::new();
    // Use match for null comparison instead of ==
    let result = eval.eval_str(r#"
        let f = (x = null) => match x {
            Null => "none",
            _ => "some"
        }
        f(42)
    "#);
    assert_eq!(result.unwrap(), Value::String("some".to_string()));
}
