//! Test suite for optional parameters with the ? operator
//!
//! Optional parameters allow functions to have parameters that can be omitted:
//! - (a: Number, b?: String) => ... // b is optional, defaults to null
//! - (x?, y?: Number) => ...        // both optional
//! - Type? as shorthand for Type | null in function type annotations

use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

// ============================================================================
// Basic Optional Parameters
// ============================================================================

#[test]
fn test_optional_param_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (a: Number, b?: String) =>
            match b {
                null => str(a),
                _ => str(a) + " " + b
            }
        f(42)
    "#);
    assert_eq!(result.unwrap(), Value::String("42".to_string()));
}

#[test]
fn test_optional_param_with_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (a: Number, b?: String) =>
            match b {
                null => str(a),
                _ => str(a) + " " + b
            }
        f(42, "hello")
    "#);
    assert_eq!(result.unwrap(), Value::String("42 hello".to_string()));
}

#[test]
fn test_optional_param_is_null() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x?: Number) => x
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Null);
}

#[test]
fn test_optional_param_with_explicit_null() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x?: Number) => x
        f(null)
    "#);
    assert_eq!(result.unwrap(), Value::Null);
}

#[test]
fn test_optional_param_untyped() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let g = (x, y?) => match y { null => x, _ => x + y }
        g(10)
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_optional_param_untyped_with_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let g = (x, y?) => match y { null => x, _ => x + y }
        g(10, 5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(15.0));
}

// ============================================================================
// Multiple Optional Parameters
// ============================================================================

#[test]
fn test_multiple_optional_params_none() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let h = (a: Number, b?: String, c?: Number) =>
            match c {
                null => match b { null => a, _ => length(b) },
                _ => a + c
            }
        h(100)
    "#);
    assert_eq!(result.unwrap(), Value::Number(100.0));
}

#[test]
fn test_multiple_optional_params_first_only() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let h = (a: Number, b?: String, c?: Number) =>
            match c {
                null => match b { null => a, _ => length(b) },
                _ => a + c
            }
        h(100, "test")
    "#);
    assert_eq!(result.unwrap(), Value::Number(4.0));
}

#[test]
fn test_multiple_optional_params_all() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let h = (a: Number, b?: String, c?: Number) =>
            match c {
                null => match b { null => a, _ => length(b) },
                _ => a + c
            }
        h(100, "test", 50)
    "#);
    assert_eq!(result.unwrap(), Value::Number(150.0));
}

// ============================================================================
// Optional Parameters with Return Types
// ============================================================================

#[test]
fn test_optional_param_with_return_type() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let i = (x?: Number): Number => match x { null => 0, _ => x }
        i()
    "#);
    assert_eq!(result.unwrap(), Value::Number(0.0));
}

#[test]
fn test_optional_param_with_return_type_provided() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let i = (x?: Number): Number => match x { null => 0, _ => x }
        i(42)
    "#);
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

// ============================================================================
// Type Checking for Optional Parameters
// ============================================================================

#[test]
fn test_optional_param_type_check_number() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x?: Number) => x
        f(100)
    "#);
    assert_eq!(result.unwrap(), Value::Number(100.0));
}

#[test]
fn test_optional_param_type_check_string() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (name?: String) => name
        f("Alice")
    "#);
    assert_eq!(result.unwrap(), Value::String("Alice".to_string()));
}

#[test]
fn test_optional_param_type_mismatch() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x?: Number) => x
        f("not a number")
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Type error") || err.contains("expected"));
}

// ============================================================================
// Mixed Optional and Default Parameters
// ============================================================================

#[test]
fn test_optional_before_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let mix = (a: Number, b?: String, c: Number = 10) => a + c
        mix(5)
    "#);
    assert_eq!(result.unwrap(), Value::Number(15.0));
}

#[test]
fn test_optional_and_default_partial() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let mix = (a: Number, b?: String, c: Number = 10) =>
            match b { null => a + c, _ => a + c + length(b) }
        mix(5, "hi")
    "#);
    assert_eq!(result.unwrap(), Value::Number(17.0));
}

#[test]
fn test_optional_and_default_all() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let mix = (a: Number, b?: String, c: Number = 10) =>
            match b { null => a + c, _ => a + c + length(b) }
        mix(5, "hi", 20)
    "#);
    assert_eq!(result.unwrap(), Value::Number(27.0));
}

// ============================================================================
// Type? Shorthand Syntax
// ============================================================================

#[test]
fn test_type_shorthand_in_function_type() {
    let mut eval = Evaluator::new();
    // Note: Type? in function type only makes the type Number | null
    // It doesn't make the parameter optional (that requires ? on the parameter itself)
    let result = eval.eval_str(r#"
        let handler: (String, Number?): String = (url, timeout?) =>
            match timeout { null => url, _ => url + ":" + str(timeout) }
        handler("http://api.com")
    "#);
    assert_eq!(result.unwrap(), Value::String("http://api.com".to_string()));
}

#[test]
fn test_type_shorthand_in_function_type_with_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let handler: (String, Number?): String = (url, timeout?) =>
            match timeout { null => url, _ => url + ":" + str(timeout) }
        handler("http://api.com", 5000)
    "#);
    assert_eq!(result.unwrap(), Value::String("http://api.com:5000".to_string()));
}

#[test]
fn test_type_shorthand_variable_declaration() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let x: Number? = null
        x
    "#);
    assert_eq!(result.unwrap(), Value::Null);
}

#[test]
fn test_type_shorthand_variable_with_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let x: Number? = 42
        x
    "#);
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

#[test]
fn test_type_shorthand_string() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let name: String? = "Alice"
        name
    "#);
    assert_eq!(result.unwrap(), Value::String("Alice".to_string()));
}

#[test]
fn test_type_shorthand_in_type_alias() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        type Handler = (String, Number?): String
        let h: Handler = (url, timeout?) =>
            match timeout { null => "default", _ => url }
        h("test")
    "#);
    assert_eq!(result.unwrap(), Value::String("default".to_string()));
}

// ============================================================================
// Error Cases
// ============================================================================

#[test]
fn test_error_optional_with_default() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let bad = (x? = 10) => x
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("optional") || err.contains("default"));
}

#[test]
fn test_error_optional_before_required() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let bad = (a?, b: Number) => b
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("default") || err.contains("cannot come after"));
}

#[test]
fn test_error_too_many_args() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let f = (x?: Number) => x
        f(1, 2, 3)
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("expects") || err.contains("arguments"));
}

// ============================================================================
// Complex Use Cases
// ============================================================================

#[test]
fn test_optional_in_higher_order_function() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let apply = (f, x, y?) => match y { null => f(x, 0), _ => f(x, y) }
        let add = (a, b) => a + b
        apply(add, 10)
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_optional_with_record_type() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let process = (data: {value: Number}, options?: {verbose: Boolean}) =>
            match options {
                null => data.value,
                _ => match options.verbose {
                    true => data.value * 2,
                    false => data.value
                }
            }
        process({value: 10})
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_optional_with_record_type_provided() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let process = (data: {value: Number}, options?: {verbose: Boolean}) =>
            match options {
                null => data.value,
                _ => match options.verbose {
                    true => data.value * 2,
                    false => data.value
                }
            }
        process({value: 10}, {verbose: true})
    "#);
    assert_eq!(result.unwrap(), Value::Number(20.0));
}

#[test]
fn test_optional_in_curried_function() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let curry = (a) => (b?) => match b { null => a * 2, _ => a + b }
        let f = curry(5)
        f()
    "#);
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_optional_in_curried_function_with_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let curry = (a) => (b?) => match b { null => a * 2, _ => a + b }
        let f = curry(5)
        f(3)
    "#);
    assert_eq!(result.unwrap(), Value::Number(8.0));
}

// ============================================================================
// Integration with Existing Features
// ============================================================================

#[test]
fn test_optional_with_match_expression() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let describe = (x?) => match x {
            null => "nothing",
            Number => "got number",
            String => "got string",
            _ => "unknown"
        }
        describe()
    "#);
    assert_eq!(result.unwrap(), Value::String("nothing".to_string()));
}

#[test]
fn test_optional_with_match_expression_provided() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let describe = (x?) => match x {
            null => "nothing",
            n if (typeof(n) == "Number") => "got number",
            s if (typeof(s) == "String") => "got string",
            _ => "unknown"
        }
        describe(42)
    "#);
    assert_eq!(result.unwrap(), Value::String("got number".to_string()));
}

#[test]
fn test_optional_with_array_operations() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let process = (arr, multiplier?) =>
            match multiplier {
                null => arr,
                _ => map(x => x * multiplier, arr)
            }
        process([1, 2, 3])
    "#);
    let result = result.unwrap();
    if let Value::Vector(v) = result {
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], Value::Number(1.0));
        assert_eq!(v[1], Value::Number(2.0));
        assert_eq!(v[2], Value::Number(3.0));
    } else {
        panic!("Expected vector");
    }
}

#[test]
fn test_optional_with_array_operations_provided() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let process = (arr, multiplier?) =>
            match multiplier {
                null => arr,
                _ => map(x => x * multiplier, arr)
            }
        process([1, 2, 3], 10)
    "#);
    let result = result.unwrap();
    if let Value::Vector(v) = result {
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], Value::Number(10.0));
        assert_eq!(v[1], Value::Number(20.0));
        assert_eq!(v[2], Value::Number(30.0));
    } else {
        panic!("Expected vector");
    }
}
