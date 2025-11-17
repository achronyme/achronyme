mod test_common;
use test_common::eval;
use achronyme_types::value::Value;

// ============================================================================
// OR (||) Operator Tests
// ============================================================================

#[test]
fn test_or_returns_first_truthy() {
    // true || anything -> true
    let result = eval("true || false").unwrap();
    assert_eq!(result, Value::Boolean(true));

    // "hello" || "world" -> "hello"
    let result = eval(r#""hello" || "world""#).unwrap();
    assert_eq!(result, Value::String("hello".to_string()));

    // 42 || 100 -> 42
    let result = eval("42 || 100").unwrap();
    assert_eq!(result, Value::Number(42.0));

    // [1, 2] || null -> [1, 2]
    let result = eval("[1, 2] || null").unwrap();
    if let Value::Vector(vec) = result {
        assert_eq!(vec.len(), 2);
    } else {
        panic!("Expected Vector");
    }
}

#[test]
fn test_or_returns_right_when_left_falsy() {
    // false || "default" -> "default"
    let result = eval(r#"false || "default""#).unwrap();
    assert_eq!(result, Value::String("default".to_string()));

    // null || 42 -> 42
    let result = eval("null || 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    // 0 || 100 -> 100
    let result = eval("0 || 100").unwrap();
    assert_eq!(result, Value::Number(100.0));

    // "" || "fallback" -> "fallback"
    let result = eval(r#""" || "fallback""#).unwrap();
    assert_eq!(result, Value::String("fallback".to_string()));
}

#[test]
fn test_or_returns_last_falsy() {
    // false || false -> false
    let result = eval("false || false").unwrap();
    assert_eq!(result, Value::Boolean(false));

    // false || null -> null
    let result = eval("false || null").unwrap();
    assert_eq!(result, Value::Null);

    // 0 || false -> false
    let result = eval("0 || false").unwrap();
    assert_eq!(result, Value::Boolean(false));

    // "" || 0 -> 0
    let result = eval(r#""" || 0"#).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_short_circuit_or_does_not_evaluate_right() {
    // If left is truthy, right should not be evaluated
    // We test this by using a side effect - an undefined variable access would fail
    // But since we're short-circuiting, it should succeed
    let result = eval(r#"
        true || undefined_variable
    "#).unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = eval(r#"
        "value" || some_error_function()
    "#).unwrap();
    assert_eq!(result, Value::String("value".to_string()));

    let result = eval("42 || (1 / 0)").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

// ============================================================================
// AND (&&) Operator Tests
// ============================================================================

#[test]
fn test_and_returns_first_falsy() {
    // false && anything -> false
    let result = eval("false && true").unwrap();
    assert_eq!(result, Value::Boolean(false));

    // null && "result" -> null
    let result = eval(r#"null && "result""#).unwrap();
    assert_eq!(result, Value::Null);

    // 0 && 100 -> 0
    let result = eval("0 && 100").unwrap();
    assert_eq!(result, Value::Number(0.0));

    // "" && "something" -> ""
    let result = eval(r#""" && "something""#).unwrap();
    assert_eq!(result, Value::String("".to_string()));
}

#[test]
fn test_and_returns_right_when_left_truthy() {
    // true && "result" -> "result"
    let result = eval(r#"true && "result""#).unwrap();
    assert_eq!(result, Value::String("result".to_string()));

    // "hello" && "world" -> "world"
    let result = eval(r#""hello" && "world""#).unwrap();
    assert_eq!(result, Value::String("world".to_string()));

    // 42 && 100 -> 100
    let result = eval("42 && 100").unwrap();
    assert_eq!(result, Value::Number(100.0));

    // [1] && false -> false
    let result = eval("[1] && false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_and_returns_last_truthy() {
    // true && true -> true
    let result = eval("true && true").unwrap();
    assert_eq!(result, Value::Boolean(true));

    // 1 && 2 && 3 -> 3
    let result = eval("1 && 2 && 3").unwrap();
    assert_eq!(result, Value::Number(3.0));

    // "a" && "b" && "c" -> "c"
    let result = eval(r#""a" && "b" && "c""#).unwrap();
    assert_eq!(result, Value::String("c".to_string()));
}

#[test]
fn test_short_circuit_and_does_not_evaluate_right() {
    // If left is falsy, right should not be evaluated
    let result = eval(r#"
        false && undefined_variable
    "#).unwrap();
    assert_eq!(result, Value::Boolean(false));

    let result = eval(r#"
        null && some_error_function()
    "#).unwrap();
    assert_eq!(result, Value::Null);

    let result = eval("0 && (1 / 0)").unwrap();
    assert_eq!(result, Value::Number(0.0));
}

// ============================================================================
// Truthy/Falsy Value Tests
// ============================================================================

#[test]
fn test_falsy_values() {
    // All falsy values with ||: should return the second operand

    // false is falsy
    let result = eval(r#"false || "yes""#).unwrap();
    assert_eq!(result, Value::String("yes".to_string()));

    // null is falsy
    let result = eval(r#"null || "yes""#).unwrap();
    assert_eq!(result, Value::String("yes".to_string()));

    // 0 is falsy
    let result = eval(r#"0 || "yes""#).unwrap();
    assert_eq!(result, Value::String("yes".to_string()));

    // Empty string is falsy
    let result = eval(r#""" || "yes""#).unwrap();
    assert_eq!(result, Value::String("yes".to_string()));

    // NaN is falsy (0/0 produces NaN)
    let result = eval(r#"(0/0) || "yes""#).unwrap();
    assert_eq!(result, Value::String("yes".to_string()));
}

#[test]
fn test_truthy_values() {
    // All truthy values with &&: should return the second operand

    // true is truthy
    let result = eval("true && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    // Non-zero numbers are truthy
    let result = eval("1 && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
    let result = eval("-1 && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
    let result = eval("0.5 && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    // Non-empty strings are truthy
    let result = eval(r#""hello" && 42"#).unwrap();
    assert_eq!(result, Value::Number(42.0));
    let result = eval(r#""0" && 42"#).unwrap(); // "0" as string is truthy
    assert_eq!(result, Value::Number(42.0));

    // Arrays are truthy (even empty ones - like JS)
    let result = eval("[] && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
    let result = eval("[1, 2, 3] && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    // Records are truthy (even empty ones)
    let result = eval("{} && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
    let result = eval("{ a: 1 } && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

// ============================================================================
// Common Usage Patterns
// ============================================================================

#[test]
fn test_null_coalescing_pattern() {
    // value || default pattern (like JavaScript's ||)
    let code = r#"
        let value = null;
        value || "default"
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::String("default".to_string()));

    let code = r#"
        let value = "provided";
        value || "default"
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::String("provided".to_string()));
}

#[test]
fn test_guard_pattern() {
    // condition && action pattern (guard)
    let code = r#"
        let x = 10;
        x > 5 && x * 2
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::Number(20.0));

    let code = r#"
        let x = 3;
        x > 5 && x * 2
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_chained_or() {
    // a || b || c pattern
    let result = eval("false || null || 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = eval(r#"false || "first" || "second""#).unwrap();
    assert_eq!(result, Value::String("first".to_string()));

    let result = eval("null || null || null").unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn test_chained_and() {
    // a && b && c pattern
    let result = eval("true && true && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = eval("1 && 2 && 3 && 4").unwrap();
    assert_eq!(result, Value::Number(4.0));

    let result = eval("true && false && 42").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_mixed_logical_operators() {
    // Combining && and ||
    let result = eval("false || true && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = eval("(false || true) && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = eval("true && false || 100").unwrap();
    assert_eq!(result, Value::Number(100.0));
}

#[test]
fn test_with_function_calls() {
    // Short-circuit with actual function calls
    let code = r#"
        let setFlag = () => true;
        true || setFlag()
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::Boolean(true));

    let code = r#"
        let getValue = () => 42;
        true && getValue()
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

// ============================================================================
// Edge Cases and Type Preservation
// ============================================================================

#[test]
fn test_type_preservation() {
    // Ensure we return the actual values, not converted booleans

    // Number should be returned as Number
    let result = eval("true && 3.14").unwrap();
    assert_eq!(result, Value::Number(3.14));

    // String should be returned as String
    let result = eval(r#"true && "text""#).unwrap();
    assert_eq!(result, Value::String("text".to_string()));

    // Record should be returned as Record
    let result = eval("true && { x: 1, y: 2 }").unwrap();
    if let Value::Record(map) = result {
        assert_eq!(map.get("x"), Some(&Value::Number(1.0)));
        assert_eq!(map.get("y"), Some(&Value::Number(2.0)));
    } else {
        panic!("Expected Record");
    }
}

#[test]
fn test_complex_number_truthiness() {
    // Complex numbers: truthiness based on magnitude
    // Non-zero complex is truthy
    let result = eval("1i && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = eval("(1 + 2i) && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_negative_zero() {
    // -0.0 should be falsy (IEEE 754)
    let result = eval("(-0.0) || 42").unwrap();
    // Note: In Rust, -0.0 == 0.0, so this should return 42
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_infinity_truthiness() {
    // Infinity is truthy (it's a number, non-zero)
    let result = eval("(1/0) && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));

    // Negative infinity is also truthy
    let result = eval("(-1/0) && 42").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

// ============================================================================
// Backward Compatibility Tests
// ============================================================================

#[test]
fn test_boolean_only_cases_still_work() {
    // Old code using && and || with just booleans should still work
    let result = eval("true && true").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = eval("true && false").unwrap();
    assert_eq!(result, Value::Boolean(false));

    let result = eval("false || true").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = eval("false || false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_conditional_expressions() {
    // Using && and || in if conditions
    let code = r#"
        let x = 5;
        if (x > 0 && x < 10) {
            "in range"
        } else {
            "out of range"
        }
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::String("in range".to_string()));

    let code = r#"
        let x = -5;
        if (x < 0 || x > 100) {
            "invalid"
        } else {
            "valid"
        }
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::String("invalid".to_string()));
}
