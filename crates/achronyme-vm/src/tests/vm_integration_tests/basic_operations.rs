use super::helpers::execute;
use crate::value::Value;

#[test]
fn test_number_literal() {
    let result = execute("42").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_boolean_literal() {
    let result = execute("true").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute("false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_null_literal() {
    let result = execute("null").unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn test_addition() {
    let result = execute("2 + 3").unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_subtraction() {
    let result = execute("10 - 4").unwrap();
    assert_eq!(result, Value::Number(6.0));
}

#[test]
fn test_multiplication() {
    let result = execute("6 * 7").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_division() {
    let result = execute("20 / 4").unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_negation() {
    let result = execute("-42").unwrap();
    assert_eq!(result, Value::Number(-42.0));
}

#[test]
fn test_arithmetic_combination() {
    let result = execute("2 + 3 * 4").unwrap();
    assert_eq!(result, Value::Number(14.0));
}

#[test]
fn test_comparison() {
    let result = execute("5 < 10").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute("5 > 10").unwrap();
    assert_eq!(result, Value::Boolean(false));

    let result = execute("5 == 5").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_variable_declaration() {
    let result = execute("let x = 42\nx").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_variable_assignment() {
    let result = execute("mut x = 10\nx = 20\nx").unwrap();
    assert_eq!(result, Value::Number(20.0));
}

#[test]
fn test_multiple_variables() {
    let result = execute("let x = 5\nlet y = 10\nx + y").unwrap();
    assert_eq!(result, Value::Number(15.0));
}

// ============================================================================
// Logical Operators with Short-Circuit Evaluation
// ============================================================================

#[test]
fn test_and_both_true() {
    let result = execute("true && true").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_and_first_false() {
    let result = execute("false && true").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_and_second_false() {
    let result = execute("true && false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_and_both_false() {
    let result = execute("false && false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_or_both_true() {
    let result = execute("true || true").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_or_first_true() {
    let result = execute("true || false").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_or_second_true() {
    let result = execute("false || true").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_or_both_false() {
    let result = execute("false || false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_not_operator() {
    let result = execute("!true").unwrap();
    assert_eq!(result, Value::Boolean(false));

    let result = execute("!false").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_and_short_circuit() {
    // If first operand is false, second should not be evaluated
    // This test uses a side effect to verify: if second is evaluated, x would be assigned
    let source = r#"
        mut x = 0
        false && do { x = 1; true }
        x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(
        result,
        Value::Number(0.0),
        "Second operand should not be evaluated"
    );
}

#[test]
fn test_or_short_circuit() {
    // If first operand is true, second should not be evaluated
    let source = r#"
        mut x = 0
        true || do { x = 1; false }
        x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(
        result,
        Value::Number(0.0),
        "Second operand should not be evaluated"
    );
}

#[test]
fn test_and_with_numbers() {
    // Numbers are truthy if non-zero
    let result = execute("5 && 10").unwrap();
    assert_eq!(
        result,
        Value::Number(10.0),
        "Should return second value when both truthy"
    );

    let result = execute("0 && 10").unwrap();
    assert_eq!(
        result,
        Value::Number(0.0),
        "Should return first value when first is falsy"
    );

    let result = execute("5 && 0").unwrap();
    assert_eq!(
        result,
        Value::Number(0.0),
        "Should return second value even if falsy"
    );
}

#[test]
fn test_or_with_numbers() {
    let result = execute("0 || 10").unwrap();
    assert_eq!(
        result,
        Value::Number(10.0),
        "Should return second value when first is falsy"
    );

    let result = execute("5 || 10").unwrap();
    assert_eq!(
        result,
        Value::Number(5.0),
        "Should return first value when first is truthy"
    );
}

#[test]
fn test_complex_logical_expression() {
    let result = execute("true && false || true").unwrap();
    assert_eq!(
        result,
        Value::Boolean(true),
        "(true && false) || true = false || true = true"
    );

    let result = execute("false || true && false").unwrap();
    assert_eq!(
        result,
        Value::Boolean(false),
        "false || (true && false) = false || false = false"
    );
}

#[test]
fn test_logical_with_comparisons() {
    let result = execute("5 > 3 && 10 < 20").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute("5 > 10 || 3 < 8").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute("5 > 3 && 10 > 20").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

// ============================================================================
// Interpolated Strings
// ============================================================================

#[test]
fn test_interpolated_string_with_number() {
    let result = execute(r#"let x = 42; 'Value: ${x}'"#).unwrap();
    assert_eq!(result, Value::String("Value: 42".to_string()));
}

#[test]
fn test_interpolated_string_with_expression() {
    let result = execute(r#"'Result: ${2 + 3}'"#).unwrap();
    assert_eq!(result, Value::String("Result: 5".to_string()));
}

#[test]
fn test_interpolated_string_multiple_parts() {
    let result = execute(r#"let x = 10; let y = 20; 'x=${x}, y=${y}, sum=${x+y}'"#).unwrap();
    assert_eq!(result, Value::String("x=10, y=20, sum=30".to_string()));
}

#[test]
fn test_interpolated_string_with_string() {
    let result = execute(r#"let name = "Alice"; 'Hello, ${name}!'"#).unwrap();
    assert_eq!(result, Value::String("Hello, Alice!".to_string()));
}

#[test]
fn test_interpolated_string_only_literal() {
    let result = execute(r#"'Just a plain string'"#).unwrap();
    assert_eq!(result, Value::String("Just a plain string".to_string()));
}

#[test]
fn test_interpolated_string_only_expression() {
    let result = execute(r#"'${42}'"#).unwrap();
    assert_eq!(result, Value::String("42".to_string()));
}

#[test]
fn test_interpolated_string_with_boolean() {
    let result = execute(r#"'Boolean: ${true}'"#).unwrap();
    assert_eq!(result, Value::String("Boolean: true".to_string()));
}

#[test]
fn test_interpolated_string_in_loop() {
    let source = r#"
        mut result = ""
        for(x in [1,2,3]) {
            result = result + '-${x}'
        }
        result
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("-1-2-3".to_string()));
}
