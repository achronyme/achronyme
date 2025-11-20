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

