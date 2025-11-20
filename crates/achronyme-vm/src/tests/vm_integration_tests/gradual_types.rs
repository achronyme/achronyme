use super::helpers::execute;
use crate::value::Value;

// ============================================================================
// WEEK 17: GRADUAL TYPE SYSTEM TESTS
// ============================================================================

#[test]
fn test_type_check_number() {
    let source = r#"
        let x: Number = 42
        x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_type_assert_fails() {
    let source = r#"
        let x: Number = "string"
    "#;
    let result = execute(source);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Type assertion failed"));
    assert!(err_msg.contains("expected Number"));
}

#[test]
fn test_type_with_try_catch() {
    let source = r#"
        try {
            let x: Number = "wrong"
            x
        } catch(e) {
            42
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_vector_type() {
    let source = r#"
        let arr: Vector = [1, 2, 3]
        arr[0]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_function_type() {
    let source = r#"
        let f: Function = () => 42
        f()
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_string_type() {
    let source = r#"
        let s: String = "hello"
        s
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("hello".to_string()));
}

#[test]
fn test_boolean_type() {
    let source = r#"
        let b: Boolean = true
        b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_type_assert_boolean_fails() {
    let source = r#"
        let b: Boolean = 123
    "#;
    let result = execute(source);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Type assertion failed"));
    assert!(err_msg.contains("expected Boolean"));
    assert!(err_msg.contains("got Number"));
}