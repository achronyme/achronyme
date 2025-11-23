//! Parser tests for default parameter values
//!
//! These tests verify that the grammar and parser correctly handle default values
//! in function parameters, including validation of parameter ordering.

use achronyme_parser::ast::AstNode;
use achronyme_parser::parse;

#[test]
fn test_parse_simple_default() {
    let result = parse("(x = 10) => x * 2");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
    let stmts = result.unwrap();
    assert_eq!(stmts.len(), 1);

    match &stmts[0] {
        AstNode::Lambda { params, .. } => {
            assert_eq!(params.len(), 1);
            let (name, _ty, default) = &params[0];
            assert_eq!(name, "x");
            assert!(default.is_some());
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_parse_typed_default() {
    let result = parse("(x: Number = 10) => x * 2");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
    let stmts = result.unwrap();

    match &stmts[0] {
        AstNode::Lambda { params, .. } => {
            let (name, ty, default) = &params[0];
            assert_eq!(name, "x");
            assert!(ty.is_some());
            assert!(default.is_some());
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_parse_mixed_params() {
    let result = parse("(a, b = 10, c = 20) => a + b + c");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
    let stmts = result.unwrap();

    match &stmts[0] {
        AstNode::Lambda { params, .. } => {
            assert_eq!(params.len(), 3);

            let (name0, _, default0) = &params[0];
            assert_eq!(name0, "a");
            assert!(default0.is_none());

            let (name1, _, default1) = &params[1];
            assert_eq!(name1, "b");
            assert!(default1.is_some());

            let (name2, _, default2) = &params[2];
            assert_eq!(name2, "c");
            assert!(default2.is_some());
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_parse_error_default_before_required() {
    // This should fail because 'a' has a default but 'b' does not
    let result = parse("(a = 10, b) => a + b");
    assert!(result.is_err(), "Should have failed to parse");
    let err = result.unwrap_err();
    assert!(
        err.contains("default") || err.contains("Parameter"),
        "Error message should mention default parameter ordering: {}",
        err
    );
}

#[test]
fn test_parse_multiple_defaults_after_required() {
    let result = parse("(x: String, y: Number = 0, z: Boolean = true) => x");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_string_default() {
    let result = parse(r#"(msg = "hello") => msg"#);
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_boolean_default() {
    let result = parse("(flag = true) => flag");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_array_default() {
    let result = parse("(arr = [1, 2, 3]) => arr");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_record_default() {
    let result = parse("(config = { x: 1, y: 2 }) => config");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_expression_default() {
    let result = parse("(x = 2 + 3 * 4) => x");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_null_default() {
    let result = parse("(x = null) => x");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_complex_typed_with_defaults() {
    let result = parse("(a: Number, b: String = \"default\", c: Boolean = false): Number => 42");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());

    let stmts = result.unwrap();
    match &stmts[0] {
        AstNode::Lambda {
            params,
            return_type,
            ..
        } => {
            assert_eq!(params.len(), 3);
            assert!(return_type.is_some());
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_parse_no_space_around_equals() {
    let result = parse("(x=10) => x");
    assert!(
        result.is_ok(),
        "Failed to parse without spaces: {:?}",
        result.err()
    );
}

#[test]
fn test_parse_variable_reference_as_default() {
    // Note: This parses successfully, but the variable lookup happens at call time
    let result = parse("(x = someVar) => x");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}

#[test]
fn test_parse_function_call_as_default() {
    let result = parse("(x = getValue()) => x");
    assert!(result.is_ok(), "Failed to parse: {:?}", result.err());
}
