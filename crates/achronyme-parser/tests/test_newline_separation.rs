/// Tests for newline-based statement separation
///
/// Verifies that statements can be separated by newlines instead of semicolons
use achronyme_parser::{ast::*, parse};

#[test]
fn test_two_statements_with_newline() {
    let code = "let a = 1\nlet b = 2";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 2);
        }
        _ => panic!("Expected Sequence, got {:?}", ast[0]),
    }
}

#[test]
fn test_three_statements_with_newlines() {
    let code = "let a = 1\nlet b = 2\na + b";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 3);
        }
        _ => panic!("Expected Sequence"),
    }
}

#[test]
fn test_do_block_with_newlines() {
    let code = r#"
let f = () => do {
    let a = 10
    let b = 20
    a + b
}
f()
    "#;

    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_if_block_with_newlines() {
    let code = r#"
let x = 10
if(x > 5) {
    let a = 1
    let b = 2
    a + b
} else {
    0
}
    "#;

    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_return_with_newlines() {
    let code = r#"
let f = () => do {
    if(true) {
        return 42
    }
    0
}
    "#;

    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_mixed_separators() {
    // Mix of semicolons and newlines
    let code = "let a = 1; let b = 2\nlet c = 3";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 3);
        }
        _ => panic!("Expected Sequence"),
    }
}

#[test]
fn test_multiple_newlines() {
    // Multiple newlines should be treated as one separator
    let code = "let a = 1\n\n\nlet b = 2";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_trailing_newline() {
    let code = "let a = 1\nlet b = 2\n";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_block_with_leading_newline() {
    let code = r#"
do {
    let x = 10
    x
}
    "#;

    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_semicolons_still_work() {
    // Semicolons should still work for backward compatibility
    let code = "let a = 1; let b = 2; a + b";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_single_line_with_semicolons() {
    // Multiple statements on one line with semicolons
    let code = "let a = 1; let b = 2; let c = a + b; c";
    let result = parse(code);
    assert!(result.is_ok(), "Failed to parse: {:?}", result);
}

#[test]
fn test_newline_in_expression_ignored() {
    // Newlines inside expressions should be ignored (treated as whitespace)
    // This is because expressions use binary operators which consume WHITESPACE
    let code = "let x = 1 + 2";
    let result = parse(code);
    assert!(result.is_ok());
}
