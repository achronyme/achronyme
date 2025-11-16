// Final verification of the root cause

use achronyme_parser::{pest_parser, ast::AstNode};

fn parse_ast(source: &str) -> Result<Vec<AstNode>, String> {
    pest_parser::parse(source)
}

#[test]
fn verify_lambda_parsing() {
    // This should parse as: a == (b => "result")
    // i.e., comparing 'a' to a lambda function that takes 'b' and returns "result"
    let source = r#"a == b => "result""#;
    let ast = parse_ast(source).expect("Should parse");

    // The AST should show a Binary comparison operation
    println!("AST for 'a == b => \"result\"':");
    println!("{:#?}", ast);

    // Verify it's a comparison (==) of 'a' to a lambda
    match &ast[0] {
        AstNode::BinaryOp { .. } => {
            println!("Confirmed: It's a comparison operation");
        }
        _ => panic!("Expected Binary comparison, got: {:?}", ast[0])
    }
}

#[test]
fn verify_guard_consumes_arrow() {
    // When this fails, it's because the guard expr consumed "b => result"
    let source = r#"match 1 { a if a == b => "result" }"#;
    let err = parse_ast(source).unwrap_err();

    // The error should be about missing match arm body
    // because the guard consumed the => as part of a lambda
    assert!(err.contains("expected") && err.contains("op"),
            "Error indicates parser consumed => into guard expression: {}", err);
}

#[test]
fn verify_fix_with_parens() {
    // Parentheses prevent lambda parsing
    let source = r#"match 1 { a if (a == b) => "result" }"#;
    let ast = parse_ast(source).expect("Should parse with parens");

    println!("AST with parenthesized guard:");
    println!("{:#?}", ast);
}

#[test]
fn verify_why_literals_work() {
    // When RHS is a literal, "5 => ..." is NOT a valid lambda
    // because lambda requires identifier parameter, not a literal
    let source = r#"5 => "result""#;
    let result = parse_ast(source);

    // This should fail because 5 is not a valid lambda parameter
    if result.is_err() {
        println!("5 => 'result' fails: {}", result.unwrap_err());
        println!("This is why guards with literal RHS work!");
    } else {
        panic!("Unexpectedly parsed number as lambda parameter");
    }
}
