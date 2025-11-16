// Test guard clause parsing - deeper analysis

use achronyme_parser::pest_parser;

fn parse_ok(source: &str) -> bool {
    pest_parser::parse(source).is_ok()
}

fn parse_err(source: &str) -> String {
    match pest_parser::parse(source) {
        Ok(_) => String::new(),
        Err(e) => e.to_string()
    }
}

#[test]
fn test_two_field_eq_with_literal() {
    // Two fields, comparing to literal
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if a == 4 => "four",
    _ => "other"
}
"#;
    assert!(parse_ok(source), "Two-field, guard compares a to literal 4");
}

#[test]
fn test_two_field_eq_with_two_vars() {
    // Two fields, comparing two bound variables
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if a == b => "same",
    _ => "diff"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Two-field, guard compares a to b");
}

#[test]
fn test_two_field_gte_with_literal() {
    // This is the working test case
    let source = r#"
match { name: "Alice", age: 30 } {
    { name: n, age: a } if a >= 18 => n,
    _ => "minor"
}
"#;
    assert!(parse_ok(source), "Two-field, guard compares a to literal 18");
}

#[test]
fn test_two_field_gte_with_two_vars() {
    // Two fields, comparing two bound variables with >=
    let source = r#"
match { x: 4, y: 3 } {
    { x: a, y: b } if a >= b => "a is bigger or equal",
    _ => "b is bigger"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Two-field, guard compares a >= b");
}

#[test]
fn test_single_field_eq_with_var() {
    // Single field, comparing to itself (degenerate case)
    let source = r#"
match { x: 4 } {
    { x: a } if a == a => "always",
    _ => "never"
}
"#;
    assert!(parse_ok(source), "Single-field, guard compares a == a");
}

#[test]
fn test_parenthesized_guard_condition() {
    // Try wrapping the guard condition in parentheses
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if (a == b) => "same",
    _ => "diff"
}
"#;
    if !parse_ok(source) {
        println!("Error with parens: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Parenthesized guard condition");
}

#[test]
fn test_different_field_names() {
    // Different field names, but still two fields
    let source = r#"
match { foo: 1, bar: 2 } {
    { foo: x, bar: y } if x == y => "equal",
    _ => "not equal"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Two-field with different names, guard compares x to y");
}

#[test]
fn test_three_field_record_pattern() {
    let source = r#"
match { a: 1, b: 2, c: 3 } {
    { a: x, b: y, c: z } if x == y => "x equals y",
    _ => "other"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Three-field record pattern with guard");
}

#[test]
fn test_record_pattern_simple_no_guard() {
    // Two fields, no guard - should always work
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } => a + b,
    _ => 0
}
"#;
    assert!(parse_ok(source), "Two-field without guard");
}

#[test]
fn test_simple_guard_expression() {
    // Is the problem in how we parse the guard expression itself?
    // Try the guard expression in a different context
    let source = r#"
let result = if (true) { a == b } else { false }
"#;
    assert!(parse_ok(source), "a == b as standalone expression");
}
