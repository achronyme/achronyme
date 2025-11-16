// Pinpointing the exact issue

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
fn test_expr_with_arrow() {
    // Is "a == b => something" a valid expression?
    let source = r#"a == b => "result""#;
    if parse_ok(source) {
        println!("'a == b => result' is valid!");
    } else {
        println!("'a == b => result' is NOT valid: {}", parse_err(source));
    }
}

#[test]
fn test_plain_identifier_arrow() {
    // Plain identifier arrow (lambda)
    let source = r#"b => "result""#;
    assert!(parse_ok(source), "Lambda expression");
}

#[test]
fn test_number_after_comparison() {
    // When RHS of comparison is a number, no lambda possible
    let source = r#"
match 1 {
    a if a == 5 => "result"
}
"#;
    assert!(parse_ok(source), "Guard with number literal");
}

#[test]
fn test_string_after_comparison() {
    // When RHS of comparison is a string
    let source = r#"
match "x" {
    s if s == "y" => "result"
}
"#;
    assert!(parse_ok(source), "Guard with string literal");
}

#[test]
fn test_identifier_after_comparison_single_pattern() {
    // When RHS of comparison is an identifier
    let source = r#"
match 1 {
    a if a == b => "result"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Guard comparing identifier to identifier");
}

#[test]
fn test_guard_with_arrow_lookahead() {
    // The key: what happens after the guard expression?
    // After "if expr", we expect "=>" for the match arm arrow
    // But the expr parser is consuming "=> result" as part of the expression!

    // Hypothesis: The grammar sees "a if b => c" and parses:
    // - pattern: a
    // - guard starts: if
    // - expr: tries to parse "b => c" as a lambda expression
    // - And it SUCCEEDS because b => c IS a valid lambda!

    let source = r#"b => c"#;
    assert!(parse_ok(source), "b => c is a valid lambda");
}

#[test]
fn test_guard_expr_consumes_arrow() {
    // The guard clause's expr is consuming the match arm's =>
    let source = r#"
match 1 {
    x if y => z
}
"#;
    // This FAILS because:
    // - pattern: x
    // - guard: if
    // - expr: tries to parse "y => z" as a lambda
    // - But then there's no => for the match arm!
    if !parse_ok(source) {
        println!("Parse error: {}", parse_err(source));
    }
}

#[test]
fn test_guard_expr_with_comparison_to_var() {
    // The real issue: when comparing variables
    let source = r#"
match { x: 1, y: 2 } {
    { x: a, y: b } if a == b => "equal"
}
"#;
    // This FAILS because:
    // - pattern: { x: a, y: b }
    // - guard: if
    // - expr: starts parsing "a == b"
    // - Then sees "=>" and thinks maybe "b => ..." is part of the expression?
    // - But wait, "a == (b => ...)" would be nonsense... let's see
    if !parse_ok(source) {
        println!("Two-var comparison error: {}", parse_err(source));
    }
}

#[test]
fn test_weird_parse() {
    // Can we parse "a == b => c" as an expression where b => c is a lambda?
    // This would be "a == (b => c)" - comparing a to a lambda function
    let source = r#"a == b => c"#;
    if parse_ok(source) {
        println!("'a == b => c' parses as: a == (b => c)");
    } else {
        println!("'a == b => c' does NOT parse: {}", parse_err(source));
    }
}

#[test]
fn test_explicit_lambda() {
    // Explicit lambda comparison
    let source = r#"a == (b => c)"#;
    assert!(parse_ok(source), "Explicit: a == (b => c)");
}
