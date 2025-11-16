// Test for lambda ambiguity issue

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
fn test_guard_with_identifier() {
    // Guard with single identifier (no operator)
    let source = r#"
match x {
    n if n => "truthy",
    _ => "falsy"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Guard with single identifier");
}

#[test]
fn test_guard_with_identifier_expr() {
    // Guard is just an identifier - does it try to parse 'n => "truthy"' as a lambda?
    let source = r#"
match true {
    b if b => "yes",
    _ => "no"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Guard with identifier");
}

#[test]
fn test_what_gets_parsed() {
    // Check if "b => something" is valid as an expression (lambda)
    let source = r#"b => "yes""#;
    if parse_ok(source) {
        println!("'b => \"yes\"' parses as a valid expression");
    } else {
        println!("'b => \"yes\"' does NOT parse: {}", parse_err(source));
    }
}

#[test]
fn test_edge_parsing() {
    // Check if => looks like edge operator
    let source = r#"a => b"#;
    if parse_ok(source) {
        println!("'a => b' parses as valid expression");
    } else {
        println!("'a => b' does NOT parse: {}", parse_err(source));
    }
}

#[test]
fn test_guard_minimal_repro() {
    // Most minimal reproduction
    let source = r#"
match 1 {
    a if b => c
}
"#;
    if !parse_ok(source) {
        println!("Minimal repro error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Minimal reproduction case");
}

#[test]
fn test_guard_minimal_repro_with_literal_guard() {
    // Minimal reproduction with literal in guard
    let source = r#"
match 1 {
    a if true => c
}
"#;
    assert!(parse_ok(source), "Minimal with literal guard");
}

#[test]
fn test_guard_minimal_repro_with_parens() {
    // Minimal reproduction with parentheses around guard
    let source = r#"
match 1 {
    a if (b) => c
}
"#;
    assert!(parse_ok(source), "Minimal with parenthesized guard");
}

#[test]
fn test_if_guard_comparison() {
    // Guard with comparison
    let source = r#"
match 1 {
    a if a > 0 => "pos"
}
"#;
    if !parse_ok(source) {
        println!("Error: {}", parse_err(source));
    }
    assert!(parse_ok(source), "Guard with comparison");
}
