// Test the exact parsing behavior of guard clauses

use achronyme_parser::pest_parser;

fn test_parse(source: &str) -> bool {
    pest_parser::parse(source).is_ok()
}

#[test]
fn test_two_field_record_with_gte_guard() {
    // Working case from existing tests (uses >=)
    let source = r#"
match { name: "Alice", age: 30 } {
    { name: n, age: a } if a >= 18 => n,
    _ => "minor"
}
"#;
    assert!(test_parse(source), "Two-field record with >= guard should parse");
}

#[test]
fn test_two_field_record_with_eq_guard_string_result() {
    // FAILING case (uses ==) with string result
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if a == b => "same",
    _ => "diff"
}
"#;
    assert!(test_parse(source), "Two-field record with == guard and string result should parse");
}

#[test]
fn test_single_field_record_with_eq_guard() {
    let source = r#"
match { x: 4 } {
    { x: a } if a == 4 => "four",
    _ => "other"
}
"#;
    assert!(test_parse(source), "Single-field record with == guard should parse");
}

#[test]
fn test_two_field_record_with_ne_guard() {
    let source = r#"
match { x: 4, y: 5 } {
    { x: a, y: b } if a != b => "different",
    _ => "same"
}
"#;
    assert!(test_parse(source), "Two-field record with != guard should parse");
}

#[test]
fn test_two_field_record_with_gt_guard() {
    let source = r#"
match { x: 4, y: 5 } {
    { x: a, y: b } if a > b => "a bigger",
    _ => "b bigger or equal"
}
"#;
    assert!(test_parse(source), "Two-field record with > guard should parse");
}

#[test]
fn test_two_field_record_with_lt_guard() {
    let source = r#"
match { x: 4, y: 5 } {
    { x: a, y: b } if a < b => "a smaller",
    _ => "a bigger or equal"
}
"#;
    assert!(test_parse(source), "Two-field record with < guard should parse");
}

#[test]
fn test_two_field_record_with_lte_guard() {
    let source = r#"
match { x: 4, y: 5 } {
    { x: a, y: b } if a <= b => "a smaller or equal",
    _ => "a bigger"
}
"#;
    assert!(test_parse(source), "Two-field record with <= guard should parse");
}

#[test]
fn test_variable_with_eq_guard() {
    let source = r#"
match 5 {
    n if n == 5 => "five",
    _ => "not five"
}
"#;
    assert!(test_parse(source), "Variable with == guard should parse");
}

#[test]
fn test_two_field_eq_guard_numeric_result() {
    // Without string in result (numeric result)
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if a == b => 1,
    _ => 0
}
"#;
    assert!(test_parse(source), "Two-field == guard with numeric result should parse");
}

#[test]
fn test_two_field_eq_guard_no_trailing_comma() {
    // Without comma after arm
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if a == b => "same"
}
"#;
    assert!(test_parse(source), "Two-field == guard without trailing comma should parse");
}

#[test]
fn test_get_error_message() {
    // Let's capture the exact error message for the failing case
    let source = r#"
match { x: 4, y: 4 } {
    { x: a, y: b } if a == b => "same",
    _ => "diff"
}
"#;
    let result = pest_parser::parse(source);
    if let Err(e) = result {
        println!("Error message for failing case:\n{}", e);
        panic!("Parse failed with: {}", e);
    }
}
