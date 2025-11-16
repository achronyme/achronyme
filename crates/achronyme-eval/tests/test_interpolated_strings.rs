use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

/// Helper function to evaluate an expression and return the result
fn eval(expr: &str) -> Result<Value, String> {
    let mut evaluator = Evaluator::new();
    evaluator.eval_str(expr)
}

/// Helper function to assert string equality
fn assert_string_eq(expr: &str, expected: &str) {
    match eval(expr) {
        Ok(Value::String(s)) => assert_eq!(s, expected, "Expression: {}", expr),
        Ok(other) => panic!("Expected String for '{}', got {:?}", expr, other),
        Err(e) => panic!("Error evaluating '{}': {}", expr, e),
    }
}

#[test]
fn test_empty_interpolated_string() {
    // Empty string with single quotes
    assert_string_eq("''", "");
}

#[test]
fn test_plain_interpolated_string() {
    // String without interpolation - just plain text
    assert_string_eq("'Hello, World!'", "Hello, World!");
    // Note: Empty ${} is not valid syntax - requires an expression
    // If you want literal ${}, use escape: \${}
    assert_string_eq(r"'Just a plain string without \${}'", "Just a plain string without ${}");
}

#[test]
fn test_single_variable_interpolation() {
    // Basic variable interpolation
    let code = r#"
        let name = "Alice"
        'Hello, ${name}!'
    "#;
    assert_string_eq(code, "Hello, Alice!");
}

#[test]
fn test_multiple_variable_interpolations() {
    // Multiple interpolations in one string
    let code = r#"
        let x = 10
        let y = 20
        'x=${x}, y=${y}, sum=${x+y}'
    "#;
    assert_string_eq(code, "x=10, y=20, sum=30");
}

#[test]
fn test_number_interpolation() {
    // Integer interpolation
    let code = "'The answer is ${42}'";
    assert_string_eq(code, "The answer is 42");

    // Float interpolation
    let code = r#"
        let pi = 3.14159
        'Pi is approximately ${pi}'
    "#;
    assert_string_eq(code, "Pi is approximately 3.14159");

    // Integer numbers should not have trailing .0
    let code = "'Value: ${100}'";
    assert_string_eq(code, "Value: 100");
}

#[test]
fn test_boolean_interpolation() {
    // Boolean true
    let code = r#"
        let flag = true
        'Flag is ${flag}'
    "#;
    assert_string_eq(code, "Flag is true");

    // Boolean false
    let code = r#"
        let flag = false
        'Flag is ${flag}'
    "#;
    assert_string_eq(code, "Flag is false");
}

#[test]
fn test_null_interpolation() {
    let code = "'Value is ${null}'";
    assert_string_eq(code, "Value is null");
}

#[test]
fn test_expression_interpolation() {
    // Arithmetic expressions
    let code = "'Result: ${2 + 3 * 4}'";
    assert_string_eq(code, "Result: 14");

    // More complex arithmetic
    let code = "'Area: ${10 * 20}'";
    assert_string_eq(code, "Area: 200");

    // Power
    let code = "'2^10 = ${2^10}'";
    assert_string_eq(code, "2^10 = 1024");
}

#[test]
fn test_conditional_expression_interpolation() {
    // If expression with true condition
    let code = r#"
        let x = 5
        'Status: ${if(x > 0) { "positive" } else { "negative" }}'
    "#;
    assert_string_eq(code, "Status: positive");

    // If expression with false condition
    let code = r#"
        let x = -5
        'Status: ${if(x > 0) { "positive" } else { "negative" }}'
    "#;
    assert_string_eq(code, "Status: negative");
}

#[test]
fn test_function_call_interpolation() {
    // Lambda function call
    let code = r#"
        let square = (x) => x * x
        '4 squared is ${square(4)}'
    "#;
    assert_string_eq(code, "4 squared is 16");

    // Built-in function
    let code = "'Max of 3, 7, 2 is ${max(3, 7, 2)}'";
    assert_string_eq(code, "Max of 3, 7, 2 is 7");
}

#[test]
fn test_record_field_interpolation() {
    // Accessing record fields
    let code = r#"
        let point = {x: 10, y: 20}
        'Point: (${point.x}, ${point.y})'
    "#;
    assert_string_eq(code, "Point: (10, 20)");
}

#[test]
fn test_array_interpolation() {
    // Array values are converted to string representation
    let code = "'Array: ${[1, 2, 3]}'";
    assert_string_eq(code, "Array: [1, 2, 3]");
}

#[test]
fn test_record_interpolation() {
    // Records are converted to {key: value} format
    // Note: HashMap order may vary, so we just check it starts and ends correctly
    let code = "'Record: ${{a: 1}}'";
    let result = eval(code).unwrap();
    if let Value::String(s) = result {
        assert!(s.starts_with("Record: {"));
        assert!(s.ends_with("}"));
        assert!(s.contains("a: 1"));
    } else {
        panic!("Expected String value");
    }
}

#[test]
fn test_escape_dollar() {
    // Escaping ${} with \$
    assert_string_eq(r"'Price: \${100}'", "Price: ${100}");
    assert_string_eq(r"'Escaped \${name} not interpolated'", "Escaped ${name} not interpolated");
}

#[test]
fn test_escape_single_quote() {
    // Escaping single quote with \'
    assert_string_eq(r"'It\'s a test'", "It's a test");
}

#[test]
fn test_escape_backslash() {
    // Escaping backslash
    assert_string_eq(r"'Path: C:\\Users'", "Path: C:\\Users");
}

#[test]
fn test_escape_newline_tab() {
    // Newline and tab escapes
    assert_string_eq(r"'Line1\nLine2'", "Line1\nLine2");
    assert_string_eq(r"'Col1\tCol2'", "Col1\tCol2");
    assert_string_eq(r"'Return\rhere'", "Return\rhere");
}

#[test]
fn test_only_interpolation() {
    // String with only interpolation
    assert_string_eq("'${42}'", "42");
    assert_string_eq("'${true}'", "true");
}

#[test]
fn test_double_quotes_no_interpolation() {
    // Double quotes should NOT interpolate
    let code = r#"
        let name = "Alice"
        "Hello, ${name}!"
    "#;
    assert_string_eq(code, "Hello, ${name}!");
}

#[test]
fn test_mixed_quotes() {
    // Test that double and single quotes work together
    let code = r#"
        let greeting = "Hello"
        let name = "World"
        '${greeting}, ${name}!'
    "#;
    assert_string_eq(code, "Hello, World!");
}

#[test]
fn test_nested_expressions() {
    // Complex nested expressions
    let code = r#"
        let a = 2
        let b = 3
        'Result: ${(a + b) * (a - b)}'
    "#;
    assert_string_eq(code, "Result: -5");
}

#[test]
fn test_comparison_in_interpolation() {
    // Boolean result from comparison
    let code = "'Is 5 > 3? ${5 > 3}'";
    assert_string_eq(code, "Is 5 > 3? true");
}

#[test]
fn test_logical_ops_in_interpolation() {
    // Logical operations
    let code = "'Result: ${true && false}'";
    assert_string_eq(code, "Result: false");

    let code = "'Result: ${true || false}'";
    assert_string_eq(code, "Result: true");

    let code = "'Result: ${!false}'";
    assert_string_eq(code, "Result: true");
}

#[test]
fn test_complex_number_interpolation() {
    // Complex numbers
    let code = "'Complex: ${3i}'";
    assert_string_eq(code, "Complex: 3i");

    let code = "'Complex: ${2 + 3i}'";
    let result = eval(code).unwrap();
    if let Value::String(s) = result {
        // Should be "Complex: 2+3i"
        assert!(s.contains("2") && s.contains("3") && s.contains("i"));
    } else {
        panic!("Expected String value");
    }
}

#[test]
fn test_adjacent_interpolations() {
    // Two interpolations next to each other
    let code = "'${1}${2}${3}'";
    assert_string_eq(code, "123");
}

#[test]
fn test_interpolation_at_start_and_end() {
    let code = r#"
        let x = "start"
        let y = "end"
        '${x} middle ${y}'
    "#;
    assert_string_eq(code, "start middle end");
}

#[test]
fn test_deeply_nested_do_block() {
    // Do block inside interpolation
    let code = r#"'Result: ${do { let a = 5; let b = 3; a * b }}'"#;
    assert_string_eq(code, "Result: 15");
}

#[test]
fn test_function_interpolation_type() {
    // Functions should show as <function>
    let code = "'Function: ${(x) => x * 2}'";
    assert_string_eq(code, "Function: <function>");
}

#[test]
fn test_edge_interpolation() {
    // Edge values
    let code = r#"
        let A = "A"
        let B = "B"
        'Edge: ${A -> B}'
    "#;
    assert_string_eq(code, "Edge: A -> B");
}

#[test]
fn test_interpolation_error_propagation() {
    // Error in expression should propagate
    let code = "'Result: ${undefined_var}'";
    let result = eval(code);
    assert!(result.is_err());
}

#[test]
fn test_whitespace_preservation() {
    // Whitespace should be preserved
    assert_string_eq("'  spaces  '", "  spaces  ");
    assert_string_eq("'tabs\there'", "tabs\there");
}

#[test]
fn test_special_characters() {
    // Various special characters (not escape sequences)
    assert_string_eq("'Hello! @#%^&*()[]{}|:;<>,.?'", "Hello! @#%^&*()[]{}|:;<>,.?");
}

#[test]
fn test_unicode_in_interpolated_string() {
    // Unicode characters
    assert_string_eq("'Hello, 世界!'", "Hello, 世界!");
    assert_string_eq("'Emoji: 🚀'", "Emoji: 🚀");
}

#[test]
fn test_multiline_expression_result() {
    // Expression that spans concept (the result is what matters)
    let code = r#"
        let compute = () => do {
            let a = 10
            let b = 20
            a + b
        }
        'Computed: ${compute()}'
    "#;
    assert_string_eq(code, "Computed: 30");
}

#[test]
fn test_ternary_style_if() {
    // Ternary-like if in interpolation
    let code = r#"
        let age = 25
        'You are ${if(age >= 18) { "adult" } else { "minor" }}'
    "#;
    assert_string_eq(code, "You are adult");
}

#[test]
fn test_string_concatenation_vs_interpolation() {
    // Comparing traditional concat with interpolation
    let code = r#"
        let name = "Bob"
        let traditional = "Hello, " + name + "!"
        let interpolated = 'Hello, ${name}!'
        traditional == interpolated
    "#;
    let result = eval(code).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_interpolated_string_as_function_arg() {
    // Using interpolated string as argument
    let code = r#"
        let x = 10
        length('Value: ${x}')
    "#;
    let result = eval(code).unwrap();
    // "Value: 10" should be 10 characters, but "Value:" is 6 + "10" is 2 = 8
    // Wait, let me recalculate: V-a-l-u-e-:-space = 7 chars, then "10" = 2 chars = 9 total
    assert_eq!(result, Value::Number(9.0)); // "Value: 10" is 9 chars (V a l u e : space 1 0)
}

#[test]
fn test_record_method_in_interpolation() {
    // Record method call
    let code = r#"
        let obj = {
            value: 42,
            describe: () => 'The value is ${self.value}'
        }
        obj.describe()
    "#;
    assert_string_eq(code, "The value is 42");
}

#[test]
fn test_very_long_interpolated_string() {
    // Long string with many interpolations
    let code = r#"
        let a = 1
        let b = 2
        let c = 3
        let d = 4
        let e = 5
        '${a}-${b}-${c}-${d}-${e}-${a+b}-${b+c}-${c+d}-${d+e}'
    "#;
    assert_string_eq(code, "1-2-3-4-5-3-5-7-9");
}
