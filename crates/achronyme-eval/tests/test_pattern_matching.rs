use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

fn eval(source: &str) -> Result<Value, String> {
    let mut evaluator = Evaluator::new();
    evaluator.eval_str(source)
}

#[test]
fn test_match_literal_number() {
    let result = eval(r#"
        let x = 42
        match x {
            0 => "zero",
            42 => "answer",
            _ => "other"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("answer".to_string()));
}

#[test]
fn test_match_literal_string() {
    let result = eval(r#"
        let s = "hello"
        match s {
            "world" => 1,
            "hello" => 2,
            _ => 3
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(2.0));
}

#[test]
fn test_match_literal_boolean() {
    let result = eval(r#"
        let flag = true
        match flag {
            false => "no",
            true => "yes"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("yes".to_string()));
}

#[test]
fn test_match_wildcard() {
    let result = eval(r#"
        let x = 999
        match x {
            1 => "one",
            2 => "two",
            _ => "many"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("many".to_string()));
}

#[test]
fn test_match_variable_binding() {
    let result = eval(r#"
        let x = 10
        match x {
            n => n * 2
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(20.0));
}

#[test]
fn test_match_with_guard() {
    let result = eval(r#"
        let x = 15
        match x {
            n if (n > 10) => "big",
            n if (n > 5) => "medium",
            _ => "small"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("big".to_string()));
}

#[test]
fn test_match_guard_fails_try_next() {
    let result = eval(r#"
        let x = 7
        match x {
            n if (n > 10) => "big",
            n if (n > 5) => "medium",
            _ => "small"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("medium".to_string()));
}

#[test]
fn test_match_type_pattern_number() {
    let result = eval(r#"
        let x = 42
        match x {
            String => "string",
            Boolean => "boolean",
            Number => "number"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("number".to_string()));
}

#[test]
fn test_match_type_pattern_string() {
    let result = eval(r#"
        let x = "hello"
        match x {
            Number => "number",
            String => "string",
            _ => "other"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("string".to_string()));
}

#[test]
fn test_match_type_pattern_boolean() {
    let result = eval(r#"
        let x = true
        match x {
            Number => "number",
            String => "string",
            Boolean => "boolean"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("boolean".to_string()));
}

#[test]
fn test_match_type_pattern_vector() {
    let result = eval(r#"
        let x = [1, 2, 3]
        match x {
            Number => "number",
            Vector => "vector",
            _ => "other"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("vector".to_string()));
}

#[test]
fn test_match_type_pattern_null() {
    let result = eval(r#"
        let x = null
        match x {
            Number => "number",
            Null => "null",
            _ => "other"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("null".to_string()));
}

#[test]
fn test_match_record_destructuring() {
    let result = eval(r#"
        let person = { name: "Alice", age: 30 }
        match person {
            { name: n, age: a } => n
        }
    "#).unwrap();
    assert_eq!(result, Value::String("Alice".to_string()));
}

#[test]
fn test_match_record_partial_match() {
    let result = eval(r#"
        let person = { name: "Bob", age: 25, city: "Paris" }
        match person {
            { name: n } => n
        }
    "#).unwrap();
    assert_eq!(result, Value::String("Bob".to_string()));
}

#[test]
fn test_match_record_shorthand() {
    let result = eval(r#"
        let obj = { value: 100, label: "test" }
        match obj {
            { value } => value * 2
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(200.0));
}

#[test]
fn test_match_record_nested() {
    let result = eval(r#"
        let data = { user: { name: "Charlie", active: true } }
        match data {
            { user: { name: n, active: true } } => n,
            { user: { name: n, active: false } } => "inactive",
            _ => "unknown"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("Charlie".to_string()));
}

#[test]
fn test_match_vector_empty() {
    let result = eval(r#"
        let list = []
        match list {
            [] => "empty",
            _ => "not empty"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("empty".to_string()));
}

#[test]
fn test_match_vector_single() {
    let result = eval(r#"
        let list = [42]
        match list {
            [] => "empty",
            [x] => x * 10,
            _ => 0
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(420.0));
}

#[test]
fn test_match_vector_pair() {
    let result = eval(r#"
        let list = [3, 4]
        match list {
            [] => 0,
            [x] => x,
            [x, y] => x + y,
            _ => -1
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(7.0));
}

#[test]
fn test_match_vector_with_rest() {
    let result = eval(r#"
        let list = [1, 2, 3, 4, 5]
        match list {
            [] => "empty",
            [head, ...tail] => head
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_match_vector_rest_captures_remaining() {
    let result = eval(r#"
        let list = [1, 2, 3, 4, 5]
        match list {
            [head, ...tail] => len(tail)
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(4.0));
}

#[test]
fn test_match_vector_multiple_patterns_with_rest() {
    let result = eval(r#"
        let list = [10, 20, 30]
        match list {
            [a, b, ...rest] => a + b
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_match_in_function() {
    let result = eval(r#"
        let describe = x => match x {
            0 => "zero",
            n if (n > 0) => "positive",
            _ => "negative"
        }
        describe(-5)
    "#).unwrap();
    assert_eq!(result, Value::String("negative".to_string()));
}

#[test]
fn test_match_expression_returns_value() {
    let result = eval(r#"
        let x = 3
        let result = match x {
            1 => 100,
            2 => 200,
            3 => 300,
            _ => 0
        }
        result
    "#).unwrap();
    assert_eq!(result, Value::Number(300.0));
}

#[test]
fn test_match_no_pattern_matches_error() {
    let result = eval(r#"
        let x = 5
        match x {
            1 => "one",
            2 => "two"
        }
    "#);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("no pattern matched"));
}

#[test]
fn test_match_first_match_wins() {
    let result = eval(r#"
        let x = 10
        match x {
            n if (n > 5) => "first",
            n if (n > 8) => "second",
            _ => "third"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("first".to_string()));
}

#[test]
fn test_match_with_arithmetic_in_guard() {
    let result = eval(r#"
        let x = 6
        match x {
            n if (n % 2 == 0) => "even",
            _ => "odd"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("even".to_string()));
}

#[test]
fn test_match_complex_record_with_guard() {
    let result = eval(r#"
        let person = { name: "David", age: 20 }
        match person {
            { name: n, age: a } if (a >= 18) => n,
            { name: n } => "minor: " + n,
            _ => "unknown"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("David".to_string()));
}

#[test]
fn test_match_multiline_syntax() {
    let result = eval(r#"
        let x = 2
        match x {
            1 =>
                "one",
            2 =>
                "two",
            _ =>
                "other"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("two".to_string()));
}

#[test]
fn test_match_with_record_type() {
    let result = eval(r#"
        let obj = { a: 1, b: 2 }
        match obj {
            Record => "is record",
            _ => "not record"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("is record".to_string()));
}

#[test]
fn test_match_nested_vector_pattern() {
    let result = eval(r#"
        let data = [1, [2, 3], 4]
        match data {
            [a, [b, c], d] => b + c,
            _ => 0
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_match_error_value() {
    let result = eval(r#"
        let err = { message: "Something went wrong", kind: "RuntimeError" }
        match err {
            { message: m, kind: k } => k + ": " + m,
            _ => "unknown error"
        }
    "#).unwrap();
    assert_eq!(result, Value::String("RuntimeError: Something went wrong".to_string()));
}

#[test]
fn test_match_trailing_comma() {
    let result = eval(r#"
        let x = 1
        match x {
            0 => "zero",
            1 => "one",
            _ => "other",
        }
    "#).unwrap();
    assert_eq!(result, Value::String("one".to_string()));
}

#[test]
fn test_match_vector_rest_empty() {
    let result = eval(r#"
        let list = [1]
        match list {
            [head, ...tail] => len(tail)
        }
    "#).unwrap();
    // tail should be empty vector with length 0
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_match_combining_all_features() {
    // Complex test combining multiple pattern matching features
    // Note: "type" is a keyword in Achronyme, so we use "status" instead
    let result = eval(r#"
        let processData = data => match data {
            { status: "success", value: v } if (v > 100) => "big success: " + str(v),
            { status: "success", value: v } => "success: " + str(v),
            { status: "error", message: m } => "error: " + m,
            [head, ...tail] if (len(tail) > 2) => "long list",
            [x] => "single item: " + str(x),
            [] => "empty",
            Number => "just a number",
            _ => "unknown"
        }

        processData({ status: "success", value: 150 })
    "#).unwrap();
    assert_eq!(result, Value::String("big success: 150".to_string()));
}
