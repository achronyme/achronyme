use super::helpers::execute;
use crate::value::Value;

// ===== Phase 4 Tests: Pattern Matching & Destructuring =====

#[test]
fn test_vector_destructuring_basic() {
    let source = r#"
        let v = [10, 20]
        let [x, y] = v
        x + y
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_vector_destructuring_three_elements() {
    let source = r#"
        let arr = [1, 2, 3]
        let [a, b, c] = arr
        a + b + c
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(6.0));
}

#[test]
fn test_vector_destructuring_nested() {
    let source = r#"
        let v = [[1, 2], [3, 4]]
        let [first, second] = v
        first[0] + second[1]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_record_destructuring_basic() {
    let source = r#"
        let r = {a: 1, b: 2}
        let {a, b} = r
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_record_destructuring_three_fields() {
    // Note: For now we'll use numbers since strings aren't fully implemented in VM
    let source = r#"
        let obj = {x: 10, y: 20, z: 30}
        let {x, z} = obj
        x + z
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(40.0));
}

#[test]
fn test_record_destructuring_nested() {
    let source = r#"
        let data = {outer: {inner: 42}}
        let {outer} = data
        outer.inner
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_destructuring_wildcard() {
    let source = r#"
        let v = [1, 2, 3]
        let [x, _, z] = v
        x + z
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(4.0));
}

// ===== Phase 4B Tests: Match Expressions with Guards =====

#[test]
fn test_match_literal_basic() {
    let source = r#"
        match 5 {
            5 => true,
            _ => false
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_match_literal_multiple_cases() {
    let source = r#"
        let x = 2
        match x {
            1 => 10,
            2 => 20,
            3 => 30,
            _ => 0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(20.0));
}

#[test]
fn test_match_wildcard() {
    let source = r#"
        match 42 {
            1 => 10,
            2 => 20,
            _ => 99
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(99.0));
}

#[test]
fn test_match_variable_binding() {
    let source = r#"
        match 42 {
            x => x * 2
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(84.0));
}

#[test]
fn test_match_with_guard_literal() {
    let source = r#"
        let x = 10
        match x {
            10 if (x > 5) => 100,
            10 => 50,
            _ => 0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(100.0));
}

#[test]
fn test_match_guard_fails() {
    let source = r#"
        let x = 10
        match x {
            10 if (x > 20) => 100,
            10 => 50,
            _ => 0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(50.0));
}

#[test]
fn test_match_variable_with_guard() {
    let source = r#"
        match 15 {
            x if (x > 10) => x * 2,
            x => x
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_match_type_pattern() {
    let source = r#"
        let v = [1, 2, 3]
        match v {
            Vector => 1,
            Number => 2,
            _ => 0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_match_boolean_patterns() {
    let source = r#"
        let b = true
        match b {
            true => 1,
            false => 0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_match_null_pattern() {
    let source = r#"
        let x = null
        match x {
            null => 42,
            _ => 0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

// ===== Phase 4C Tests: Rest Patterns =====

#[test]
fn test_rest_pattern_basic() {
    let source = r#"
        let v = [1, 2, 3, 4, 5]
        let [first, ...rest] = v
        first
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_rest_pattern_length() {
    let source = r#"
        let v = [1, 2, 3, 4, 5]
        let [first, ...rest] = v
        rest[0]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(2.0));
}

#[test]
fn test_rest_pattern_access_elements() {
    let source = r#"
        let v = [10, 20, 30, 40]
        let [a, ...rest] = v
        rest[2]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(40.0));
}

#[test]
fn test_rest_pattern_two_elements() {
    let source = r#"
        let v = [1, 2, 3, 4, 5]
        let [first, second, ...rest] = v
        rest[0]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_rest_pattern_empty() {
    // This should fail because rest would be empty and indexing would be out of bounds
    // But let's first test that rest exists as an empty vector
    let source = r#"
        let v = [1]
        let [a, ...rest] = v
        a
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_rest_pattern_combines_with_operation() {
    let source = r#"
        let numbers = [5, 10, 15, 20]
        let [head, ...tail] = numbers
        head + tail[0]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_rest_pattern_with_three_elements_before() {
    let source = r#"
        let data = [1, 2, 3, 4, 5, 6]
        let [a, b, c, ...rest] = data
        rest[0] + rest[1] + rest[2]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(15.0)); // 4 + 5 + 6
}

// ===== Phase 4D Tests: Default Values =====

#[test]
fn test_vector_default_value_basic() {
    let source = r#"
        let v = [1]
        let [a = 0, b = 0] = v
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(1.0)); // a=1, b=0 (default)
}

#[test]
fn test_vector_default_all_present() {
    let source = r#"
        let v = [10, 20]
        let [a = 0, b = 0] = v
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0)); // Both values present
}

#[test]
fn test_vector_default_all_missing() {
    let source = r#"
        let v = []
        let [a = 5, b = 10] = v
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(15.0)); // Both defaults used
}

#[test]
fn test_vector_default_mixed() {
    let source = r#"
        let v = [100]
        let [a = 1, b = 2, c = 3] = v
        a + b + c
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(105.0)); // 100 + 2 + 3
}

#[test]
fn test_vector_default_with_expression() {
    let source = r#"
        let v = [5]
        let [a = 10, b = 20 + 5] = v
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0)); // 5 + 25
}

#[test]
fn test_record_default_value_basic() {
    let source = r#"
        let r = {a: 10}
        let {a = 0, b = 0} = r
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(10.0)); // a=10, b=0 (default)
}

#[test]
fn test_record_default_all_present() {
    let source = r#"
        let r = {x: 5, y: 15}
        let {x = 0, y = 0} = r
        x + y
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(20.0)); // Both values present
}

#[test]
fn test_record_default_all_missing() {
    let source = r#"
        let r = {}
        let {a = 100, b = 200} = r
        a + b
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(300.0)); // Both defaults used
}

#[test]
fn test_record_default_with_expression() {
    // Note: 'other' default uses 'value' from outer scope
    let source = r#"
        let r = {x: 10}
        let {x = 0, y = 5 * 2} = r
        x + y
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(20.0)); // 10 + 10
}

// ===== Type Patterns in Record Destructuring =====

#[test]
fn test_record_type_pattern_matching() {
    // Type pattern should check type and bind field name to value
    let source = r#"
        let {x: Number, y} = {x: 10, y: 20}
        x + y
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_record_type_pattern_mismatch() {
    // Type pattern should throw error when type doesn't match
    let source = r#"
        let {x: Number, y} = {x: "String", y: 20}
        x
    "#;
    let result = execute(source);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Type mismatch"));
}

#[test]
fn test_record_type_pattern_multiple() {
    // Multiple type patterns in same record
    let source = r#"
        let {x: Number, y: String} = {x: 42, y: "hello"}
        y
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("hello".to_string()));
}

#[test]
fn test_record_wildcard_pattern() {
    // Wildcard pattern should bind field name to value
    let source = r#"
        let {x: _, y: Number} = {x: "anything", y: 42}
        x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("anything".to_string()));
}

#[test]
fn test_record_type_pattern_with_variable() {
    // Mix of type pattern and variable pattern
    let source = r#"
        let {x: Number, y: z} = {x: 10, y: 20}
        x + z
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0));
}
