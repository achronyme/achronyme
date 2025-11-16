use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

fn eval(source: &str) -> Result<Value, String> {
    let mut evaluator = Evaluator::new();
    evaluator.eval_str(source)
}

// ==================== Record Destructuring Tests ====================

#[test]
fn test_simple_record_destructuring() {
    let result = eval(r#"
        let person = { name: "Alice", age: 30 }
        let { name, age } = person
        name
    "#).unwrap();
    assert_eq!(result, Value::String("Alice".to_string()));
}

#[test]
fn test_record_destructuring_multiple_vars() {
    let result = eval(r#"
        let point = { x: 10, y: 20 }
        let { x, y } = point
        x + y
    "#).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_record_destructuring_with_renaming() {
    let result = eval(r#"
        let data = { name: "Bob", age: 25 }
        let { name: n, age: a } = data
        n
    "#).unwrap();
    assert_eq!(result, Value::String("Bob".to_string()));
}

#[test]
fn test_record_destructuring_partial() {
    // Only destructure some fields from a larger record
    let result = eval(r#"
        let record = { x: 1, y: 2, z: 3 }
        let { x } = record
        x
    "#).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_record_destructuring_nested() {
    let result = eval(r#"
        let data = { user: { name: "Charlie", level: 5 } }
        let { user: { name: n } } = data
        n
    "#).unwrap();
    assert_eq!(result, Value::String("Charlie".to_string()));
}

#[test]
fn test_record_destructuring_deeply_nested() {
    let result = eval(r#"
        let data = { result: { value: 42, status: "ok" } }
        let { result: { value: v } } = data
        v
    "#).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

// ==================== Vector Destructuring Tests ====================

#[test]
fn test_simple_vector_destructuring() {
    let result = eval(r#"
        let coords = [10, 20, 30]
        let [x, y, z] = coords
        x
    "#).unwrap();
    assert_eq!(result, Value::Number(10.0));
}

#[test]
fn test_vector_destructuring_multiple_vars() {
    let result = eval(r#"
        let values = [1, 2, 3]
        let [a, b, c] = values
        a + b + c
    "#).unwrap();
    assert_eq!(result, Value::Number(6.0));
}

#[test]
fn test_vector_destructuring_with_rest() {
    let result = eval(r#"
        let list = [1, 2, 3, 4, 5]
        let [head, ...tail] = list
        head
    "#).unwrap();
    assert_eq!(result, Value::Number(1.0));
}

#[test]
fn test_vector_destructuring_rest_is_array() {
    let result = eval(r#"
        let list = [1, 2, 3, 4, 5]
        let [head, ...tail] = list
        len(tail)
    "#).unwrap();
    assert_eq!(result, Value::Number(4.0));
}

#[test]
fn test_vector_destructuring_rest_elements() {
    let result = eval(r#"
        let list = [1, 2, 3, 4, 5]
        let [head, ...tail] = list
        tail[0]
    "#).unwrap();
    assert_eq!(result, Value::Number(2.0));
}

#[test]
fn test_vector_destructuring_with_wildcard() {
    let result = eval(r#"
        let triple = [1, 2, 3]
        let [first, _, third] = triple
        first + third
    "#).unwrap();
    assert_eq!(result, Value::Number(4.0));
}

#[test]
fn test_vector_destructuring_empty_rest() {
    let result = eval(r#"
        let list = [1, 2]
        let [a, b, ...rest] = list
        len(rest)
    "#).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_vector_destructuring_nested_patterns() {
    let result = eval(r#"
        let data = [{ value: 10 }, { value: 20 }]
        let [{ value: first }, _] = data
        first
    "#).unwrap();
    assert_eq!(result, Value::Number(10.0));
}

// ==================== Mutable Destructuring Tests ====================

#[test]
fn test_mutable_record_destructuring() {
    let result = eval(r#"
        let point = { x: 10, y: 20 }
        mut { x, y } = point
        x = x + 5
        x
    "#).unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_mutable_vector_destructuring() {
    let result = eval(r#"
        let coords = [1, 2, 3]
        mut [a, b, c] = coords
        a = a * 10
        a
    "#).unwrap();
    assert_eq!(result, Value::Number(10.0));
}

// ==================== Error Cases ====================

#[test]
fn test_record_destructuring_missing_field() {
    let result = eval(r#"
        let data = { x: 1 }
        let { x, y } = data
        x
    "#);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not match"));
}

#[test]
fn test_vector_destructuring_too_few_elements() {
    let result = eval(r#"
        let arr = [1, 2]
        let [a, b, c] = arr
        a
    "#);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not match"));
}

#[test]
fn test_vector_destructuring_too_many_elements() {
    let result = eval(r#"
        let arr = [1, 2, 3, 4]
        let [a, b] = arr
        a
    "#);
    // Without rest pattern, vector length must match exactly
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not match"));
}

#[test]
fn test_record_destructuring_type_mismatch() {
    let result = eval(r#"
        let value = 42
        let { x } = value
        x
    "#);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not match"));
}

#[test]
fn test_vector_destructuring_type_mismatch() {
    let result = eval(r#"
        let value = { x: 1 }
        let [a] = value
        a
    "#);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not match"));
}

// ==================== Complex Use Cases ====================

#[test]
fn test_destructuring_in_do_block() {
    let result = eval(r#"
        let processPoint = (point) => do {
            let { x, y } = point
            sqrt(x^2 + y^2)
        }
        processPoint({ x: 3, y: 4 })
    "#).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_destructuring_function_return() {
    let result = eval(r#"
        let getPoint = () => { x: 100, y: 200 }
        let { x, y } = getPoint()
        x + y
    "#).unwrap();
    assert_eq!(result, Value::Number(300.0));
}

#[test]
fn test_destructuring_computed_value() {
    let result = eval(r#"
        let makeTriple = (a) => [a, a*2, a*3]
        let [first, second, third] = makeTriple(5)
        first + second + third
    "#).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_multiple_destructuring_statements() {
    let result = eval(r#"
        let person = { name: "Alice", age: 30 }
        let coords = [10, 20]
        let { name } = person
        let [x, y] = coords
        len(name) + x + y
    "#).unwrap();
    assert_eq!(result, Value::Number(35.0));  // 5 + 10 + 20
}

#[test]
fn test_destructuring_in_sequence() {
    let result = eval(r#"
        do {
            let data = { value: 100 }
            let { value: v } = data
            v * 2
        }
    "#).unwrap();
    assert_eq!(result, Value::Number(200.0));
}

#[test]
fn test_destructuring_preserves_original() {
    let result = eval(r#"
        let original = { a: 1, b: 2, c: 3 }
        let { a, b } = original
        original.c
    "#).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

// ==================== Edge Cases ====================

#[test]
fn test_destructuring_empty_record() {
    let result = eval(r#"
        let empty = {}
        let {} = empty
        42
    "#).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_destructuring_empty_vector() {
    let result = eval(r#"
        let empty = []
        let [] = empty
        42
    "#).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_destructuring_with_string_values() {
    let result = eval(r#"
        let data = { greeting: "Hello", target: "World" }
        let { greeting, target } = data
        greeting
    "#).unwrap();
    assert_eq!(result, Value::String("Hello".to_string()));
}

#[test]
fn test_destructuring_with_boolean_values() {
    let result = eval(r#"
        let flags = { enabled: true, debug: false }
        let { enabled, debug } = flags
        enabled
    "#).unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_vector_destructuring_strings() {
    let result = eval(r#"
        let words = ["hello", "world"]
        let [first, second] = words
        len(first)
    "#).unwrap();
    assert_eq!(result, Value::Number(5.0));
}
