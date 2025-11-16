//! Type Alias Tests

use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

#[test]
fn test_simple_type_alias() {
    let mut eval = Evaluator::new();
    // Define a simple type alias
    let result = eval.eval_str(r#"
        type Num = Number
        let x: Num = 42
        x
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

#[test]
fn test_record_type_alias() {
    let mut eval = Evaluator::new();
    // Define a record type alias
    let result = eval.eval_str(r#"
        type Point = { x: Number, y: Number }
        let p: Point = { x: 10, y: 20 }
        p.x + p.y
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(30.0));
}

#[test]
fn test_union_type_alias() {
    let mut eval = Evaluator::new();
    // Define a union type alias
    let result = eval.eval_str(r#"
        type OptionalNumber = Number | null
        let x: OptionalNumber = 100
        let y: OptionalNumber = null
        x
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(100.0));
}

#[test]
fn test_function_type_alias() {
    let mut eval = Evaluator::new();
    // Define a function type alias
    let result = eval.eval_str(r#"
        type BinaryOp = (Number, Number): Number
        let add: BinaryOp = (a, b) => a + b
        add(5, 3)
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(8.0));
}

#[test]
fn test_type_alias_error_checking() {
    let mut eval = Evaluator::new();
    // Type alias should still enforce type checking
    let result = eval.eval_str(r#"
        type Num = Number
        let x: Num = "not a number"
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Type error"));
}

#[test]
fn test_nested_type_alias() {
    let mut eval = Evaluator::new();
    // Define nested type aliases
    let result = eval.eval_str(r#"
        type ID = Number
        type Person = { id: ID, name: String }
        let john: Person = { id: 1, name: "John" }
        john.id
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(1.0));
}

#[test]
fn test_mutable_with_type_alias() {
    let mut eval = Evaluator::new();
    // Mutable variables with type aliases
    let result = eval.eval_str(r#"
        type Counter = Number
        mut count: Counter = 0
        count = 10
        count
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(10.0));
}

#[test]
fn test_mutable_type_alias_enforcement() {
    let mut eval = Evaluator::new();
    // Type alias should be enforced on assignment
    let result = eval.eval_str(r#"
        type Num = Number
        mut x: Num = 10
        x = "wrong type"
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Type error"));
}

#[test]
fn test_complex_record_type_alias() {
    let mut eval = Evaluator::new();
    // More complex record with type alias
    let result = eval.eval_str(r#"
        type Config = {
            debug: Boolean,
            maxRetries: Number,
            name: String
        }
        let config: Config = {
            debug: true,
            maxRetries: 3,
            name: "App"
        }
        config.maxRetries
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(3.0));
}

#[test]
fn test_type_alias_with_tensor() {
    let mut eval = Evaluator::new();
    // Type alias for tensor type
    let result = eval.eval_str(r#"
        type Matrix = Tensor<Number>
        let m: Matrix = [[1, 2], [3, 4]]
        len(m)
    "#);
    assert!(result.is_ok());
    // len returns total elements in tensor
    assert_eq!(result.unwrap(), Value::Number(4.0));
}

#[test]
fn test_chained_type_aliases() {
    let mut eval = Evaluator::new();
    // Chained type aliases (alias of an alias)
    let result = eval.eval_str(r#"
        type Integer = Number
        type PositiveInt = Integer
        let n: PositiveInt = 42
        n
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::Number(42.0));
}

#[test]
fn test_type_alias_in_union() {
    let mut eval = Evaluator::new();
    // Using type alias within a union
    let result = eval.eval_str(r#"
        type ErrorCode = Number
        type Result = String | ErrorCode
        let ok: Result = "success"
        let err: Result = 404
        ok
    "#);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Value::String("success".to_string()));
}
