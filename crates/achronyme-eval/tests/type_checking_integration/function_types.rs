//! Function Type Annotation Tests

use achronyme_eval::Evaluator;

#[test]
fn test_function_type_annotation_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let add: (Number, Number): Number = (a, b) => a + b;
        add(10, 20)
    "#);
    assert!(result.is_ok());
    match result.unwrap() {
        achronyme_types::value::Value::Number(n) => assert_eq!(n, 30.0),
        other => panic!("Expected Number(30), got {:?}", other),
    }
}

#[test]
fn test_function_type_annotation_enforces_param_types() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let add: (Number, Number): Number = (a, b) => a + b;
        add(10, "Hola")
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Type error"));
    assert!(err.contains("argument 2"));
    assert!(err.contains("Number"));
    assert!(err.contains("String"));
}

#[test]
fn test_function_type_annotation_enforces_return_type() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let getNum: (): Number = () => "not a number";
        getNum()
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Type error"));
    assert!(err.contains("return type"));
}

#[test]
fn test_function_type_mismatch_not_a_function() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let add: (Number, Number): Number = "not a function"
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Type error"));
    assert!(err.contains("String"));
}

#[test]
fn test_function_type_with_any_param() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let toString: (Any): String = x => "Value: " + x;
        toString(42)
    "#);
    assert!(result.is_ok());
}

#[test]
fn test_higher_order_function_type() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let curry: (Number): ((Number): Number) = a => b => a + b;
        let add5 = curry(5);
        add5(10)
    "#);
    assert!(result.is_ok());
    match result.unwrap() {
        achronyme_types::value::Value::Number(n) => assert_eq!(n, 15.0),
        other => panic!("Expected Number(15), got {:?}", other),
    }
}

#[test]
fn test_function_type_no_params() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let getAnswer: (): Number = () => 42;
        getAnswer()
    "#);
    assert!(result.is_ok());
    match result.unwrap() {
        achronyme_types::value::Value::Number(n) => assert_eq!(n, 42.0),
        other => panic!("Expected Number(42), got {:?}", other),
    }
}

#[test]
fn test_function_type_with_union_param() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let process: (Number | String): Boolean = x => true;
        process(42)
    "#);
    assert!(result.is_ok());
}
