use super::helpers::execute;
use crate::value::Value;

// ===== Phase 2 Tests: Lambdas, Closures, and Function Calls =====

#[test]
fn test_lambda_simple() {
    let result = execute("let add = (x, y) => x + y\nadd(2, 3)").unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_lambda_immediate_call() {
    let result = execute("((x) => x * 2)(21)").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_closure_capture() {
    let source = r#"
        let x = 10
        let f = (y) => x + y
        f(5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_closure_multiple_captures() {
    let source = r#"
        let x = 10
        let y = 20
        let f = (z) => x + y + z
        f(5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(35.0));
}

#[test]
fn test_closure_mutation() {
    let source = r#"
        mut counter = 0
        let increment = () => do {
            counter = counter + 1
            counter
        }
        increment()
        increment()
        increment()
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_nested_closures() {
    let source = r#"
        let makeAdder = (x) => (y) => x + y
        let add5 = makeAdder(5)
        add5(10)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(15.0));
}

#[test]
fn test_recursive_factorial() {
    let source = r#"
        let factorial = (n) => if (n <= 1) { 1 } else { n * rec(n - 1) }
        factorial(5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(120.0));
}

#[test]
fn test_recursive_fibonacci() {
    let source = r#"
        let fib = (n) => if (n <= 1) { n } else { rec(n - 1) + rec(n - 2) }
        fib(10)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(55.0));
}

#[test]
fn test_higher_order_function() {
    let source = r#"
        let twice = (f, x) => f(f(x))
        let addOne = (n) => n + 1
        twice(addOne, 5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(7.0));
}

#[test]
fn test_lambda_with_multiple_params() {
    let source = r#"
        let add3 = (a, b, c) => a + b + c
        add3(1, 2, 3)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(6.0));
}