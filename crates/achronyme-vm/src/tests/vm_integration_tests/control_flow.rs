use super::helpers::execute;
use crate::value::Value;

#[test]
fn test_if_expression() {
    let result = execute("if (true) { 42 } else { 0 }").unwrap();
    assert_eq!(result, Value::Number(42.0));

    let result = execute("if (false) { 42 } else { 0 }").unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_return_in_do_block() {
    let source = r#"
        let f = (x) => do {
            if (x < 0) {
                return "negative"
            }
            if (x == 0) {
                return "zero"
            }
            "positive"
        }
        f(-5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("negative".to_string()));
}

#[test]
fn test_return_early_in_function() {
    let source = r#"
        let f = (x) => do {
            if (x <= 0) {
                return "eso qué pa"
            }
            "El precio será: " + str(x * 10)
        }
        f(0)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("eso qué pa".to_string()));
}

#[test]
fn test_return_multiple_paths() {
    let source = r#"
        let checkValue = (n) => do {
            if (n < 0) {
                return "negative"
            }
            if (n > 0) {
                return "positive"
            }
            "zero"
        }
        [checkValue(-5), checkValue(5), checkValue(0)]
    "#;
    let result = execute(source).unwrap();

    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.read();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::String("negative".to_string()));
            assert_eq!(vec[1], Value::String("positive".to_string()));
            assert_eq!(vec[2], Value::String("zero".to_string()));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_return_with_expression() {
    let source = r#"
        let multiply = (a, b) => do {
            if (a == 0 || b == 0) {
                return 0
            }
            a * b
        }
        multiply(0, 5)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_if_with_condition() {
    let result = execute("if (5 > 3) { 1 } else { 2 }").unwrap();
    assert_eq!(result, Value::Number(1.0));

    let result = execute("if (5 < 3) { 1 } else { 2 }").unwrap();
    assert_eq!(result, Value::Number(2.0));
}

#[test]
fn test_nested_if() {
    let source = r#"
        let x = 10
        if (x > 5) {
            if (x > 15) {
                100
            } else {
                50
            }
        } else {
            0
        }
    "#;

    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(50.0));
}

#[test]
fn test_while_loop() {
    let source = r#"
        mut i = 0
        mut sum = 0
        while (i < 5) {
            sum = sum + i
            i = i + 1
        }
        sum
    "#;

    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(10.0)); // 0+1+2+3+4
}
