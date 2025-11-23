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
