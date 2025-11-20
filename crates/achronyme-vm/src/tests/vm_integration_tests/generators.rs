use super::helpers::execute;
use crate::value::Value;

// ===== Phase 5: Generators =====

#[test]
fn test_generator_creation() {
    let source = r#"
        let gen = generate {
            yield 1
        }
        gen
    "#;
    let result = execute(source).unwrap();
    assert!(result.is_generator());
}

#[test]
fn test_generator_simple_yield() {
    let source = r#"
        let gen = generate {
            yield 1
            yield 2
            yield 3
        }
        gen.next()
    "#;
    let result = execute(source).unwrap();
    // Should return {value: 1, done: false}
    match result {
        Value::Record(rec_rc) => {
            let rec = rec_rc.borrow();
            assert_eq!(rec.get("value"), Some(&Value::Number(1.0)));
            assert_eq!(rec.get("done"), Some(&Value::Boolean(false)));
        }
        _ => panic!("Expected Record, got {:?}", result),
    }
}

#[test]
fn test_generator_multiple_next() {
    let source = r#"
        let gen = generate {
            yield 10
            yield 20
            yield 30
        }
        let a = gen.next()
        let b = gen.next()
        let c = gen.next()
        a.value + b.value + c.value
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(60.0)); // 10 + 20 + 30
}

#[test]
fn test_generator_exhausted() {
    let source = r#"
        let gen = generate {
            yield 42
        }
        gen.next()
        gen.next()
        gen.next()
    "#;
    let result = execute(source).unwrap();
    // Should return {value: null, done: true} when exhausted
    match result {
        Value::Record(rec_rc) => {
            let rec = rec_rc.borrow();
            assert_eq!(rec.get("value"), Some(&Value::Null));
            assert_eq!(rec.get("done"), Some(&Value::Boolean(true)));
        }
        _ => panic!("Expected Record, got {:?}", result),
    }
}

#[test]
fn test_generator_iterator_protocol() {
    // Test that generator.next() returns proper iterator result objects
    let source = r#"
        let gen = generate {
            yield 100
            yield 200
        }
        let first = gen.next()
        let second = gen.next()
        let third = gen.next()

        // Check first yield
        let first_value = first.value
        let first_done = first.done

        // Check second yield
        let second_value = second.value
        let second_done = second.done

        // Check exhausted state
        let third_done = third.done

        // Verify values
        if (first_done == false) {
            if (second_done == false) {
                if (third_done == true) {
                    first_value + second_value
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        }
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(300.0));
}

// ===== Phase 5 Week 14: for-in loops =====

#[test]
fn test_for_in_generator() {
    let source = r#"
        let gen = generate {
            yield 1
            yield 2
            yield 3
        }

        mut sum = 0
        for (x in gen) {
            sum = sum + x
        }
        sum
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(6.0)); // 1 + 2 + 3
}

#[test]
fn test_for_in_break() {
    let source = r#"
        let gen = generate {
            yield 1
            yield 2
            yield 3
            yield 4
        }

        mut sum = 0
        for (x in gen) {
            if (x > 2) {
                break
            }
            sum = sum + x
        }
        sum
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(3.0)); // 1 + 2, stops at 3
}

#[test]
fn test_for_in_continue() {
    let source = r#"
        let gen = generate {
            yield 1
            yield 2
            yield 3
        }

        mut sum = 0
        for (x in gen) {
            if (x == 2) {
                continue
            }
            sum = sum + x
        }
        sum
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(4.0)); // 1 + 3, skips 2
}

// ===== Collection Iterator Tests =====

#[test]
fn test_for_in_vector() {
    // Test iterating over a vector
    let source = r#"
        let vec = [10, 20, 30]
        mut sum = 0
        for (x in vec) {
            sum = sum + x
        }
        sum
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(60.0));
}

#[test]
fn test_for_in_string() {
    // Test iterating over a string
    let source = r#"
        let str = "abc"
        mut result = ""
        for (c in str) {
            result = result + c
        }
        result
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::String("abc".to_string()));
}

#[test]
fn test_for_in_empty_vector() {
    // Test iterating over an empty vector
    let source = r#"
        let vec = []
        mut sum = 0
        for (x in vec) {
            sum = sum + x
        }
        sum
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(0.0));
}

#[test]
fn test_for_in_nested() {
    // Test nested iteration with 2D array
    // Note: Each inner iteration needs a fresh vector reference
    let source = r#"
        let matrix = [[1, 2], [3, 4]]
        mut sum = 0
        mut i = 0
        for (row in matrix) {
            mut j = 0
            while (j < 2) {
                let val = row[j]
                sum = sum + val
                j = j + 1
            }
            i = i + 1
        }
        sum
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(10.0)); // 1 + 2 + 3 + 4
}