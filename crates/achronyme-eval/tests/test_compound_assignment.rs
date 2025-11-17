use achronyme_eval::Evaluator;
use achronyme_types::value::Value;

// Helper function to extract number value
fn extract_number(value: &Value) -> f64 {
    match value {
        Value::Number(n) => *n,
        _ => panic!("Expected Number, got {:?}", value),
    }
}

#[test]
fn test_add_assign_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        x += 5
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_sub_assign_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 15
        x -= 3
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 12.0);
}

#[test]
fn test_mul_assign_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 12
        x *= 2
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 24.0);
}

#[test]
fn test_div_assign_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 24
        x /= 4
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 6.0);
}

#[test]
fn test_mod_assign_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 6
        x %= 4
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 2.0);
}

#[test]
fn test_pow_assign_basic() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 2
        x ^= 3
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 8.0);
}

#[test]
fn test_compound_assignment_chain() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        x += 5
        x -= 3
        x *= 2
        x /= 4
        x %= 4
        x
    "#).unwrap();
    // 10 + 5 = 15
    // 15 - 3 = 12
    // 12 * 2 = 24
    // 24 / 4 = 6
    // 6 % 4 = 2
    assert_eq!(extract_number(&result), 2.0);
}

#[test]
fn test_compound_with_expression_rhs() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut n = 10
        n += 2 * 3
        n
    "#).unwrap();
    // 10 + (2 * 3) = 10 + 6 = 16
    assert_eq!(extract_number(&result), 16.0);
}

#[test]
fn test_compound_with_complex_expression() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 100
        x -= (5 + 3) * 2
        x
    "#).unwrap();
    // 100 - ((5 + 3) * 2) = 100 - 16 = 84
    assert_eq!(extract_number(&result), 84.0);
}

#[test]
fn test_compound_assignment_returns_new_value() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        x += 5
    "#).unwrap();
    // Compound assignment should return the new value
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_multiple_variables_compound() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut a = 10
        mut b = 20
        a += 5
        b -= 10
        a + b
    "#).unwrap();
    // a = 15, b = 10, sum = 25
    assert_eq!(extract_number(&result), 25.0);
}

#[test]
fn test_record_field_compound_assignment() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut obj = {mut value: 10}
        obj.value += 5
        obj.value
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_record_field_all_operators() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut obj = {mut a: 10, mut b: 20, mut c: 8, mut d: 24, mut e: 7, mut f: 2}
        obj.a += 5
        obj.b -= 3
        obj.c *= 2
        obj.d /= 6
        obj.e %= 3
        obj.f ^= 4
        [obj.a, obj.b, obj.c, obj.d, obj.e, obj.f]
    "#).unwrap();

    // Arrays of numbers can be either Vector or Tensor
    match result {
        Value::Tensor(tensor) => {
            let shape = tensor.shape().to_vec();
            assert_eq!(shape, vec![6]);
            let data = tensor.data().to_vec();
            assert_eq!(data[0], 15.0); // 10 + 5
            assert_eq!(data[1], 17.0); // 20 - 3
            assert_eq!(data[2], 16.0); // 8 * 2
            assert_eq!(data[3], 4.0);  // 24 / 6
            assert_eq!(data[4], 1.0);  // 7 % 3
            assert_eq!(data[5], 16.0); // 2 ^ 4
        }
        Value::Vector(vec) => {
            assert_eq!(vec.len(), 6);
            assert_eq!(extract_number(&vec[0]), 15.0); // 10 + 5
            assert_eq!(extract_number(&vec[1]), 17.0); // 20 - 3
            assert_eq!(extract_number(&vec[2]), 16.0); // 8 * 2
            assert_eq!(extract_number(&vec[3]), 4.0);  // 24 / 6
            assert_eq!(extract_number(&vec[4]), 1.0);  // 7 % 3
            assert_eq!(extract_number(&vec[5]), 16.0); // 2 ^ 4
        }
        _ => panic!("Expected Tensor or Vector, got {:?}", result),
    }
}

#[test]
fn test_nested_record_field_compound() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut config = {
            mut settings: {
                mut count: 5
            }
        }
        config.settings.count += 10
        config.settings.count
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_immutable_variable_error() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let x = 10
        x += 5
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("immutable") || err.contains("assign"));
}

#[test]
fn test_immutable_field_error() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let obj = {value: 10}
        obj.value += 5
    "#);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("immutable") || err.contains("mut"));
}

#[test]
fn test_counter_pattern() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut counter = 0
        counter += 1
        counter += 1
        counter += 1
        counter
    "#).unwrap();
    assert_eq!(extract_number(&result), 3.0);
}

#[test]
fn test_sum_in_while_loop() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut sum = 0
        mut i = 0
        while(i < 5) {
            sum += i
            i += 1
        }
        sum
    "#).unwrap();
    // sum = 0 + 1 + 2 + 3 + 4 = 10
    assert_eq!(extract_number(&result), 10.0);
}

#[test]
fn test_factorial_with_compound() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut result = 1
        mut n = 5
        while(n > 0) {
            result *= n
            n -= 1
        }
        result
    "#).unwrap();
    // 5! = 120
    assert_eq!(extract_number(&result), 120.0);
}

#[test]
fn test_fibonacci_with_compound() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut a = 0
        mut b = 1
        mut count = 10
        while(count > 0) {
            let temp = b
            b += a
            a = temp
            count -= 1
        }
        b
    "#).unwrap();
    // F(11) = 89 (after 10 iterations from F(1)=1, F(2)=1)
    assert_eq!(extract_number(&result), 89.0);
}

#[test]
fn test_string_concatenation_with_add_assign() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut s = "Hello"
        s += " World"
        s
    "#).unwrap();
    if let Value::String(s) = result {
        assert_eq!(s, "Hello World");
    } else {
        panic!("Expected String, got {:?}", result);
    }
}

#[test]
fn test_compound_with_negative_numbers() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        x += -5
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 5.0);
}

#[test]
fn test_compound_with_floating_point() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10.5
        x += 2.3
        x
    "#).unwrap();
    let n = extract_number(&result);
    assert!((n - 12.8).abs() < 0.0001);
}

#[test]
fn test_compound_preserves_type_annotation() {
    let mut eval = Evaluator::new();
    // This should work because we're assigning a number to a number type
    let result = eval.eval_str(r#"
        mut x: Number = 10
        x += 5
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_compound_division_by_zero() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        x /= 0
        x
    "#);
    // IEEE 754 compliant: division by zero returns Infinity, not an error
    assert!(result.is_ok(), "Division by zero should return Infinity (IEEE 754)");
    match result.unwrap() {
        achronyme_types::value::Value::MutableRef(rc) => {
            match rc.borrow().clone() {
                achronyme_types::value::Value::Number(n) => {
                    assert!(n.is_infinite(), "Expected Infinity for division by zero");
                    assert!(n.is_sign_positive());
                }
                _ => panic!("Expected Number inside MutableRef"),
            }
        }
        achronyme_types::value::Value::Number(n) => {
            assert!(n.is_infinite(), "Expected Infinity for division by zero");
            assert!(n.is_sign_positive());
        }
        other => panic!("Expected MutableRef or Number, got {:?}", other),
    }
}

#[test]
fn test_compound_modulo_by_zero() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        x %= 0
        x
    "#);
    // Achronyme returns an error for modulo by zero
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Modulo by zero") || err.contains("modulo"));
}

#[test]
fn test_compound_with_parenthesized_target() {
    let mut eval = Evaluator::new();
    // Testing that we can use compound assignment after getting value
    let result = eval.eval_str(r#"
        mut x = 10
        x += (3 + 2)
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_compound_in_do_block() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        do {
            x += 5
            x *= 2
        }
        x
    "#).unwrap();
    // (10 + 5) * 2 = 30
    assert_eq!(extract_number(&result), 30.0);
}

#[test]
fn test_compound_in_if_branches() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 10
        if(x > 5) {
            x += 10
        } else {
            x -= 10
        }
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 20.0);
}

#[test]
fn test_power_assign_with_fractional_exponent() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut x = 4
        x ^= 0.5
        x
    "#).unwrap();
    // 4^0.5 = 2
    let n = extract_number(&result);
    assert!((n - 2.0).abs() < 0.0001);
}

#[test]
fn test_compound_accumulator_pattern() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let items = [1, 2, 3, 4, 5]
        mut sum = 0
        mut i = 0
        while(i < 5) {
            sum += items[i]
            i += 1
        }
        sum
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_compound_product_pattern() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let items = [1, 2, 3, 4, 5]
        mut product = 1
        mut i = 0
        while(i < 5) {
            product *= items[i]
            i += 1
        }
        product
    "#).unwrap();
    assert_eq!(extract_number(&result), 120.0);
}

#[test]
fn test_compound_max_pattern() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        mut max = 0
        let values = [5, 2, 8, 1, 9, 3]
        mut i = 0
        while(i < 6) {
            if(values[i] > max) {
                max = values[i]
            }
            i += 1
        }
        max
    "#).unwrap();
    assert_eq!(extract_number(&result), 9.0);
}

#[test]
fn test_compound_in_lambda() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let incrementBy = n => do {
            mut x = 10
            x += n
            x
        }
        incrementBy(5)
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}

#[test]
fn test_compound_with_function_call_rhs() {
    let mut eval = Evaluator::new();
    let result = eval.eval_str(r#"
        let getValue = () => 5
        mut x = 10
        x += getValue()
        x
    "#).unwrap();
    assert_eq!(extract_number(&result), 15.0);
}
