//! Integration tests for the VM

use crate::compiler::Compiler;
use crate::value::Value;
use crate::vm::VM;

/// Helper to compile and execute source code
fn execute(source: &str) -> Result<Value, String> {
    // Parse
    let ast = achronyme_parser::parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

    // Compile
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler
        .compile(&ast)
        .map_err(|e| format!("Compile error: {}", e))?;

    // Execute
    let mut vm = VM::new();
    vm.execute(module)
        .map_err(|e| format!("Runtime error: {}", e))
}

#[test]
fn test_number_literal() {
    let result = execute("42").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_boolean_literal() {
    let result = execute("true").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute("false").unwrap();
    assert_eq!(result, Value::Boolean(false));
}

#[test]
fn test_null_literal() {
    let result = execute("null").unwrap();
    assert_eq!(result, Value::Null);
}

#[test]
fn test_addition() {
    let result = execute("2 + 3").unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_subtraction() {
    let result = execute("10 - 4").unwrap();
    assert_eq!(result, Value::Number(6.0));
}

#[test]
fn test_multiplication() {
    let result = execute("6 * 7").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_division() {
    let result = execute("20 / 4").unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_negation() {
    let result = execute("-42").unwrap();
    assert_eq!(result, Value::Number(-42.0));
}

#[test]
fn test_arithmetic_combination() {
    let result = execute("2 + 3 * 4").unwrap();
    assert_eq!(result, Value::Number(14.0));
}

#[test]
fn test_comparison() {
    let result = execute("5 < 10").unwrap();
    assert_eq!(result, Value::Boolean(true));

    let result = execute("5 > 10").unwrap();
    assert_eq!(result, Value::Boolean(false));

    let result = execute("5 == 5").unwrap();
    assert_eq!(result, Value::Boolean(true));
}

#[test]
fn test_variable_declaration() {
    let result = execute("let x = 42\nx").unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_variable_assignment() {
    let result = execute("mut x = 10\nx = 20\nx").unwrap();
    assert_eq!(result, Value::Number(20.0));
}

#[test]
fn test_multiple_variables() {
    let result = execute("let x = 5\nlet y = 10\nx + y").unwrap();
    assert_eq!(result, Value::Number(15.0));
}

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

// ===== Phase 3: Vectors and Records =====

#[test]
fn test_vector_literal() {
    let source = "[1, 2, 3]";
    let result = execute(source).unwrap();

    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 3);
            assert_eq!(vec[0], Value::Number(1.0));
            assert_eq!(vec[1], Value::Number(2.0));
            assert_eq!(vec[2], Value::Number(3.0));
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_vector_index_access() {
    let source = r#"
        let arr = [10, 20, 30]
        arr[1]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(20.0));
}

#[test]
fn test_vector_negative_index() {
    let source = r#"
        let arr = [1, 2, 3, 4, 5]
        arr[-1]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_vector_assignment() {
    let source = r#"
        let arr = [1, 2, 3]
        arr[1] = 99
        arr[1]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(99.0));
}

#[test]
fn test_vector_reference_semantics() {
    let source = r#"
        let arr1 = [1, 2, 3]
        let arr2 = arr1
        arr2[0] = 99
        arr1[0]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(99.0), "Vectors should have reference semantics");
}

#[test]
fn test_nested_vectors() {
    let source = r#"
        let matrix = [[1, 2], [3, 4]]
        matrix[1][0]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(3.0));
}

#[test]
fn test_empty_vector() {
    let source = "[]";
    let result = execute(source).unwrap();

    match result {
        Value::Vector(vec_rc) => {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 0);
        }
        _ => panic!("Expected Vector, got {:?}", result),
    }
}

#[test]
fn test_record_literal() {
    let source = r#"
        { x: 10, y: 20 }
    "#;
    let result = execute(source).unwrap();

    match result {
        Value::Record(rec_rc) => {
            let rec = rec_rc.borrow();
            assert_eq!(rec.len(), 2);
            assert_eq!(rec.get("x"), Some(&Value::Number(10.0)));
            assert_eq!(rec.get("y"), Some(&Value::Number(20.0)));
        }
        _ => panic!("Expected Record, got {:?}", result),
    }
}

#[test]
fn test_record_field_access() {
    let source = r#"
        let point = { x: 5, y: 10 }
        point.x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(5.0));
}

#[test]
fn test_record_field_assignment() {
    let source = r#"
        let point = { x: 5, y: 10 }
        point.x = 99
        point.x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(99.0));
}

#[test]
fn test_record_reference_semantics() {
    let source = r#"
        let p1 = { x: 1, y: 2 }
        let p2 = p1
        p2.x = 99
        p1.x
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(99.0), "Records should have reference semantics");
}

#[test]
fn test_nested_records() {
    let source = r#"
        let person = { name: "Alice", address: { city: "NYC" } }
        person.address.city
    "#;
    // Note: String literals not yet implemented, so this test will use numbers
    let source = r#"
        let obj = { outer: { inner: 42 } }
        obj.outer.inner
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(42.0));
}

#[test]
fn test_empty_record() {
    let source = "{}";
    let result = execute(source).unwrap();

    match result {
        Value::Record(rec_rc) => {
            let rec = rec_rc.borrow();
            assert_eq!(rec.len(), 0);
        }
        _ => panic!("Expected Record, got {:?}", result),
    }
}

#[test]
fn test_vector_in_record() {
    let source = r#"
        let data = { values: [1, 2, 3] }
        data.values[1]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(2.0));
}

#[test]
fn test_record_in_vector() {
    let source = r#"
        let people = [{ age: 25 }, { age: 30 }]
        people[1].age
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(30.0));
}

#[test]
fn test_vector_mutation_in_loop() {
    let source = r#"
        let arr = [1, 2, 3]
        mut i = 0
        while (i < 3) {
            arr[i] = arr[i] * 2
            i = i + 1
        }
        arr[2]
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(6.0));
}

#[test]
fn test_record_with_functions() {
    let source = r#"
        let obj = {
            value: 10,
            getValue: (o) => o.value
        }
        obj.getValue(obj)
    "#;
    let result = execute(source).unwrap();
    assert_eq!(result, Value::Number(10.0));
}
