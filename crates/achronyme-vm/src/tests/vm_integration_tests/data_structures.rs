use super::helpers::execute;
use crate::value::Value;

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