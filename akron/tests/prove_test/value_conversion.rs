use memory::{FieldElement, Value};

#[test]
fn value_to_field_element_field() {
    use akron::machine::prove::value_to_field_element;
    let mut heap = memory::Heap::new();
    let fe = FieldElement::from_u64(42);
    let handle = heap.alloc_field(fe).expect("alloc");
    let val = Value::field(handle);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(fe));
}

#[test]
fn value_to_field_element_int() {
    use akron::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::int(123);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(FieldElement::from_i64(123)));
}

#[test]
fn value_to_field_element_nil_returns_none() {
    use akron::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::nil();
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, None);
}

#[test]
fn value_to_field_element_bool_returns_none() {
    use akron::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::true_val();
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, None);
}

#[test]
fn value_to_field_element_int_seven() {
    use akron::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::int(7);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(FieldElement::from_i64(7)));
}

#[test]
fn value_to_field_element_negative_int() {
    use akron::machine::prove::value_to_field_element;
    let heap = memory::Heap::new();
    let val = Value::int(-3);
    let result = value_to_field_element(&heap, val);
    assert_eq!(result, Some(FieldElement::from_i64(-3)));
}
