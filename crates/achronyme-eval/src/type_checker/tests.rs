//! Tests for the type checker module

#[cfg(test)]
mod tests {
    use crate::type_checker::{check_type, check_type_detailed, infer_type, is_assignable};
    use achronyme_parser::TypeAnnotation;
    use achronyme_types::complex::Complex;
    use achronyme_types::function::Function;
    use achronyme_types::tensor::{ComplexTensor, RealTensor};
    use achronyme_types::value::Value;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    // Helper to create a simple lambda function for testing
    fn create_test_function(param_count: usize) -> Function {
        let params: Vec<String> = (0..param_count).map(|i| format!("p{}", i)).collect();
        let env = achronyme_types::Environment::new();
        Function::new_with_env(
            params,
            achronyme_parser::AstNode::Number(0.0),
            Rc::new(RefCell::new(env)),
        )
    }

    #[test]
    fn test_simple_number_type() {
        let value = Value::Number(42.0);
        assert!(check_type(&value, &TypeAnnotation::Number).is_ok());
        assert!(check_type(&value, &TypeAnnotation::String).is_err());
        assert!(check_type(&value, &TypeAnnotation::Boolean).is_err());
    }

    #[test]
    fn test_simple_boolean_type() {
        let value = Value::Boolean(true);
        assert!(check_type(&value, &TypeAnnotation::Boolean).is_ok());
        assert!(check_type(&value, &TypeAnnotation::Number).is_err());
    }

    #[test]
    fn test_simple_string_type() {
        let value = Value::String("hello".to_string());
        assert!(check_type(&value, &TypeAnnotation::String).is_ok());
        assert!(check_type(&value, &TypeAnnotation::Number).is_err());
    }

    #[test]
    fn test_simple_complex_type() {
        let value = Value::Complex(Complex::new(3.0, 4.0));
        assert!(check_type(&value, &TypeAnnotation::Complex).is_ok());
        assert!(check_type(&value, &TypeAnnotation::Number).is_err());
    }

    #[test]
    fn test_null_type() {
        let value = Value::Null;
        assert!(check_type(&value, &TypeAnnotation::Null).is_ok());
        assert!(check_type(&value, &TypeAnnotation::Number).is_err());

        let number = Value::Number(42.0);
        assert!(check_type(&number, &TypeAnnotation::Null).is_err());
    }

    #[test]
    fn test_any_type_matches_everything() {
        assert!(check_type(&Value::Number(42.0), &TypeAnnotation::Any).is_ok());
        assert!(check_type(&Value::Boolean(true), &TypeAnnotation::Any).is_ok());
        assert!(check_type(&Value::String("test".into()), &TypeAnnotation::Any).is_ok());
        assert!(check_type(&Value::Null, &TypeAnnotation::Any).is_ok());
        assert!(check_type(&Value::Vector(vec![]), &TypeAnnotation::Any).is_ok());
    }

    #[test]
    fn test_union_type_matches_any_variant() {
        let union = TypeAnnotation::Union(vec![
            TypeAnnotation::Number,
            TypeAnnotation::String,
        ]);

        assert!(check_type(&Value::Number(42.0), &union).is_ok());
        assert!(check_type(&Value::String("hello".into()), &union).is_ok());
        assert!(check_type(&Value::Boolean(true), &union).is_err());
    }

    #[test]
    fn test_optional_type_with_null() {
        let optional_number = TypeAnnotation::Union(vec![
            TypeAnnotation::Number,
            TypeAnnotation::Null,
        ]);

        assert!(check_type(&Value::Number(42.0), &optional_number).is_ok());
        assert!(check_type(&Value::Null, &optional_number).is_ok());
        assert!(check_type(&Value::String("hello".into()), &optional_number).is_err());
    }

    #[test]
    fn test_triple_union_type() {
        let union = TypeAnnotation::Union(vec![
            TypeAnnotation::Number,
            TypeAnnotation::String,
            TypeAnnotation::Boolean,
        ]);

        assert!(check_type(&Value::Number(42.0), &union).is_ok());
        assert!(check_type(&Value::String("test".into()), &union).is_ok());
        assert!(check_type(&Value::Boolean(false), &union).is_ok());
        assert!(check_type(&Value::Null, &union).is_err());
    }

    #[test]
    fn test_vector_type() {
        let empty_vec = Value::Vector(vec![]);
        let mixed_vec = Value::Vector(vec![
            Value::Number(1.0),
            Value::String("two".into()),
            Value::Boolean(true),
        ]);

        // Vector type matches any vector (heterogeneous, no element checking)
        assert!(check_type(&empty_vec, &TypeAnnotation::Vector).is_ok());
        assert!(check_type(&mixed_vec, &TypeAnnotation::Vector).is_ok());

        // Non-vectors don't match
        assert!(check_type(&Value::Number(42.0), &TypeAnnotation::Vector).is_err());
    }

    #[test]
    fn test_record_structural_typing_exact_match() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        fields.insert("age".to_string(), (false, false, TypeAnnotation::Number));
        let record_type = TypeAnnotation::Record { fields };

        let mut actual_fields = HashMap::new();
        actual_fields.insert("name".to_string(), Value::String("John".into()));
        actual_fields.insert("age".to_string(), Value::Number(30.0));
        let value = Value::Record(actual_fields);

        assert!(check_type(&value, &record_type).is_ok());
    }

    #[test]
    fn test_record_structural_typing_extra_fields_allowed() {
        let mut required_fields = HashMap::new();
        required_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        let record_type = TypeAnnotation::Record {
            fields: required_fields,
        };

        let mut actual_fields = HashMap::new();
        actual_fields.insert("name".to_string(), Value::String("John".into()));
        actual_fields.insert("age".to_string(), Value::Number(30.0)); // Extra field
        actual_fields.insert(
            "email".to_string(),
            Value::String("john@example.com".into()),
        ); // Another extra field
        let value = Value::Record(actual_fields);

        // Should match because all required fields are present with correct types
        assert!(check_type(&value, &record_type).is_ok());
    }

    #[test]
    fn test_record_missing_required_field() {
        let mut required_fields = HashMap::new();
        required_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        required_fields.insert("age".to_string(), (false, false, TypeAnnotation::Number));
        let record_type = TypeAnnotation::Record {
            fields: required_fields,
        };

        let mut actual_fields = HashMap::new();
        actual_fields.insert("name".to_string(), Value::String("John".into()));
        // Missing "age" field
        let value = Value::Record(actual_fields);

        assert!(check_type(&value, &record_type).is_err());
    }

    #[test]
    fn test_record_wrong_field_type() {
        let mut required_fields = HashMap::new();
        required_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        let record_type = TypeAnnotation::Record {
            fields: required_fields,
        };

        let mut actual_fields = HashMap::new();
        actual_fields.insert("name".to_string(), Value::Number(42.0)); // Wrong type
        let value = Value::Record(actual_fields);

        assert!(check_type(&value, &record_type).is_err());
    }

    #[test]
    fn test_nested_record_types() {
        let mut inner_fields = HashMap::new();
        inner_fields.insert("street".to_string(), (false, false, TypeAnnotation::String));
        let inner_record = TypeAnnotation::Record {
            fields: inner_fields,
        };

        let mut outer_fields = HashMap::new();
        outer_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        outer_fields.insert("address".to_string(), (false, false, inner_record));
        let outer_record = TypeAnnotation::Record {
            fields: outer_fields,
        };

        let mut inner_value = HashMap::new();
        inner_value.insert("street".to_string(), Value::String("123 Main St".into()));

        let mut outer_value = HashMap::new();
        outer_value.insert("name".to_string(), Value::String("John".into()));
        outer_value.insert("address".to_string(), Value::Record(inner_value));

        let value = Value::Record(outer_value);

        assert!(check_type(&value, &outer_record).is_ok());
    }

    #[test]
    fn test_real_tensor_type_no_shape() {
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0], vec![3]).unwrap();
        let value = Value::Tensor(tensor);

        let tensor_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: None,
        };

        assert!(check_type(&value, &tensor_type).is_ok());
    }

    #[test]
    fn test_real_tensor_type_with_exact_shape() {
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0], vec![2, 3]).unwrap();
        let value = Value::Tensor(tensor);

        let tensor_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(vec![Some(2), Some(3)]),
        };

        assert!(check_type(&value, &tensor_type).is_ok());

        // Wrong shape should fail
        let wrong_shape_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(vec![Some(3), Some(2)]),
        };
        assert!(check_type(&value, &wrong_shape_type).is_err());
    }

    #[test]
    fn test_real_tensor_type_with_wildcard_shape() {
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0], vec![2, 3]).unwrap();
        let value = Value::Tensor(tensor);

        // Wildcard for first dimension
        let tensor_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(vec![None, Some(3)]), // [_, 3]
        };

        assert!(check_type(&value, &tensor_type).is_ok());

        // Wildcard for second dimension
        let tensor_type2 = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(vec![Some(2), None]), // [2, _]
        };

        assert!(check_type(&value, &tensor_type2).is_ok());

        // All wildcards
        let tensor_type3 = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(vec![None, None]), // [_, _]
        };

        assert!(check_type(&value, &tensor_type3).is_ok());
    }

    #[test]
    fn test_real_tensor_wrong_rank() {
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0], vec![3]).unwrap(); // 1D
        let value = Value::Tensor(tensor);

        let tensor_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: Some(vec![Some(3), Some(1)]), // Expects 2D
        };

        assert!(check_type(&value, &tensor_type).is_err());
    }

    #[test]
    fn test_complex_tensor_type() {
        let tensor = ComplexTensor::new(
            vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)],
            vec![2],
        )
        .unwrap();
        let value = Value::ComplexTensor(tensor);

        let tensor_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Complex),
            shape: None,
        };

        assert!(check_type(&value, &tensor_type).is_ok());

        // Wrong element type should fail
        let wrong_element_type = TypeAnnotation::Tensor {
            element_type: Box::new(TypeAnnotation::Number),
            shape: None,
        };
        assert!(check_type(&value, &wrong_element_type).is_err());
    }

    #[test]
    fn test_function_type_basic() {
        let func = create_test_function(2);
        let value = Value::Function(func);

        let func_type = TypeAnnotation::Function {
            params: vec![Some(TypeAnnotation::Number), Some(TypeAnnotation::String)],
            return_type: Box::new(TypeAnnotation::Number),
        };

        assert!(check_type(&value, &func_type).is_ok());
    }

    #[test]
    fn test_function_type_wrong_param_count() {
        let func = create_test_function(2);
        let value = Value::Function(func);

        let func_type = TypeAnnotation::Function {
            params: vec![
                Some(TypeAnnotation::Number),
                Some(TypeAnnotation::String),
                Some(TypeAnnotation::Boolean),
            ],
            return_type: Box::new(TypeAnnotation::Number),
        };

        assert!(check_type(&value, &func_type).is_err());
    }

    #[test]
    fn test_function_type_empty_params() {
        let func = create_test_function(5);
        let value = Value::Function(func);

        // Empty params means no checking of parameter count
        let func_type = TypeAnnotation::Function {
            params: vec![],
            return_type: Box::new(TypeAnnotation::Any),
        };

        assert!(check_type(&value, &func_type).is_ok());
    }

    #[test]
    fn test_mutable_ref_auto_deref() {
        let inner_value = Value::Number(42.0);
        let mutable_ref = Value::MutableRef(Rc::new(RefCell::new(inner_value)));

        // Should auto-dereference and check the inner value
        assert!(check_type(&mutable_ref, &TypeAnnotation::Number).is_ok());
        assert!(check_type(&mutable_ref, &TypeAnnotation::String).is_err());
    }

    #[test]
    fn test_mutable_ref_with_union() {
        let inner_value = Value::String("hello".into());
        let mutable_ref = Value::MutableRef(Rc::new(RefCell::new(inner_value)));

        let union = TypeAnnotation::Union(vec![
            TypeAnnotation::Number,
            TypeAnnotation::String,
        ]);

        assert!(check_type(&mutable_ref, &union).is_ok());
    }

    #[test]
    fn test_is_assignable() {
        assert!(is_assignable(&Value::Number(42.0), &TypeAnnotation::Number));
        assert!(!is_assignable(
            &Value::Number(42.0),
            &TypeAnnotation::String
        ));

        let union = TypeAnnotation::Union(vec![
            TypeAnnotation::Number,
            TypeAnnotation::String,
        ]);
        assert!(is_assignable(&Value::Number(42.0), &union));
        assert!(is_assignable(&Value::String("test".into()), &union));
        assert!(!is_assignable(&Value::Boolean(true), &union));
    }

    #[test]
    fn test_check_type_detailed() {
        let result = check_type_detailed(&Value::Number(42.0), &TypeAnnotation::String);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.expected, "String");
        assert_eq!(error.actual, "Number");
    }

    #[test]
    fn test_infer_type_simple() {
        assert_eq!(infer_type(&Value::Number(42.0)), TypeAnnotation::Number);
        assert_eq!(infer_type(&Value::Boolean(true)), TypeAnnotation::Boolean);
        assert_eq!(
            infer_type(&Value::String("test".into())),
            TypeAnnotation::String
        );
        assert_eq!(
            infer_type(&Value::Complex(Complex::new(1.0, 2.0))),
            TypeAnnotation::Complex
        );
        assert_eq!(infer_type(&Value::Null), TypeAnnotation::Null);
        assert_eq!(infer_type(&Value::Vector(vec![])), TypeAnnotation::Vector);
    }

    #[test]
    fn test_infer_type_tensor() {
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0], vec![3]).unwrap();
        let value = Value::Tensor(tensor);

        let inferred = infer_type(&value);
        match inferred {
            TypeAnnotation::Tensor {
                element_type,
                shape,
            } => {
                assert_eq!(*element_type, TypeAnnotation::Number);
                assert_eq!(shape, Some(vec![Some(3)]));
            }
            _ => panic!("Expected Tensor type annotation"),
        }
    }

    #[test]
    fn test_infer_type_record() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), Value::String("John".into()));
        fields.insert("age".to_string(), Value::Number(30.0));
        let value = Value::Record(fields);

        let inferred = infer_type(&value);
        match inferred {
            TypeAnnotation::Record { fields } => {
                assert_eq!(fields.len(), 2);
                // Fields are now (is_mutable, is_optional, type)
                assert_eq!(fields.get("name").unwrap().2, TypeAnnotation::String);
                assert_eq!(fields.get("age").unwrap().2, TypeAnnotation::Number);
            }
            _ => panic!("Expected Record type annotation"),
        }
    }

    #[test]
    fn test_infer_type_mutable_ref() {
        let inner = Value::Boolean(true);
        let mutable_ref = Value::MutableRef(Rc::new(RefCell::new(inner)));

        // Should auto-dereference and infer the inner type
        assert_eq!(infer_type(&mutable_ref), TypeAnnotation::Boolean);
    }

    #[test]
    fn test_error_message_clarity() {
        let result = check_type(&Value::Number(42.0), &TypeAnnotation::String);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("expected String"));
        assert!(error.contains("got Number"));
    }

    #[test]
    fn test_complex_union_with_records() {
        let mut record_fields = HashMap::new();
        record_fields.insert("value".to_string(), (false, false, TypeAnnotation::Number));
        let record_type = TypeAnnotation::Record {
            fields: record_fields,
        };

        let union = TypeAnnotation::Union(vec![
            TypeAnnotation::String,
            record_type,
        ]);

        // String matches
        assert!(check_type(&Value::String("test".into()), &union).is_ok());

        // Record with value field matches
        let mut record_value = HashMap::new();
        record_value.insert("value".to_string(), Value::Number(42.0));
        assert!(check_type(&Value::Record(record_value), &union).is_ok());

        // Number doesn't match
        assert!(check_type(&Value::Number(42.0), &union).is_err());
    }

    #[test]
    fn test_optional_field_present() {
        // Test that a record with an optional field present type checks correctly
        let mut type_fields = HashMap::new();
        type_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        type_fields.insert("age".to_string(), (false, true, TypeAnnotation::Number)); // optional
        let record_type = TypeAnnotation::Record { fields: type_fields };

        let mut value_fields = HashMap::new();
        value_fields.insert("name".to_string(), Value::String("Alice".into()));
        value_fields.insert("age".to_string(), Value::Number(30.0));
        let value = Value::Record(value_fields);

        assert!(check_type(&value, &record_type).is_ok());
    }

    #[test]
    fn test_optional_field_absent() {
        // Test that a record with an optional field absent type checks correctly
        let mut type_fields = HashMap::new();
        type_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        type_fields.insert("age".to_string(), (false, true, TypeAnnotation::Number)); // optional
        let record_type = TypeAnnotation::Record { fields: type_fields };

        let mut value_fields = HashMap::new();
        value_fields.insert("name".to_string(), Value::String("Bob".into()));
        // age is absent
        let value = Value::Record(value_fields);

        assert!(check_type(&value, &record_type).is_ok());
    }

    #[test]
    fn test_required_field_absent_fails() {
        // Test that a record with a required field absent fails type check
        let mut type_fields = HashMap::new();
        type_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        type_fields.insert("age".to_string(), (false, false, TypeAnnotation::Number)); // required
        let record_type = TypeAnnotation::Record { fields: type_fields };

        let mut value_fields = HashMap::new();
        value_fields.insert("name".to_string(), Value::String("Charlie".into()));
        // age is absent but required
        let value = Value::Record(value_fields);

        assert!(check_type(&value, &record_type).is_err());
    }

    #[test]
    fn test_optional_field_wrong_type_fails() {
        // Test that an optional field with wrong type fails
        let mut type_fields = HashMap::new();
        type_fields.insert("name".to_string(), (false, false, TypeAnnotation::String));
        type_fields.insert("age".to_string(), (false, true, TypeAnnotation::Number)); // optional Number
        let record_type = TypeAnnotation::Record { fields: type_fields };

        let mut value_fields = HashMap::new();
        value_fields.insert("name".to_string(), Value::String("Dave".into()));
        value_fields.insert("age".to_string(), Value::String("not a number".into())); // wrong type
        let value = Value::Record(value_fields);

        assert!(check_type(&value, &record_type).is_err());
    }

    #[test]
    fn test_mutable_optional_field() {
        // Test mutable optional field
        let mut type_fields = HashMap::new();
        type_fields.insert("id".to_string(), (false, false, TypeAnnotation::Number));
        type_fields.insert("mut_value".to_string(), (true, true, TypeAnnotation::String)); // mutable and optional
        let record_type = TypeAnnotation::Record { fields: type_fields };

        // With mutable optional field absent
        let mut value_fields = HashMap::new();
        value_fields.insert("id".to_string(), Value::Number(1.0));
        let value = Value::Record(value_fields);

        assert!(check_type(&value, &record_type).is_ok());
    }
}
