use achronyme_parser::{parse, ast::*, type_annotation::TypeAnnotation};

// ============================================================================
// Variable Declaration Tests
// ============================================================================

#[test]
fn test_let_with_simple_type() {
    let result = parse("let x: Number = 42");
    assert!(result.is_ok());

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::VariableDecl { name, type_annotation, initializer } => {
            assert_eq!(name, "x");
            assert_eq!(type_annotation, &Some(TypeAnnotation::Number));
            match **initializer {
                AstNode::Number(n) => assert_eq!(n, 42.0),
                _ => panic!("Expected Number initializer"),
            }
        }
        _ => panic!("Expected VariableDecl, got {:?}", ast[0]),
    }
}

#[test]
fn test_let_without_type() {
    let result = parse("let x = 42");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableDecl { name, type_annotation, .. } => {
            assert_eq!(name, "x");
            assert_eq!(type_annotation, &None);
        }
        _ => panic!("Expected VariableDecl"),
    }
}

#[test]
fn test_mut_with_simple_type() {
    let result = parse("mut count: Number = 0");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::MutableDecl { name, type_annotation, initializer } => {
            assert_eq!(name, "count");
            assert_eq!(type_annotation, &Some(TypeAnnotation::Number));
            match **initializer {
                AstNode::Number(n) => assert_eq!(n, 0.0),
                _ => panic!("Expected Number initializer"),
            }
        }
        _ => panic!("Expected MutableDecl"),
    }
}

#[test]
fn test_let_with_union_type() {
    let result = parse("let value: Number | String = 42");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableDecl { name, type_annotation, .. } => {
            assert_eq!(name, "value");
            match type_annotation {
                Some(TypeAnnotation::Union(types)) => {
                    assert_eq!(types.len(), 2);
                    assert_eq!(types[0], TypeAnnotation::Number);
                    assert_eq!(types[1], TypeAnnotation::String);
                }
                _ => panic!("Expected Union type annotation, got {:?}", type_annotation),
            }
        }
        _ => panic!("Expected VariableDecl"),
    }
}

#[test]
fn test_let_with_optional_type() {
    let result = parse("let maybe: Number | null = null");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableDecl { name, type_annotation, .. } => {
            assert_eq!(name, "maybe");
            match type_annotation {
                Some(TypeAnnotation::Union(types)) => {
                    assert_eq!(types.len(), 2);
                    assert_eq!(types[0], TypeAnnotation::Number);
                    assert_eq!(types[1], TypeAnnotation::Null);
                }
                _ => panic!("Expected Union type annotation"),
            }
        }
        _ => panic!("Expected VariableDecl"),
    }
}

// ============================================================================
// Lambda Type Annotation Tests
// ============================================================================

#[test]
fn test_lambda_with_typed_params() {
    let result = parse("(x: Number, y: Number) => x + y");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { params, return_type, .. } => {
            assert_eq!(params.len(), 2);

            // First parameter
            assert_eq!(params[0].0, "x");
            assert_eq!(params[0].1, Some(TypeAnnotation::Number));

            // Second parameter
            assert_eq!(params[1].0, "y");
            assert_eq!(params[1].1, Some(TypeAnnotation::Number));

            // No return type specified
            assert_eq!(return_type, &None);
        }
        _ => panic!("Expected Lambda, got {:?}", ast[0]),
    }
}

#[test]
fn test_lambda_with_partial_typing() {
    let result = parse("(a: Number, b) => a + b");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { params, .. } => {
            assert_eq!(params.len(), 2);

            // First parameter is typed
            assert_eq!(params[0].0, "a");
            assert_eq!(params[0].1, Some(TypeAnnotation::Number));

            // Second parameter is untyped
            assert_eq!(params[1].0, "b");
            assert_eq!(params[1].1, None);
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_lambda_with_return_type() {
    let result = parse("(x: Number, y: Number): Number => x + y");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { params, return_type, .. } => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].1, Some(TypeAnnotation::Number));
            assert_eq!(params[1].1, Some(TypeAnnotation::Number));
            assert_eq!(return_type, &Some(TypeAnnotation::Number));
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_lambda_no_types() {
    let result = parse("(x, y) => x + y");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { params, return_type, .. } => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].1, None);
            assert_eq!(params[1].1, None);
            assert_eq!(return_type, &None);
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_lambda_single_typed_param() {
    let result = parse("x: Number => x^2");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { params, return_type, .. } => {
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].0, "x");
            assert_eq!(params[0].1, Some(TypeAnnotation::Number));
            assert_eq!(return_type, &None);
        }
        _ => panic!("Expected Lambda"),
    }
}

#[test]
fn test_lambda_with_union_param_type() {
    let result = parse("(x: Number | Complex) => x^2");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { params, .. } => {
            assert_eq!(params.len(), 1);
            match &params[0].1 {
                Some(TypeAnnotation::Union(types)) => {
                    assert_eq!(types.len(), 2);
                    assert_eq!(types[0], TypeAnnotation::Number);
                    assert_eq!(types[1], TypeAnnotation::Complex);
                }
                _ => panic!("Expected Union type"),
            }
        }
        _ => panic!("Expected Lambda"),
    }
}

// ============================================================================
// Complex Type Annotation Tests
// ============================================================================

#[test]
fn test_let_with_tensor_type() {
    let result = parse("let matrix: Tensor<Number, [2, 3]> = [[1, 2, 3], [4, 5, 6]]");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableDecl { type_annotation, .. } => {
            match type_annotation {
                Some(TypeAnnotation::Tensor { element_type, shape }) => {
                    assert_eq!(**element_type, TypeAnnotation::Number);
                    assert_eq!(shape, &Some(vec![Some(2), Some(3)]));
                }
                _ => panic!("Expected Tensor type annotation"),
            }
        }
        _ => panic!("Expected VariableDecl"),
    }
}

#[test]
fn test_let_with_tensor_no_shape() {
    let result = parse("let data: Tensor<Complex> = [[1i, 2i], [3i, 4i]]");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableDecl { type_annotation, .. } => {
            match type_annotation {
                Some(TypeAnnotation::Tensor { element_type, shape }) => {
                    assert_eq!(**element_type, TypeAnnotation::Complex);
                    assert_eq!(shape, &None);
                }
                _ => panic!("Expected Tensor type annotation"),
            }
        }
        _ => panic!("Expected VariableDecl"),
    }
}

#[test]
fn test_lambda_with_function_return_type() {
    // Use correct function type syntax: (Number): Number
    let result = parse("(): ((Number): Number) => (x: Number) => x^2");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Lambda { return_type, .. } => {
            match return_type {
                Some(TypeAnnotation::Function { params, return_type }) => {
                    assert_eq!(params.len(), 1);
                    assert_eq!(params[0], Some(TypeAnnotation::Number));
                    assert_eq!(**return_type, TypeAnnotation::Number);
                }
                _ => panic!("Expected Function type annotation"),
            }
        }
        _ => panic!("Expected Lambda"),
    }
}

// ============================================================================
// Integration Tests (Type Annotations in Complex Expressions)
// ============================================================================

#[test]
fn test_sequence_with_types() {
    let result = parse("let x: Number = 10; mut y: String = \"hello\"; y");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 3);

            // First statement: let x: Number = 10
            match &statements[0] {
                AstNode::VariableDecl { name, type_annotation, .. } => {
                    assert_eq!(name, "x");
                    assert_eq!(type_annotation, &Some(TypeAnnotation::Number));
                }
                _ => panic!("Expected VariableDecl"),
            }

            // Second statement: mut y: String = "hello"
            match &statements[1] {
                AstNode::MutableDecl { name, type_annotation, .. } => {
                    assert_eq!(name, "y");
                    assert_eq!(type_annotation, &Some(TypeAnnotation::String));
                }
                _ => panic!("Expected MutableDecl"),
            }
        }
        _ => panic!("Expected Sequence"),
    }
}

#[test]
fn test_higher_order_function_with_types() {
    // Use correct function type syntax: ((Number): Number, Vector): Vector
    let result = parse("let map: (((Number): Number), Vector): Vector = (f, v) => v");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableDecl { name, type_annotation, .. } => {
            assert_eq!(name, "map");
            match type_annotation {
                Some(TypeAnnotation::Function { params, return_type }) => {
                    assert_eq!(params.len(), 2);

                    // First param: (Number): Number
                    match &params[0] {
                        Some(TypeAnnotation::Function { params: inner_params, return_type: inner_return }) => {
                            assert_eq!(inner_params.len(), 1);
                            assert_eq!(inner_params[0], Some(TypeAnnotation::Number));
                            assert_eq!(**inner_return, TypeAnnotation::Number);
                        }
                        _ => panic!("Expected Function type for first param"),
                    }

                    // Second param: Vector
                    assert_eq!(params[1], Some(TypeAnnotation::Vector));

                    // Return type: Vector
                    assert_eq!(**return_type, TypeAnnotation::Vector);
                }
                _ => panic!("Expected Function type annotation"),
            }
        }
        _ => panic!("Expected VariableDecl"),
    }
}
