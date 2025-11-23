use achronyme_parser::{ast::*, parse};

#[test]
fn test_parse_mut_statement() {
    let result = parse("mut x = 10");
    assert!(result.is_ok());

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::MutableDecl {
            name, initializer, ..
        } => {
            assert_eq!(name, "x");
            match **initializer {
                AstNode::Number(n) => assert_eq!(n, 10.0),
                _ => panic!("Expected Number in initializer"),
            }
        }
        _ => panic!("Expected MutableDecl, got {:?}", ast[0]),
    }
}

#[test]
fn test_parse_mut_with_expression() {
    let result = parse("mut count = 5 + 3");
    assert!(result.is_ok());

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::MutableDecl { name, .. } => {
            assert_eq!(name, "count");
        }
        _ => panic!("Expected MutableDecl"),
    }
}

#[test]
fn test_parse_assignment_simple() {
    let result = parse("x = 20");
    assert!(result.is_ok());

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::Assignment { target, value } => {
            // Target should be a VariableRef
            match &**target {
                AstNode::VariableRef(name) => assert_eq!(name, "x"),
                _ => panic!("Expected VariableRef as target, got {:?}", target),
            }

            // Value should be Number
            match &**value {
                AstNode::Number(n) => assert_eq!(*n, 20.0),
                _ => panic!("Expected Number as value"),
            }
        }
        _ => panic!("Expected Assignment, got {:?}", ast[0]),
    }
}

#[test]
fn test_parse_assignment_field_access() {
    let result = parse("config.valor = 30");
    assert!(result.is_ok());

    let ast = result.unwrap();
    assert_eq!(ast.len(), 1);

    match &ast[0] {
        AstNode::Assignment { target, value } => {
            // Target should be FieldAccess
            match &**target {
                AstNode::FieldAccess { record, field } => {
                    match &**record {
                        AstNode::VariableRef(name) => assert_eq!(name, "config"),
                        _ => panic!("Expected VariableRef in field access"),
                    }
                    assert_eq!(field, "valor");
                }
                _ => panic!("Expected FieldAccess as target, got {:?}", target),
            }

            match &**value {
                AstNode::Number(n) => assert_eq!(*n, 30.0),
                _ => panic!("Expected Number as value"),
            }
        }
        _ => panic!("Expected Assignment"),
    }
}

#[test]
fn test_parse_assignment_nested_fields() {
    let result = parse("app.config.debug = true");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Assignment { target, value } => {
            // Should parse as nested field access
            match &**target {
                AstNode::FieldAccess { field, .. } => {
                    assert_eq!(field, "debug");
                }
                _ => panic!("Expected FieldAccess"),
            }

            match &**value {
                AstNode::Boolean(b) => assert_eq!(*b, true),
                _ => panic!("Expected Boolean"),
            }
        }
        _ => panic!("Expected Assignment"),
    }
}

#[test]
fn test_parse_assignment_array_index() {
    let result = parse("arr[0] = 100");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Assignment { target, value } => {
            // Target should be IndexAccess
            match &**target {
                AstNode::IndexAccess { object, indices } => {
                    match &**object {
                        AstNode::VariableRef(name) => assert_eq!(name, "arr"),
                        _ => panic!("Expected VariableRef"),
                    }
                    assert_eq!(indices.len(), 1);
                }
                _ => panic!("Expected IndexAccess as target, got {:?}", target),
            }

            match &**value {
                AstNode::Number(n) => assert_eq!(*n, 100.0),
                _ => panic!("Expected Number"),
            }
        }
        _ => panic!("Expected Assignment"),
    }
}

#[test]
fn test_parse_record_with_mutable_field() {
    let result = parse("{mut valor: 10, inmutable: 20}");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::RecordLiteral(fields) => {
            assert_eq!(fields.len(), 2);

            // First field should be mutable
            match &fields[0] {
                RecordFieldOrSpread::MutableField { name, value } => {
                    assert_eq!(name, "valor");
                    match value {
                        AstNode::Number(n) => assert_eq!(*n, 10.0),
                        _ => panic!("Expected Number"),
                    }
                }
                _ => panic!("Expected MutableField, got {:?}", fields[0]),
            }

            // Second field should be immutable
            match &fields[1] {
                RecordFieldOrSpread::Field { name, value } => {
                    assert_eq!(name, "inmutable");
                    match value {
                        AstNode::Number(n) => assert_eq!(*n, 20.0),
                        _ => panic!("Expected Number"),
                    }
                }
                _ => panic!("Expected Field"),
            }
        }
        _ => panic!("Expected RecordLiteral"),
    }
}

#[test]
fn test_parse_record_only_mutable_fields() {
    let result = parse("{mut x: 1, mut y: 2}");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::RecordLiteral(fields) => {
            assert_eq!(fields.len(), 2);

            for field in fields {
                match field {
                    RecordFieldOrSpread::MutableField { .. } => {}
                    _ => panic!("Expected all fields to be mutable"),
                }
            }
        }
        _ => panic!("Expected RecordLiteral"),
    }
}

#[test]
fn test_parse_sequence_mut_and_assignment() {
    let result = parse("mut x = 10; x = 20; x");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 3);

            // First: mut declaration
            match &statements[0] {
                AstNode::MutableDecl { name, .. } => assert_eq!(name, "x"),
                _ => panic!("Expected MutableDecl"),
            }

            // Second: assignment
            match &statements[1] {
                AstNode::Assignment { .. } => {}
                _ => panic!("Expected Assignment"),
            }

            // Third: variable reference
            match &statements[2] {
                AstNode::VariableRef(name) => assert_eq!(name, "x"),
                _ => panic!("Expected VariableRef"),
            }
        }
        _ => panic!("Expected Sequence"),
    }
}

#[test]
fn test_parse_mut_not_confused_with_identifier() {
    // "mut" should be a keyword, not an identifier
    // This should parse as a variable reference, not a mut statement
    let result = parse("mutant");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::VariableRef(name) => assert_eq!(name, "mutant"),
        _ => panic!("Expected VariableRef for 'mutant'"),
    }
}

#[test]
fn test_parse_assignment_complex_expression() {
    let result = parse("state.values[0].count = getData().process()");
    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::Assignment { target, value } => {
            // Target should be complex postfix expression
            // We just verify it parses, detailed structure varies
            match &**value {
                AstNode::CallExpression { .. } => {}
                _ => panic!("Expected CallExpression in value"),
            }
        }
        _ => panic!("Expected Assignment"),
    }
}

#[test]
fn test_parse_record_with_mutable_method() {
    // Note: assignments in lambda bodies require do blocks
    let result = parse(
        r#"{
        mut valor: 0,
        incrementar: () => do { self.valor = self.valor + 1 }
    }"#,
    );

    if let Err(ref e) = result {
        eprintln!("Parse error: {}", e);
    }

    assert!(result.is_ok());

    let ast = result.unwrap();
    match &ast[0] {
        AstNode::RecordLiteral(fields) => {
            assert_eq!(fields.len(), 2);

            // First field: mutable valor
            match &fields[0] {
                RecordFieldOrSpread::MutableField { name, .. } => {
                    assert_eq!(name, "valor");
                }
                _ => panic!("Expected MutableField"),
            }

            // Second field: incrementar method with assignment inside
            match &fields[1] {
                RecordFieldOrSpread::Field { name, value } => {
                    assert_eq!(name, "incrementar");
                    match value {
                        AstNode::Lambda { body, .. } => {
                            // Body should be a DoBlock containing assignment
                            match &**body {
                                AstNode::DoBlock { statements } => {
                                    assert!(statements.len() > 0);
                                    match &statements[0] {
                                        AstNode::Assignment { .. } => {}
                                        _ => panic!("Expected Assignment in do block"),
                                    }
                                }
                                _ => panic!("Expected DoBlock in lambda body"),
                            }
                        }
                        _ => panic!("Expected Lambda"),
                    }
                }
                _ => panic!("Expected Field"),
            }
        }
        _ => panic!("Expected RecordLiteral"),
    }
}
