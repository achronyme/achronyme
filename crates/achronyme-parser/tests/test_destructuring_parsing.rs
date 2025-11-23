use achronyme_parser::ast::{LiteralPattern, Pattern, VectorPatternElement};
use achronyme_parser::{parse, AstNode};

#[test]
fn test_parse_simple_record_destructuring() {
    let result = parse("let { x, y } = point").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring {
            pattern,
            type_annotation,
            initializer,
        } => {
            assert!(type_annotation.is_none());
            match pattern {
                Pattern::Record { fields } => {
                    assert_eq!(fields.len(), 2);
                    assert_eq!(fields[0].0, "x");
                    assert_eq!(fields[1].0, "y");
                }
                _ => panic!("Expected Record pattern"),
            }
            match initializer.as_ref() {
                AstNode::VariableRef(name) => assert_eq!(name, "point"),
                _ => panic!("Expected VariableRef"),
            }
        }
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_record_destructuring_with_renaming() {
    let result = parse("let { name: n, age: a } = person").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => {
            match pattern {
                Pattern::Record { fields } => {
                    assert_eq!(fields.len(), 2);
                    assert_eq!(fields[0].0, "name");
                    assert_eq!(fields[1].0, "age");
                    // Check that patterns are variables
                    match &fields[0].1 {
                        Pattern::Variable(name) => assert_eq!(name, "n"),
                        _ => panic!("Expected Variable pattern for 'n'"),
                    }
                    match &fields[1].1 {
                        Pattern::Variable(name) => assert_eq!(name, "a"),
                        _ => panic!("Expected Variable pattern for 'a'"),
                    }
                }
                _ => panic!("Expected Record pattern"),
            }
        }
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_simple_vector_destructuring() {
    let result = parse("let [a, b, c] = values").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Vector { elements } => {
                assert_eq!(elements.len(), 3);
            }
            _ => panic!("Expected Vector pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_vector_destructuring_with_rest() {
    let result = parse("let [head, ...tail] = list").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => {
            match pattern {
                Pattern::Vector { elements } => {
                    assert_eq!(elements.len(), 2);
                    match &elements[0] {
                        VectorPatternElement::Pattern(Pattern::Variable(name), default) => {
                            assert_eq!(name, "head");
                            assert!(default.is_none()); // No default
                        }
                        _ => panic!("Expected Variable pattern for head"),
                    }
                    match &elements[1] {
                        VectorPatternElement::Rest(name) => {
                            assert_eq!(name, "tail");
                        }
                        _ => panic!("Expected Rest pattern for tail"),
                    }
                }
                _ => panic!("Expected Vector pattern"),
            }
        }
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_vector_destructuring_with_wildcard() {
    let result = parse("let [first, _, third] = triple").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => {
            match pattern {
                Pattern::Vector { elements } => {
                    assert_eq!(elements.len(), 3);
                    match &elements[1] {
                        VectorPatternElement::Pattern(Pattern::Wildcard, default) => {
                            assert!(default.is_none()); // No default
                        }
                        _ => panic!("Expected Wildcard pattern"),
                    }
                }
                _ => panic!("Expected Vector pattern"),
            }
        }
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_mutable_record_destructuring() {
    let result = parse("mut { x, y } = point").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::MutableDestructuring { pattern, .. } => match pattern {
            Pattern::Record { fields } => {
                assert_eq!(fields.len(), 2);
            }
            _ => panic!("Expected Record pattern"),
        },
        _ => panic!("Expected MutableDestructuring"),
    }
}

#[test]
fn test_parse_mutable_vector_destructuring() {
    let result = parse("mut [a, b] = values").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::MutableDestructuring { pattern, .. } => match pattern {
            Pattern::Vector { elements } => {
                assert_eq!(elements.len(), 2);
            }
            _ => panic!("Expected Vector pattern"),
        },
        _ => panic!("Expected MutableDestructuring"),
    }
}

#[test]
fn test_parse_nested_record_destructuring() {
    let result = parse("let { user: { name: n } } = data").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Record { fields } => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].0, "user");
                match &fields[0].1 {
                    Pattern::Record {
                        fields: inner_fields,
                    } => {
                        assert_eq!(inner_fields.len(), 1);
                        assert_eq!(inner_fields[0].0, "name");
                        match &inner_fields[0].1 {
                            Pattern::Variable(name) => assert_eq!(name, "n"),
                            _ => panic!("Expected Variable pattern"),
                        }
                    }
                    _ => panic!("Expected nested Record pattern"),
                }
            }
            _ => panic!("Expected Record pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_destructuring_with_literal_pattern() {
    // Record patterns can have literal patterns for matching
    let result = parse("let { status: \"ok\", value: v } = result").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Record { fields } => {
                assert_eq!(fields.len(), 2);
                match &fields[0].1 {
                    Pattern::Literal(LiteralPattern::String(s)) => {
                        assert_eq!(s, "ok");
                    }
                    _ => panic!("Expected String literal pattern"),
                }
                match &fields[1].1 {
                    Pattern::Variable(name) => {
                        assert_eq!(name, "v");
                    }
                    _ => panic!("Expected Variable pattern"),
                }
            }
            _ => panic!("Expected Record pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_empty_record_destructuring() {
    let result = parse("let {} = empty").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Record { fields } => {
                assert_eq!(fields.len(), 0);
            }
            _ => panic!("Expected Record pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_empty_vector_destructuring() {
    let result = parse("let [] = empty").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Vector { elements } => {
                assert_eq!(elements.len(), 0);
            }
            _ => panic!("Expected Vector pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_simple_let_still_works() {
    // Ensure we haven't broken simple let statements
    let result = parse("let x = 42").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::VariableDecl {
            name,
            type_annotation,
            ..
        } => {
            assert_eq!(name, "x");
            assert!(type_annotation.is_none());
        }
        _ => panic!("Expected VariableDecl"),
    }
}

#[test]
fn test_parse_simple_mut_still_works() {
    // Ensure we haven't broken simple mut statements
    let result = parse("mut y = 100").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::MutableDecl {
            name,
            type_annotation,
            ..
        } => {
            assert_eq!(name, "y");
            assert!(type_annotation.is_none());
        }
        _ => panic!("Expected MutableDecl"),
    }
}

#[test]
fn test_parse_let_with_type_annotation_still_works() {
    let result = parse("let x: Number = 42").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::VariableDecl {
            name,
            type_annotation,
            ..
        } => {
            assert_eq!(name, "x");
            assert!(type_annotation.is_some());
        }
        _ => panic!("Expected VariableDecl"),
    }
}

#[test]
fn test_parse_multiple_statements_with_destructuring() {
    let result = parse(
        r#"
        let person = { name: "Alice", age: 30 }
        let { name, age } = person
        name
    "#,
    )
    .unwrap();

    // Parser wraps multiple statements in a Sequence node
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 3);
            match &statements[0] {
                AstNode::VariableDecl { name, .. } => assert_eq!(name, "person"),
                _ => panic!("Expected VariableDecl for first statement"),
            }
            match &statements[1] {
                AstNode::LetDestructuring { .. } => {}
                _ => panic!("Expected LetDestructuring for second statement"),
            }
            match &statements[2] {
                AstNode::VariableRef(name) => assert_eq!(name, "name"),
                _ => panic!("Expected VariableRef for third statement"),
            }
        }
        _ => panic!("Expected Sequence node"),
    }
}

// ==================== Default Value Parsing Tests ====================

#[test]
fn test_parse_record_destructuring_with_default() {
    let result = parse("let { name, age = 25 } = user").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => {
            match pattern {
                Pattern::Record { fields } => {
                    assert_eq!(fields.len(), 2);
                    // First field: no default
                    assert_eq!(fields[0].0, "name");
                    assert!(fields[0].2.is_none());
                    // Second field: has default
                    assert_eq!(fields[1].0, "age");
                    assert!(fields[1].2.is_some());
                    match fields[1].2.as_ref().unwrap().as_ref() {
                        AstNode::Number(n) => assert_eq!(*n, 25.0),
                        _ => panic!("Expected Number as default"),
                    }
                }
                _ => panic!("Expected Record pattern"),
            }
        }
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_vector_destructuring_with_default() {
    let result = parse("let [first = 0, second = 0] = arr").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Vector { elements } => {
                assert_eq!(elements.len(), 2);
                match &elements[0] {
                    VectorPatternElement::Pattern(Pattern::Variable(name), default) => {
                        assert_eq!(name, "first");
                        assert!(default.is_some());
                    }
                    _ => panic!("Expected Variable pattern with default"),
                }
                match &elements[1] {
                    VectorPatternElement::Pattern(Pattern::Variable(name), default) => {
                        assert_eq!(name, "second");
                        assert!(default.is_some());
                    }
                    _ => panic!("Expected Variable pattern with default"),
                }
            }
            _ => panic!("Expected Vector pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_record_destructuring_string_default() {
    let result = parse("let { name = \"Anonymous\" } = data").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => match pattern {
            Pattern::Record { fields } => {
                assert_eq!(fields.len(), 1);
                assert_eq!(fields[0].0, "name");
                assert!(fields[0].2.is_some());
                match fields[0].2.as_ref().unwrap().as_ref() {
                    AstNode::StringLiteral(s) => assert_eq!(s, "Anonymous"),
                    _ => panic!("Expected StringLiteral as default"),
                }
            }
            _ => panic!("Expected Record pattern"),
        },
        _ => panic!("Expected LetDestructuring"),
    }
}

#[test]
fn test_parse_record_destructuring_expression_default() {
    let result = parse("let { value = 10 * 2 } = data").unwrap();
    assert_eq!(result.len(), 1);

    match &result[0] {
        AstNode::LetDestructuring { pattern, .. } => {
            match pattern {
                Pattern::Record { fields } => {
                    assert_eq!(fields.len(), 1);
                    assert!(fields[0].2.is_some());
                    // Check that default is a BinaryOp (expression)
                    match fields[0].2.as_ref().unwrap().as_ref() {
                        AstNode::BinaryOp { .. } => {}
                        _ => panic!("Expected BinaryOp as default expression"),
                    }
                }
                _ => panic!("Expected Record pattern"),
            }
        }
        _ => panic!("Expected LetDestructuring"),
    }
}
