use achronyme_parser::{
    ast::{AstNode, ImportItem},
    parse,
};

#[test]
fn test_simple_import() {
    let input = r#"import { sin, cos } from "math""#;
    let result = parse(input);

    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let statements = result.unwrap();
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::Import { items, module_path } => {
            assert_eq!(module_path, "math");
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].name, "sin");
            assert_eq!(items[0].alias, None);
            assert_eq!(items[1].name, "cos");
            assert_eq!(items[1].alias, None);
        }
        _ => panic!("Expected Import node, got {:?}", statements[0]),
    }
}

#[test]
fn test_import_with_alias() {
    let input = r#"import { mean as average, std } from "stats""#;
    let result = parse(input);

    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let statements = result.unwrap();
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::Import { items, module_path } => {
            assert_eq!(module_path, "stats");
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].name, "mean");
            assert_eq!(items[0].alias, Some("average".to_string()));
            assert_eq!(items[1].name, "std");
            assert_eq!(items[1].alias, None);
        }
        _ => panic!("Expected Import node"),
    }
}

#[test]
fn test_import_from_relative_path() {
    let input = r#"import { helper } from "./utils""#;
    let result = parse(input);

    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let statements = result.unwrap();
    match &statements[0] {
        AstNode::Import { module_path, .. } => {
            assert_eq!(module_path, "./utils");
        }
        _ => panic!("Expected Import node"),
    }
}

#[test]
fn test_export_statement() {
    let input = r#"export { foo, bar }"#;
    let result = parse(input);

    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let statements = result.unwrap();
    assert_eq!(statements.len(), 1);

    match &statements[0] {
        AstNode::Export { items } => {
            assert_eq!(items.len(), 2);
            assert_eq!(items[0].name, "foo");
            assert_eq!(items[1].name, "bar");
        }
        _ => panic!("Expected Export node"),
    }
}

#[test]
fn test_import_with_usage() {
    let input = r#"
    import { mean } from "stats"
    let result = mean([1, 2, 3])
    "#;

    let result = parse(input);
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let top_level = result.unwrap();
    assert_eq!(top_level.len(), 1);

    // Should be a sequence with 2 statements
    match &top_level[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 2);

            // First statement should be import
            match &statements[0] {
                AstNode::Import { items, module_path } => {
                    assert_eq!(module_path, "stats");
                    assert_eq!(items[0].name, "mean");
                }
                _ => panic!("Expected Import node as first statement"),
            }

            // Second statement should be let
            match &statements[1] {
                AstNode::VariableDecl { name, .. } => {
                    assert_eq!(name, "result");
                }
                _ => panic!("Expected VariableDecl node as second statement"),
            }
        }
        _ => panic!("Expected Sequence node at top level"),
    }
}

#[test]
fn test_multiple_imports() {
    let input = r#"
    import { sin, cos } from "math"
    import { mean, std } from "stats"
    let x = sin(pi)
    "#;

    let result = parse(input);
    assert!(result.is_ok(), "Parse failed: {:?}", result.err());

    let top_level = result.unwrap();
    assert_eq!(top_level.len(), 1);

    // Should be a sequence with 3 statements
    match &top_level[0] {
        AstNode::Sequence { statements } => {
            assert_eq!(statements.len(), 3);

            // Check first import
            match &statements[0] {
                AstNode::Import { module_path, .. } => {
                    assert_eq!(module_path, "math");
                }
                _ => panic!("Expected first Import node"),
            }

            // Check second import
            match &statements[1] {
                AstNode::Import { module_path, .. } => {
                    assert_eq!(module_path, "stats");
                }
                _ => panic!("Expected second Import node"),
            }
        }
        _ => panic!("Expected Sequence node at top level"),
    }
}

#[test]
fn test_import_item_local_name() {
    let item_with_alias = ImportItem {
        name: "mean".to_string(),
        alias: Some("average".to_string()),
    };
    assert_eq!(item_with_alias.local_name(), "average");

    let item_without_alias = ImportItem {
        name: "mean".to_string(),
        alias: None,
    };
    assert_eq!(item_without_alias.local_name(), "mean");
}

#[test]
fn test_import_reserved_keyword_prevention() {
    // "import" itself should not be usable as an identifier
    let input = "let import = 5";
    let result = parse(input);
    assert!(result.is_err(), "Should not allow 'import' as identifier");
}
