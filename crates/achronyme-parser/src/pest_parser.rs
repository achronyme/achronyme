// ============================================================================
// Pest-based Parser for Achronyme SOC Language
// ============================================================================
// This module uses Pest (PEG parser generator) to parse SOC expressions
// and generate the AST (Abstract Syntax Tree).
//
// The grammar is defined in grammar.pest.
// ============================================================================

use pest::Parser;
use pest_derive::Parser;

use crate::ast::AstNode;
use crate::parser::AstParser;

// ============================================================================
// Parser Definition
// ============================================================================

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct SOCParser;

// ============================================================================
// Public API
// ============================================================================

/// Parse a SOC expression string into an AST
pub fn parse(input: &str) -> Result<Vec<AstNode>, String> {
    let pairs =
        SOCParser::parse(Rule::program, input).map_err(|e| format!("Parse error: {}", e))?;

    // The unwrap is safe because a valid program will always have a `program` rule.
    let program_pair = pairs.into_iter().next().unwrap();

    AstParser::new().parse_program(program_pair)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::BinaryOp;

    #[test]
    fn test_parse_return_statement() {
        let result = parse("return 42");
        assert!(result.is_ok(), "Failed to parse: {:?}", result);

        let ast = result.unwrap();
        assert_eq!(ast.len(), 1);
        assert!(matches!(ast[0], AstNode::Return { .. }));
    }

    #[test]
    fn test_parse_number() {
        let result = parse("42").unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], AstNode::Number(42.0)));
    }

    #[test]
    fn test_parse_arithmetic() {
        let result = parse("2 + 3 * 4").unwrap();
        assert_eq!(result.len(), 1);
        // Should parse as: 2 + (3 * 4)

        // Verify the structure
        match &result[0] {
            AstNode::BinaryOp { op, left, right } => {
                assert!(matches!(op, BinaryOp::Add));
                assert!(matches!(**left, AstNode::Number(2.0)));
                // Right should be 3 * 4
                match &**right {
                    AstNode::BinaryOp { op: mult_op, .. } => {
                        assert!(matches!(mult_op, BinaryOp::Multiply));
                    }
                    _ => panic!("Expected multiplication on right side"),
                }
            }
            _ => panic!("Expected binary op at top level"),
        }
    }

    #[test]
    fn test_parse_power() {
        let result = parse("2^3^4").unwrap();
        assert_eq!(result.len(), 1);
        // Should parse as: 2^(3^4) - right associative
    }

    #[test]
    fn test_parse_vector() {
        let result = parse("[1, 2, 3]").unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], AstNode::ArrayLiteral(_)));
    }

    #[test]
    fn test_parse_lambda() {
        let result = parse("x => x^2").unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], AstNode::Lambda { .. }));
    }

    #[test]
    fn test_parse_function_call() {
        let result = parse("sin(PI)").unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], AstNode::CallExpression { .. }));
    }

    #[test]
    fn test_parse_let_statement() {
        let result = parse("let x = 42").unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], AstNode::VariableDecl { .. }));
    }

    #[test]
    fn test_parse_complex() {
        let result = parse("3i").unwrap();
        assert_eq!(result.len(), 1);
        assert!(matches!(
            result[0],
            AstNode::ComplexLiteral { re: 0.0, im: 3.0 }
        ));
    }

    #[test]
    fn test_parse_if_expr_with_else() {
        let result = parse("if(true) { 42 } else { 0 }");
        match result {
            Ok(ast) => {
                assert_eq!(ast.len(), 1);
                assert!(matches!(ast[0], AstNode::If { .. }));
            }
            Err(e) => {
                panic!("Failed to parse if expression: {}", e);
            }
        }
    }

    #[test]
    fn test_parse_if_expr_without_else() {
        let result = parse("if(x > 5) { 42 }");
        match result {
            Ok(ast) => {
                assert_eq!(ast.len(), 1);
                assert!(matches!(ast[0], AstNode::If { .. }));
            }
            Err(e) => {
                panic!("Failed to parse if expression without else: {}", e);
            }
        }
    }

    #[test]
    fn test_parse_if_expr_else_if() {
        let result = parse("if(x > 10) { 1 } else if(x > 5) { 2 } else { 3 }");
        match result {
            Ok(ast) => {
                assert_eq!(ast.len(), 1);
                assert!(matches!(ast[0], AstNode::If { .. }));
            }
            Err(e) => {
                panic!("Failed to parse else-if chain: {}", e);
            }
        }
    }

    #[test]
    fn test_parse_if_vs_function_call() {
        // if(x, y, z) should parse as a functional if, which becomes an If node
        let result = parse("if(true, 42, 0)");
        match result {
            Ok(ast) => {
                assert_eq!(ast.len(), 1);
                match &ast[0] {
                    AstNode::If { .. } => {
                        // Correct, functional if is converted to If node
                    }
                    _ => panic!(
                        "Expected If node for if(cond, then, else), got {:?}",
                        ast[0]
                    ),
                }
            }
            Err(e) => {
                panic!("Failed to parse functional if: {}", e);
            }
        }
    }
}
