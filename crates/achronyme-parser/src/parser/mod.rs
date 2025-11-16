use pest::iterators::Pair;
use crate::ast::AstNode;
use crate::pest_parser::Rule;

pub mod statements;
pub mod expressions;
pub mod primary;
pub mod collections;
pub mod control_flow;
pub mod functions;
pub mod util;
pub mod type_parser;
pub mod pattern;

// ============================================================================
// AST Parser Struct
// ============================================================================

pub struct AstParser;

impl AstParser {
    pub(crate) fn new() -> Self {
        AstParser
    }

    pub(crate) fn parse_program(&mut self, pair: Pair<Rule>) -> Result<Vec<AstNode>, String> {
        let mut statements = Vec::new();
        for inner_pair in pair.into_inner() {
            match inner_pair.as_rule() {
                Rule::top_level_expr => {
                    statements.push(self.build_ast_from_top_level_expr(inner_pair)?);
                }
                Rule::statement => {
                    // For backward compatibility (shouldn't happen with new grammar)
                    statements.push(self.build_ast_from_statement(inner_pair)?);
                }
                Rule::EOI => {} // End of input, ignore
                _ => {}
            }
        }
        Ok(statements)
    }

    // Build AST from top_level_expr (either sequence or statement)
    fn build_ast_from_top_level_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let inner = pair.into_inner().next()
            .ok_or("Empty top_level_expr")?;

        match inner.as_rule() {
            Rule::sequence => self.build_sequence(inner),
            Rule::statement => self.build_ast_from_statement(inner),
            _ => Err(format!("Unexpected top_level_expr rule: {:?}", inner.as_rule()))
        }
    }

    // Build AST from sequence
    fn build_sequence(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut statements = Vec::new();

        for inner_pair in pair.into_inner() {
            match inner_pair.as_rule() {
                Rule::statement => {
                    statements.push(self.build_ast_from_statement(inner_pair)?);
                }
                _ => {}
            }
        }

        if statements.is_empty() {
            return Err("Empty sequence".to_string());
        }

        Ok(AstNode::Sequence { statements })
    }
}