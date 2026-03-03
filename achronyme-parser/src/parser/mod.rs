/// Recursive descent parser with Pratt expression parsing for Achronyme.
///
/// Drop-in replacement for `build_ast::parse_program` / `build_ast::parse_block`.
use crate::ast::*;
use crate::error::ParseError;
use crate::lexer::Lexer;

mod core;
mod exprs;
mod stmts;
mod tables;

#[cfg(test)]
mod tests;

use core::Parser;

/// Parse a complete source string into an AST Program.
///
/// ```
/// use achronyme_parser::parse_program;
///
/// let prog = parse_program("let x = 1 + 2").unwrap();
/// assert_eq!(prog.stmts.len(), 1);
/// ```
pub fn parse_program(source: &str) -> Result<Program, String> {
    let tokens = Lexer::tokenize(source).map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_program().map_err(|e| e.to_string())
}

/// Parse a block source (including braces) into an AST Block.
///
/// ```
/// use achronyme_parser::parse_program;
/// use achronyme_parser::ast::Stmt;
///
/// let prog = parse_program("public x\nwitness y\nassert_eq(x, y)").unwrap();
/// assert_eq!(prog.stmts.len(), 3);
/// assert!(matches!(&prog.stmts[0], Stmt::PublicDecl { .. }));
/// assert!(matches!(&prog.stmts[1], Stmt::WitnessDecl { .. }));
/// ```
/// Parse a complete source string, returning a structured [`ParseError`] on failure.
pub fn parse_program_with_errors(source: &str) -> Result<Program, ParseError> {
    let tokens = Lexer::tokenize(source)?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_program()
}

pub fn parse_block(source: &str) -> Result<Block, String> {
    let tokens = Lexer::tokenize(source).map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_block().map_err(|e| e.to_string())
}
