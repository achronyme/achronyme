/// Recursive descent parser with Pratt expression parsing for Achronyme.
use crate::ast::*;
use crate::diagnostic::Diagnostic;
use crate::lexer::Lexer;

mod core;
mod exprs;
mod stmts;
mod tables;

#[cfg(test)]
mod tests;

use core::Parser;

/// Parse a complete source string, collecting multiple errors via recovery.
///
/// Returns the (possibly partial) AST and all diagnostics. Failed regions
/// appear as `Stmt::Error` nodes in the AST.
///
/// ```
/// use achronyme_parser::parse_program;
///
/// let (prog, errors) = parse_program("let x = 1 + 2");
/// assert!(errors.is_empty());
/// assert_eq!(prog.stmts.len(), 1);
/// ```
pub fn parse_program(source: &str) -> (Program, Vec<Diagnostic>) {
    match Lexer::tokenize(source) {
        Ok(tokens) => {
            let mut parser = Parser::new(tokens, source.to_string());
            let program = parser
                .do_parse_program()
                .unwrap_or_else(|_| Program { stmts: Vec::new() });
            let errors = parser.take_errors();
            (program, errors)
        }
        Err(lex_err) => {
            let diag: Diagnostic = lex_err.into();
            (Program { stmts: Vec::new() }, vec![diag])
        }
    }
}

/// Parse a block source (including braces) into an AST Block.
///
/// ```
/// use achronyme_parser::parse_program;
/// use achronyme_parser::ast::Stmt;
///
/// let (prog, errors) = parse_program("public x\nwitness y\nassert_eq(x, y)");
/// assert!(errors.is_empty());
/// assert_eq!(prog.stmts.len(), 3);
/// assert!(matches!(&prog.stmts[0], Stmt::PublicDecl { .. }));
/// assert!(matches!(&prog.stmts[1], Stmt::WitnessDecl { .. }));
/// ```
pub fn parse_block(source: &str) -> Result<Block, String> {
    let tokens = Lexer::tokenize(source).map_err(|e| e.to_string())?;
    let mut parser = Parser::new(tokens, source.to_string());
    parser.do_parse_block().map_err(|e| e.to_string())
}
