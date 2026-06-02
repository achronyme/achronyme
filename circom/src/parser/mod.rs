//! Circom parser — hand-written recursive descent with Pratt expression parsing.
//!
//! Public API: [`parse_circom`] parses a complete `.circom` file.

mod core;
mod exprs;
mod stmts;
mod tables;

use diagnostics::{Diagnostic, ParseError};

use crate::ast::CircomProgram;
use crate::lexer::Lexer;

/// Parse a complete Circom source file.
///
/// Returns `(program, diagnostics)`. On partial failure, the program may
/// contain `Stmt::Error` / `Expr::Error` placeholders and the diagnostics
/// will list the errors encountered.
pub fn parse_circom(source: &str) -> Result<(CircomProgram, Vec<Diagnostic>), ParseError> {
    let tokens = Lexer::tokenize(source)?;
    let mut parser = core::Parser::new(tokens);
    let program = parser.do_parse_program()?;
    let errors = parser.take_errors();
    Ok((program, errors))
}

#[cfg(test)]
mod tests;
