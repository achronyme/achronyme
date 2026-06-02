/// Single-pass O(n) lexer for Achronyme source code.
mod cursor;
mod escape;
mod literal;
mod token;

#[cfg(test)]
mod tests;

use crate::ast::Span;
use crate::error::ParseError;
use crate::token::{Token, TokenKind};

pub use escape::unescape;

pub struct Lexer<'a> {
    source: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
}

impl<'a> Lexer<'a> {
    pub fn tokenize(source: &str) -> Result<Vec<Token>, ParseError> {
        let mut lexer = Lexer {
            source: source.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        };
        let mut tokens = Vec::new();
        loop {
            let tok = lexer.next_token()?;
            let is_eof = tok.kind == TokenKind::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }
}
