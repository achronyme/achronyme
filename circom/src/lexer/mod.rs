//! Single-pass O(n) lexer for Circom 2.x syntax.
//!
//! The [`Lexer`] struct and its `tokenize` entry point live here; the
//! rest of the state-machine is split by responsibility:
//!
//! - [`dispatch`] — the big `next_token` match that classifies the next
//!   byte and emits operator/delimiter tokens directly.
//! - [`literals`] — number, identifier/keyword, and string scanners.
//! - [`trivia`] — whitespace and comment skipping.
//!
//! All three attach their own `impl<'a> Lexer<'a>` blocks so the
//! primitive helpers below (`peek`, `advance`, `make_token`, …) stay
//! shared.

use diagnostics::{ParseError, Span};

use crate::token::{Token, TokenKind};

mod dispatch;
mod literals;
mod trivia;

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

    fn peek(&self) -> Option<u8> {
        self.source.get(self.pos).copied()
    }

    fn peek2(&self) -> Option<u8> {
        self.source.get(self.pos + 1).copied()
    }

    fn advance(&mut self) -> u8 {
        let ch = self.source[self.pos];
        self.pos += 1;
        if ch == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        ch
    }

    fn start_pos(&self) -> (usize, usize, usize) {
        (self.pos, self.line, self.col)
    }

    fn make_span(&self, start: (usize, usize, usize)) -> Span {
        Span {
            byte_start: start.0,
            byte_end: self.pos,
            line_start: start.1,
            col_start: start.2,
            line_end: self.line,
            col_end: self.col,
        }
    }

    fn make_token(&self, kind: TokenKind, start: (usize, usize, usize), lexeme: &str) -> Token {
        Token {
            kind,
            span: self.make_span(start),
            lexeme: lexeme.into(),
        }
    }
}

#[cfg(test)]
mod tests;
