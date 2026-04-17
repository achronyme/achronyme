//! Scanners for literal tokens: numbers (decimal + hex), strings, and
//! identifiers/keywords.
//!
//! These methods are invoked from `next_token` in `dispatch.rs` after a
//! one-byte lookahead classifies the opening character.

use diagnostics::ParseError;

use super::Lexer;
use crate::token::{lookup_keyword, Token, TokenKind};

impl<'a> Lexer<'a> {
    pub(super) fn lex_number(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        // Check for hex prefix: 0x
        if self.peek() == Some(b'0') && self.peek2() == Some(b'x') {
            self.advance(); // '0'
            self.advance(); // 'x'
            let digit_start = self.pos;
            while let Some(ch) = self.peek() {
                if ch.is_ascii_hexdigit() {
                    self.advance();
                } else {
                    break;
                }
            }
            if self.pos == digit_start {
                return Err(ParseError::with_code(
                    "expected hex digits after `0x`",
                    "E302",
                    start.1,
                    start.2,
                ));
            }
            let lexeme = std::str::from_utf8(&self.source[start.0..self.pos])
                .map_err(|_| ParseError::with_code("invalid UTF-8", "E302", start.1, start.2))?
                .to_string();
            return Ok(Token {
                kind: TokenKind::HexNumber,
                span: self.make_span(start),
                lexeme,
            });
        }

        // Decimal number
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }
        let lexeme = std::str::from_utf8(&self.source[start.0..self.pos])
            .map_err(|_| ParseError::with_code("invalid UTF-8", "E302", start.1, start.2))?
            .to_string();
        Ok(Token {
            kind: TokenKind::DecNumber,
            span: self.make_span(start),
            lexeme,
        })
    }

    pub(super) fn lex_ident(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        // Circom identifiers: [$_]*[a-zA-Z][a-zA-Z$_0-9]*
        // We accept the broader pattern: starts with alpha, _, or $
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'$' {
                self.advance();
            } else {
                break;
            }
        }
        let lexeme = std::str::from_utf8(&self.source[start.0..self.pos])
            .map_err(|_| ParseError::with_code("invalid UTF-8", "E302", start.1, start.2))?
            .to_string();

        // Check for underscore-only identifier → Underscore token
        if lexeme == "_" {
            return Ok(Token {
                kind: TokenKind::Underscore,
                span: self.make_span(start),
                lexeme,
            });
        }

        let kind = lookup_keyword(&lexeme).unwrap_or(TokenKind::Ident);
        Ok(Token {
            kind,
            span: self.make_span(start),
            lexeme,
        })
    }

    pub(super) fn lex_string(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        self.advance(); // consume opening "
        let mut buf = String::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => {
                    return Err(ParseError::with_code(
                        "unterminated string literal",
                        "E301",
                        start.1,
                        start.2,
                    ));
                }
                Some(b'"') => {
                    self.advance(); // consume closing "
                    return Ok(Token {
                        kind: TokenKind::StringLit,
                        span: self.make_span(start),
                        lexeme: buf,
                    });
                }
                Some(b'\\') => {
                    self.advance(); // consume backslash
                    match self.peek() {
                        Some(b'n') => {
                            self.advance();
                            buf.push('\n');
                        }
                        Some(b't') => {
                            self.advance();
                            buf.push('\t');
                        }
                        Some(b'r') => {
                            self.advance();
                            buf.push('\r');
                        }
                        Some(b'\\') => {
                            self.advance();
                            buf.push('\\');
                        }
                        Some(b'"') => {
                            self.advance();
                            buf.push('"');
                        }
                        Some(b'0') => {
                            self.advance();
                            buf.push('\0');
                        }
                        Some(ch) => {
                            return Err(ParseError::with_code(
                                format!("invalid escape sequence `\\{}`", ch as char),
                                "E303",
                                self.line,
                                self.col,
                            ));
                        }
                        None => {
                            return Err(ParseError::with_code(
                                "unterminated string literal",
                                "E301",
                                start.1,
                                start.2,
                            ));
                        }
                    }
                }
                Some(ch) => {
                    self.advance();
                    buf.push(ch as char);
                }
            }
        }
    }
}
