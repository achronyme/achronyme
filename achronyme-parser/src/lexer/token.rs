use super::*;

impl<'a> Lexer<'a> {
    pub(super) fn next_token(&mut self) -> Result<Token, ParseError> {
        self.skip_whitespace_and_comments()?;

        let start = self.start_pos();

        let Some(ch) = self.peek() else {
            return Ok(Token {
                kind: TokenKind::Eof,
                span: self.make_span(start),
                lexeme: String::new(),
            });
        };

        // Numbers
        if ch.is_ascii_digit() {
            return self.lex_number(start);
        }

        // Identifiers and keywords
        if ch.is_ascii_alphabetic() || ch == b'_' {
            return self.lex_ident(start);
        }

        // Strings
        if ch == b'"' {
            return self.lex_string(start);
        }

        // Multi-character operators
        match ch {
            b'=' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::Eq,
                        span: self.make_span(start),
                        lexeme: "==".into(),
                    });
                }
                return Ok(Token {
                    kind: TokenKind::Assign,
                    span: self.make_span(start),
                    lexeme: "=".into(),
                });
            }
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::Neq,
                        span: self.make_span(start),
                        lexeme: "!=".into(),
                    });
                }
                return Ok(Token {
                    kind: TokenKind::Not,
                    span: self.make_span(start),
                    lexeme: "!".into(),
                });
            }
            b'<' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::Le,
                        span: self.make_span(start),
                        lexeme: "<=".into(),
                    });
                }
                return Ok(Token {
                    kind: TokenKind::Lt,
                    span: self.make_span(start),
                    lexeme: "<".into(),
                });
            }
            b'>' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::Ge,
                        span: self.make_span(start),
                        lexeme: ">=".into(),
                    });
                }
                return Ok(Token {
                    kind: TokenKind::Gt,
                    span: self.make_span(start),
                    lexeme: ">".into(),
                });
            }
            b'&' => {
                self.advance();
                if self.peek() == Some(b'&') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::And,
                        span: self.make_span(start),
                        lexeme: "&&".into(),
                    });
                }
                return Err(ParseError::new(
                    "unexpected character `&`",
                    start.1,
                    start.2,
                ));
            }
            b'|' => {
                self.advance();
                if self.peek() == Some(b'|') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::Or,
                        span: self.make_span(start),
                        lexeme: "||".into(),
                    });
                }
                return Err(ParseError::new(
                    "unexpected character `|`",
                    start.1,
                    start.2,
                ));
            }
            b'-' => {
                self.advance();
                if self.peek() == Some(b'>') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::Arrow,
                        span: self.make_span(start),
                        lexeme: "->".into(),
                    });
                }
                return Ok(Token {
                    kind: TokenKind::Minus,
                    span: self.make_span(start),
                    lexeme: "-".into(),
                });
            }
            b'.' => {
                self.advance();
                if self.peek() == Some(b'.') {
                    self.advance();
                    return Ok(Token {
                        kind: TokenKind::DotDot,
                        span: self.make_span(start),
                        lexeme: "..".into(),
                    });
                }
                return Ok(Token {
                    kind: TokenKind::Dot,
                    span: self.make_span(start),
                    lexeme: ".".into(),
                });
            }
            _ => {}
        }

        // Single-character tokens
        self.advance();
        let (kind, lexeme) = match ch {
            b'+' => (TokenKind::Plus, "+"),
            b'*' => (TokenKind::Star, "*"),
            b'/' => (TokenKind::Slash, "/"),
            b'%' => (TokenKind::Percent, "%"),
            b'^' => (TokenKind::Caret, "^"),
            b'(' => (TokenKind::LParen, "("),
            b')' => (TokenKind::RParen, ")"),
            b'[' => (TokenKind::LBracket, "["),
            b']' => (TokenKind::RBracket, "]"),
            b'{' => (TokenKind::LBrace, "{"),
            b'}' => (TokenKind::RBrace, "}"),
            b',' => (TokenKind::Comma, ","),
            b':' => {
                if self.peek() == Some(b':') {
                    self.advance();
                    (TokenKind::ColonColon, "::")
                } else {
                    (TokenKind::Colon, ":")
                }
            }
            b';' => (TokenKind::Semicolon, ";"),
            _ => {
                return Err(ParseError::new(
                    format!("unexpected character `{}`", ch as char),
                    start.1,
                    start.2,
                ));
            }
        };
        Ok(Token {
            kind,
            span: self.make_span(start),
            lexeme: lexeme.into(),
        })
    }
}
