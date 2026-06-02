use super::*;

impl<'a> Lexer<'a> {
    pub(super) fn lex_number(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        // Check for 0p field literal prefix
        if self.peek() == Some(b'0') && self.peek2() == Some(b'p') {
            self.advance(); // consume '0'
            self.advance(); // consume 'p'
            return self.lex_field_lit(start);
        }
        // Check for 0i bigint literal prefix
        if self.peek() == Some(b'0') && self.peek2() == Some(b'i') {
            self.advance(); // consume '0'
            self.advance(); // consume 'i'
            return self.lex_bigint_lit(start);
        }
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }
        let lexeme = self.ascii_str(&self.source[start.0..self.pos])?.to_string();
        Ok(Token {
            kind: TokenKind::Integer,
            span: self.make_span(start),
            lexeme,
        })
    }

    pub(super) fn lex_field_lit(
        &mut self,
        start: (usize, usize, usize),
    ) -> Result<Token, ParseError> {
        let next = self
            .peek()
            .ok_or_else(|| ParseError::new("expected digits after 0p", start.1, start.2))?;
        let lexeme = match next {
            b'x' => {
                self.advance(); // consume 'x'
                let digit_start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_hexdigit() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                if self.pos == digit_start {
                    return Err(ParseError::new(
                        "expected hex digits after 0px",
                        start.1,
                        start.2,
                    ));
                }
                let digits = self.ascii_str(&self.source[digit_start..self.pos])?;
                format!("x{digits}")
            }
            b'b' => {
                self.advance(); // consume 'b'
                let digit_start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch == b'0' || ch == b'1' {
                        self.advance();
                    } else {
                        break;
                    }
                }
                if self.pos == digit_start {
                    return Err(ParseError::new(
                        "expected binary digits after 0pb",
                        start.1,
                        start.2,
                    ));
                }
                let digits = self.ascii_str(&self.source[digit_start..self.pos])?;
                format!("b{digits}")
            }
            ch if ch.is_ascii_digit() => {
                let digit_start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                self.ascii_str(&self.source[digit_start..self.pos])?
                    .to_string()
            }
            _ => {
                return Err(ParseError::new(
                    "expected digits after 0p",
                    start.1,
                    start.2,
                ));
            }
        };
        Ok(Token {
            kind: TokenKind::FieldLit,
            span: self.make_span(start),
            lexeme,
        })
    }

    pub(super) fn lex_bigint_lit(
        &mut self,
        start: (usize, usize, usize),
    ) -> Result<Token, ParseError> {
        // Parse width: 256 or 512
        let width_start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.advance();
            } else {
                break;
            }
        }
        let width_str =
            std::str::from_utf8(&self.source[width_start..self.pos]).unwrap_or_default();
        if width_str != "256" && width_str != "512" {
            return Err(ParseError::new(
                format!("invalid BigInt width `{width_str}`, expected 256 or 512"),
                start.1,
                start.2,
            ));
        }

        // Parse radix char and digits
        let radix_ch = self.peek().ok_or_else(|| {
            ParseError::new(
                "expected radix (x/d/b) after BigInt width",
                start.1,
                start.2,
            )
        })?;
        let lexeme = match radix_ch {
            b'x' => {
                self.advance();
                let digit_start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_hexdigit() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                if self.pos == digit_start {
                    return Err(ParseError::new(
                        "expected hex digits after 0i<width>x",
                        start.1,
                        start.2,
                    ));
                }
                let digits = self.ascii_str(&self.source[digit_start..self.pos])?;
                format!("{width_str}x{digits}")
            }
            b'd' => {
                self.advance();
                let digit_start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                if self.pos == digit_start {
                    return Err(ParseError::new(
                        "expected decimal digits after 0i<width>d",
                        start.1,
                        start.2,
                    ));
                }
                let digits = self.ascii_str(&self.source[digit_start..self.pos])?;
                format!("{width_str}d{digits}")
            }
            b'b' => {
                self.advance();
                let digit_start = self.pos;
                while let Some(ch) = self.peek() {
                    if ch == b'0' || ch == b'1' {
                        self.advance();
                    } else {
                        break;
                    }
                }
                if self.pos == digit_start {
                    return Err(ParseError::new(
                        "expected binary digits after 0i<width>b",
                        start.1,
                        start.2,
                    ));
                }
                let digits = self.ascii_str(&self.source[digit_start..self.pos])?;
                format!("{width_str}b{digits}")
            }
            _ => {
                return Err(ParseError::new(
                    "expected radix (x/d/b) after BigInt width",
                    start.1,
                    start.2,
                ));
            }
        };
        Ok(Token {
            kind: TokenKind::BigIntLit,
            span: self.make_span(start),
            lexeme,
        })
    }

    pub(super) fn lex_ident(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        let lexeme = self.ascii_str(&self.source[start.0..self.pos])?.to_string();
        let kind = match lexeme.as_str() {
            "let" => TokenKind::Let,
            "mut" => TokenKind::Mut,
            "if" => TokenKind::If,
            "else" => TokenKind::Else,
            "while" => TokenKind::While,
            "for" => TokenKind::For,
            "in" => TokenKind::In,
            "fn" => TokenKind::Fn,
            "return" => TokenKind::Return,
            "break" => TokenKind::Break,
            "continue" => TokenKind::Continue,
            "print" => TokenKind::Print,
            "nil" => TokenKind::Nil,
            "true" => TokenKind::True,
            "false" => TokenKind::False,
            "public" => TokenKind::Public,
            "witness" => TokenKind::Witness,
            "prove" => TokenKind::Prove,
            "circuit" => TokenKind::Circuit,
            "forever" => TokenKind::Forever,
            "import" => TokenKind::Import,
            "export" => TokenKind::Export,
            "as" => TokenKind::As,
            _ => TokenKind::Ident,
        };
        Ok(Token {
            kind,
            span: self.make_span(start),
            lexeme,
        })
    }

    pub(super) fn lex_string(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        self.advance(); // consume opening "
        let mut value = String::new();
        loop {
            match self.peek() {
                None => {
                    return Err(ParseError::new(
                        "unterminated string literal",
                        start.1,
                        start.2,
                    ));
                }
                Some(b'"') => {
                    self.advance();
                    break;
                }
                Some(b'\\') => {
                    self.advance();
                    match self.peek() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            value.push('\\');
                            if let Some(ch) = self.peek() {
                                value.push(ch as char);
                            }
                            self.advance();
                        }
                        Some(ch) => {
                            let esc_line = self.line;
                            let esc_col = self.col;
                            return Err(ParseError::new(
                                format!("invalid escape sequence `\\{}`", ch as char),
                                esc_line,
                                esc_col,
                            ));
                        }
                        None => {
                            return Err(ParseError::new(
                                "unterminated string literal",
                                start.1,
                                start.2,
                            ));
                        }
                    }
                }
                Some(_) => {
                    // Decode full UTF-8 character (may be multi-byte)
                    let rest = &self.source[self.pos..];
                    match std::str::from_utf8(rest) {
                        Ok(s) => {
                            let c = s
                                .chars()
                                .next()
                                .expect("non-empty str after peek() returned Some");
                            self.advance_multibyte(c.len_utf8());
                            value.push(c);
                        }
                        Err(_) => {
                            let byte_line = self.line;
                            let byte_col = self.col;
                            return Err(ParseError::new(
                                "invalid UTF-8 in string literal",
                                byte_line,
                                byte_col,
                            ));
                        }
                    }
                }
            }
        }
        Ok(Token {
            kind: TokenKind::StringLit,
            span: self.make_span(start),
            lexeme: value,
        })
    }
}
