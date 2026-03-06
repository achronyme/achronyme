/// Single-pass O(n) lexer for Achronyme source code.
use crate::ast::Span;
use crate::error::ParseError;
use crate::token::{Token, TokenKind};

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

    /// Capture current position as start of a span.
    fn start_pos(&self) -> (usize, usize, usize) {
        (self.pos, self.line, self.col)
    }

    /// Build a span from a captured start position to the current position.
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

    fn skip_whitespace_and_comments(&mut self) -> Result<(), ParseError> {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => {
                    self.advance();
                }
                Some(b'/') => {
                    if self.peek2() == Some(b'/') {
                        // Line comment
                        self.advance();
                        self.advance();
                        while let Some(ch) = self.peek() {
                            if ch == b'\n' {
                                break;
                            }
                            self.advance();
                        }
                    } else if self.peek2() == Some(b'*') {
                        // Block comment
                        let comment_line = self.line;
                        let comment_col = self.col;
                        self.advance();
                        self.advance();
                        let mut closed = false;
                        loop {
                            match self.peek() {
                                None => break,
                                Some(b'*') if self.peek2() == Some(b'/') => {
                                    self.advance();
                                    self.advance();
                                    closed = true;
                                    break;
                                }
                                _ => {
                                    self.advance();
                                }
                            }
                        }
                        if !closed {
                            return Err(ParseError::new(
                                "unterminated block comment",
                                comment_line,
                                comment_col,
                            ));
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn next_token(&mut self) -> Result<Token, ParseError> {
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
            return Ok(self.lex_ident(start));
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
            b':' => (TokenKind::Colon, ":"),
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

    fn lex_number(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
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
        let lexeme = std::str::from_utf8(&self.source[start.0..self.pos])
            .unwrap()
            .to_string();
        Ok(Token {
            kind: TokenKind::Integer,
            span: self.make_span(start),
            lexeme,
        })
    }

    fn lex_field_lit(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
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
                let digits = std::str::from_utf8(&self.source[digit_start..self.pos]).unwrap();
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
                let digits = std::str::from_utf8(&self.source[digit_start..self.pos]).unwrap();
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
                std::str::from_utf8(&self.source[digit_start..self.pos])
                    .unwrap()
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

    fn lex_bigint_lit(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
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
                let digits = std::str::from_utf8(&self.source[digit_start..self.pos]).unwrap();
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
                let digits = std::str::from_utf8(&self.source[digit_start..self.pos]).unwrap();
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
                let digits = std::str::from_utf8(&self.source[digit_start..self.pos]).unwrap();
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

    fn lex_ident(&mut self, start: (usize, usize, usize)) -> Token {
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == b'_' {
                self.advance();
            } else {
                break;
            }
        }
        let lexeme = std::str::from_utf8(&self.source[start.0..self.pos])
            .unwrap()
            .to_string();
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
            "forever" => TokenKind::Forever,
            "import" => TokenKind::Import,
            "export" => TokenKind::Export,
            "as" => TokenKind::As,
            _ => TokenKind::Ident,
        };
        Token {
            kind,
            span: self.make_span(start),
            lexeme,
        }
    }

    fn lex_string(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
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
                            value.push(self.peek().unwrap() as char);
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
                            let c = s.chars().next().unwrap();
                            for _ in 0..c.len_utf8() {
                                self.advance();
                            }
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

/// Process escape sequences in a raw string literal value.
///
/// The lexer stores string contents with escapes unprocessed (e.g., `\n` as
/// literal backslash + `n`). Call this function to convert them to their
/// interpreted values (e.g., real newline character).
pub fn unescape(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\u{08}'),
                Some('f') => result.push('\u{0C}'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        Lexer::tokenize(src)
            .unwrap()
            .into_iter()
            .map(|t| t.kind)
            .collect()
    }

    #[test]
    fn simple_tokens() {
        assert_eq!(
            kinds("+ - * / %"),
            vec![
                TokenKind::Plus,
                TokenKind::Minus,
                TokenKind::Star,
                TokenKind::Slash,
                TokenKind::Percent,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn multi_char_ops() {
        assert_eq!(
            kinds("== != <= >= && || .."),
            vec![
                TokenKind::Eq,
                TokenKind::Neq,
                TokenKind::Le,
                TokenKind::Ge,
                TokenKind::And,
                TokenKind::Or,
                TokenKind::DotDot,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn keywords() {
        assert_eq!(
            kinds("let mut if else fn return"),
            vec![
                TokenKind::Let,
                TokenKind::Mut,
                TokenKind::If,
                TokenKind::Else,
                TokenKind::Fn,
                TokenKind::Return,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn ident_not_keyword() {
        let tokens = Lexer::tokenize("letter").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Ident);
        assert_eq!(tokens[0].lexeme, "letter");
    }

    #[test]
    fn number_literal() {
        let tokens = Lexer::tokenize("42").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Integer);
        assert_eq!(tokens[0].lexeme, "42");
    }

    #[test]
    fn string_escapes() {
        let tokens = Lexer::tokenize(r#""hello\nworld""#).unwrap();
        assert_eq!(tokens[0].kind, TokenKind::StringLit);
        // P-01 fix: lexer stores raw escape sequences, not processed values
        assert_eq!(tokens[0].lexeme, r"hello\nworld");
        assert_eq!(tokens[0].lexeme.len(), 12); // literal backslash + n, not newline

        // Verify all escape types are stored raw
        let tokens = Lexer::tokenize(r#""a\tb\nc\\d\"e""#).unwrap();
        assert_eq!(tokens[0].lexeme, r#"a\tb\nc\\d\"e"#);
    }

    #[test]
    fn unterminated_string() {
        assert!(Lexer::tokenize(r#""unterminated"#).is_err());
    }

    #[test]
    fn line_comment() {
        assert_eq!(
            kinds("1 // comment\n2"),
            vec![TokenKind::Integer, TokenKind::Integer, TokenKind::Eof]
        );
    }

    #[test]
    fn block_comment() {
        assert_eq!(
            kinds("1 /* comment */ 2"),
            vec![TokenKind::Integer, TokenKind::Integer, TokenKind::Eof]
        );
    }

    #[test]
    fn delimiters() {
        assert_eq!(
            kinds("()[]{},:;"),
            vec![
                TokenKind::LParen,
                TokenKind::RParen,
                TokenKind::LBracket,
                TokenKind::RBracket,
                TokenKind::LBrace,
                TokenKind::RBrace,
                TokenKind::Comma,
                TokenKind::Colon,
                TokenKind::Semicolon,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn string_utf8_multibyte() {
        // P-05 fix: multi-byte UTF-8 characters in strings
        let tokens = Lexer::tokenize("\"café\"").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::StringLit);
        assert_eq!(tokens[0].lexeme, "café");

        let tokens = Lexer::tokenize("\"hello 世界\"").unwrap();
        assert_eq!(tokens[0].lexeme, "hello 世界");

        // Emoji (4-byte UTF-8)
        let tokens = Lexer::tokenize("\"🎉\"").unwrap();
        assert_eq!(tokens[0].lexeme, "🎉");
    }

    #[test]
    fn unescape_basic() {
        assert_eq!(unescape(r"hello\nworld"), "hello\nworld");
        assert_eq!(unescape(r"tab\there"), "tab\there");
        assert_eq!(unescape(r"back\\slash"), "back\\slash");
        assert_eq!(unescape(r#"say\"hi\""#), "say\"hi\"");
        assert_eq!(unescape(r"\b\f\r"), "\u{08}\u{0C}\r");
        assert_eq!(unescape("no escapes"), "no escapes");
        assert_eq!(unescape(""), "");
    }

    #[test]
    fn token_span_has_byte_range() {
        let tokens = Lexer::tokenize("let x = 42").unwrap();
        // "let" is at bytes 0..3
        assert_eq!(tokens[0].span.byte_start, 0);
        assert_eq!(tokens[0].span.byte_end, 3);
        assert_eq!(tokens[0].span.line_start, 1);
        assert_eq!(tokens[0].span.col_start, 1);
        assert_eq!(tokens[0].span.line_end, 1);
        assert_eq!(tokens[0].span.col_end, 4);
        // "x" is at bytes 4..5
        assert_eq!(tokens[1].span.byte_start, 4);
        assert_eq!(tokens[1].span.byte_end, 5);
        // "=" is at bytes 6..7
        assert_eq!(tokens[2].span.byte_start, 6);
        assert_eq!(tokens[2].span.byte_end, 7);
        // "42" is at bytes 8..10
        assert_eq!(tokens[3].span.byte_start, 8);
        assert_eq!(tokens[3].span.byte_end, 10);
    }

    #[test]
    fn token_span_multiline() {
        let tokens = Lexer::tokenize("a\nb").unwrap();
        // "a" on line 1
        assert_eq!(tokens[0].span.line_start, 1);
        assert_eq!(tokens[0].span.line_end, 1);
        // "b" on line 2
        assert_eq!(tokens[1].span.line_start, 2);
        assert_eq!(tokens[1].span.line_end, 2);
    }
}
