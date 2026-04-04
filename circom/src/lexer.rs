//! Single-pass O(n) lexer for Circom 2.x syntax.

use diagnostics::{ParseError, Span};

use crate::token::{lookup_keyword, Token, TokenKind};

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
            return Ok(self.make_token(TokenKind::Eof, start, ""));
        };

        // Numbers: decimal or hex (0x...)
        if ch.is_ascii_digit() {
            return self.lex_number(start);
        }

        // Identifiers, keywords, and $ prefixed identifiers
        if ch.is_ascii_alphabetic() || ch == b'_' || ch == b'$' {
            return self.lex_ident(start);
        }

        // String literals
        if ch == b'"' {
            return self.lex_string(start);
        }

        // Multi-character operators (maximal munch)
        //
        // Disambiguation order matters:
        //   < : <== (3) > <-- (3) > <= (2) > << (2) > < (1)
        //   = : === (3) > ==> (3) > == (2) > = (1)
        //   - : --> (3) > -- (2) > -= (2) > - (1)
        //   > : >>= (3) > >= (2) > >> (2) > > (1)
        //   * : **= (3) > ** (2) > *= (2) > * (1)
        //   + : += (2) > ++ (2) > + (1)
        //   ! : != (2) > ! (1)
        //   & : &= (2) > && (2) > & (1)
        //   | : |= (2) > || (2) > | (1)
        //   ^ : ^= (2) > ^ (1)

        match ch {
            b'<' => {
                self.advance();
                match self.peek() {
                    Some(b'=') => {
                        self.advance();
                        if self.peek() == Some(b'=') {
                            self.advance();
                            Ok(self.make_token(TokenKind::ConstraintAssign, start, "<=="))
                        } else {
                            Ok(self.make_token(TokenKind::Le, start, "<="))
                        }
                    }
                    Some(b'-') => {
                        self.advance();
                        if self.peek() == Some(b'-') {
                            self.advance();
                            Ok(self.make_token(TokenKind::SignalAssign, start, "<--"))
                        } else {
                            Err(ParseError::new(
                                "unexpected `<-`, did you mean `<--`?",
                                start.1,
                                start.2,
                            ))
                        }
                    }
                    Some(b'<') => {
                        self.advance();
                        if self.peek() == Some(b'=') {
                            self.advance();
                            Ok(self.make_token(TokenKind::ShiftLAssign, start, "<<="))
                        } else {
                            Ok(self.make_token(TokenKind::ShiftL, start, "<<"))
                        }
                    }
                    _ => Ok(self.make_token(TokenKind::Lt, start, "<")),
                }
            }
            b'=' => {
                self.advance();
                match self.peek() {
                    Some(b'=') => {
                        self.advance();
                        match self.peek() {
                            Some(b'=') => {
                                self.advance();
                                Ok(self.make_token(TokenKind::ConstraintEq, start, "==="))
                            }
                            Some(b'>') => {
                                self.advance();
                                Ok(self.make_token(TokenKind::RConstraintAssign, start, "==>"))
                            }
                            _ => Ok(self.make_token(TokenKind::Eq, start, "==")),
                        }
                    }
                    _ => Ok(self.make_token(TokenKind::Assign, start, "=")),
                }
            }
            b'-' => {
                self.advance();
                match self.peek() {
                    Some(b'-') => {
                        self.advance();
                        if self.peek() == Some(b'>') {
                            self.advance();
                            Ok(self.make_token(TokenKind::RSignalAssign, start, "-->"))
                        } else {
                            Ok(self.make_token(TokenKind::Decrement, start, "--"))
                        }
                    }
                    Some(b'=') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::MinusAssign, start, "-="))
                    }
                    _ => Ok(self.make_token(TokenKind::Minus, start, "-")),
                }
            }
            b'>' => {
                self.advance();
                match self.peek() {
                    Some(b'>') => {
                        self.advance();
                        if self.peek() == Some(b'=') {
                            self.advance();
                            Ok(self.make_token(TokenKind::ShiftRAssign, start, ">>="))
                        } else {
                            Ok(self.make_token(TokenKind::ShiftR, start, ">>"))
                        }
                    }
                    Some(b'=') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::Ge, start, ">="))
                    }
                    _ => Ok(self.make_token(TokenKind::Gt, start, ">")),
                }
            }
            b'*' => {
                self.advance();
                match self.peek() {
                    Some(b'*') => {
                        self.advance();
                        if self.peek() == Some(b'=') {
                            self.advance();
                            Ok(self.make_token(TokenKind::PowerAssign, start, "**="))
                        } else {
                            Ok(self.make_token(TokenKind::Power, start, "**"))
                        }
                    }
                    Some(b'=') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::StarAssign, start, "*="))
                    }
                    _ => Ok(self.make_token(TokenKind::Star, start, "*")),
                }
            }
            b'+' => {
                self.advance();
                match self.peek() {
                    Some(b'+') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::Increment, start, "++"))
                    }
                    Some(b'=') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::PlusAssign, start, "+="))
                    }
                    _ => Ok(self.make_token(TokenKind::Plus, start, "+")),
                }
            }
            b'!' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(self.make_token(TokenKind::Neq, start, "!="))
                } else {
                    Ok(self.make_token(TokenKind::Not, start, "!"))
                }
            }
            b'&' => {
                self.advance();
                match self.peek() {
                    Some(b'&') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::And, start, "&&"))
                    }
                    Some(b'=') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::BitAndAssign, start, "&="))
                    }
                    _ => Ok(self.make_token(TokenKind::BitAnd, start, "&")),
                }
            }
            b'|' => {
                self.advance();
                match self.peek() {
                    Some(b'|') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::Or, start, "||"))
                    }
                    Some(b'=') => {
                        self.advance();
                        Ok(self.make_token(TokenKind::BitOrAssign, start, "|="))
                    }
                    _ => Ok(self.make_token(TokenKind::BitOr, start, "|")),
                }
            }
            b'^' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(self.make_token(TokenKind::BitXorAssign, start, "^="))
                } else {
                    Ok(self.make_token(TokenKind::BitXor, start, "^"))
                }
            }
            b'/' => {
                // Comments already handled in skip_whitespace_and_comments
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(self.make_token(TokenKind::SlashAssign, start, "/="))
                } else {
                    Ok(self.make_token(TokenKind::Slash, start, "/"))
                }
            }
            b'\\' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(self.make_token(TokenKind::IntDivAssign, start, "\\="))
                } else {
                    Ok(self.make_token(TokenKind::IntDiv, start, "\\"))
                }
            }
            b'%' => {
                self.advance();
                if self.peek() == Some(b'=') {
                    self.advance();
                    Ok(self.make_token(TokenKind::PercentAssign, start, "%="))
                } else {
                    Ok(self.make_token(TokenKind::Percent, start, "%"))
                }
            }
            b'~' => {
                self.advance();
                Ok(self.make_token(TokenKind::BitNot, start, "~"))
            }
            b'?' => {
                self.advance();
                Ok(self.make_token(TokenKind::Question, start, "?"))
            }
            // Single-character delimiters
            b'(' => {
                self.advance();
                Ok(self.make_token(TokenKind::LParen, start, "("))
            }
            b')' => {
                self.advance();
                Ok(self.make_token(TokenKind::RParen, start, ")"))
            }
            b'[' => {
                self.advance();
                Ok(self.make_token(TokenKind::LBracket, start, "["))
            }
            b']' => {
                self.advance();
                Ok(self.make_token(TokenKind::RBracket, start, "]"))
            }
            b'{' => {
                self.advance();
                Ok(self.make_token(TokenKind::LBrace, start, "{"))
            }
            b'}' => {
                self.advance();
                Ok(self.make_token(TokenKind::RBrace, start, "}"))
            }
            b',' => {
                self.advance();
                Ok(self.make_token(TokenKind::Comma, start, ","))
            }
            b':' => {
                self.advance();
                Ok(self.make_token(TokenKind::Colon, start, ":"))
            }
            b';' => {
                self.advance();
                Ok(self.make_token(TokenKind::Semicolon, start, ";"))
            }
            b'.' => {
                self.advance();
                Ok(self.make_token(TokenKind::Dot, start, "."))
            }
            _ => Err(ParseError::new(
                format!("unexpected character `{}`", ch as char),
                start.1,
                start.2,
            )),
        }
    }

    fn lex_number(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
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
                return Err(ParseError::new(
                    "expected hex digits after `0x`",
                    start.1,
                    start.2,
                ));
            }
            let lexeme = std::str::from_utf8(&self.source[start.0..self.pos])
                .map_err(|_| ParseError::new("invalid UTF-8", start.1, start.2))?
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
            .map_err(|_| ParseError::new("invalid UTF-8", start.1, start.2))?
            .to_string();
        Ok(Token {
            kind: TokenKind::DecNumber,
            span: self.make_span(start),
            lexeme,
        })
    }

    fn lex_ident(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
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
            .map_err(|_| ParseError::new("invalid UTF-8", start.1, start.2))?
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

    fn lex_string(&mut self, start: (usize, usize, usize)) -> Result<Token, ParseError> {
        self.advance(); // consume opening "
        let mut buf = String::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => {
                    return Err(ParseError::new(
                        "unterminated string literal",
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
                            return Err(ParseError::new(
                                format!("invalid escape sequence `\\{}`", ch as char),
                                self.line,
                                self.col,
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
                Some(ch) => {
                    self.advance();
                    buf.push(ch as char);
                }
            }
        }
    }
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

    fn lexemes(src: &str) -> Vec<String> {
        Lexer::tokenize(src)
            .unwrap()
            .into_iter()
            .map(|t| t.lexeme)
            .collect()
    }

    // ── Signal operators ─────────────────────────────────────────────

    #[test]
    fn signal_constraint_assign() {
        assert_eq!(
            kinds("a <== b"),
            vec![
                TokenKind::Ident,
                TokenKind::ConstraintAssign,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn signal_assign() {
        assert_eq!(
            kinds("a <-- b"),
            vec![
                TokenKind::Ident,
                TokenKind::SignalAssign,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn constraint_eq() {
        assert_eq!(
            kinds("a === b"),
            vec![
                TokenKind::Ident,
                TokenKind::ConstraintEq,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn reverse_constraint_assign() {
        assert_eq!(
            kinds("a ==> b"),
            vec![
                TokenKind::Ident,
                TokenKind::RConstraintAssign,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn reverse_signal_assign() {
        assert_eq!(
            kinds("a --> b"),
            vec![
                TokenKind::Ident,
                TokenKind::RSignalAssign,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }

    // ── Disambiguation ───────────────────────────────────────────────

    #[test]
    fn less_than_vs_constraint_assign() {
        // `<` then `<==` on separate expressions
        assert_eq!(
            kinds("a < b"),
            vec![
                TokenKind::Ident,
                TokenKind::Lt,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
        assert_eq!(
            kinds("a <= b"),
            vec![
                TokenKind::Ident,
                TokenKind::Le,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
        assert_eq!(
            kinds("a <== b"),
            vec![
                TokenKind::Ident,
                TokenKind::ConstraintAssign,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }

    #[test]
    fn equals_disambiguation() {
        assert_eq!(kinds("=")[..2], [TokenKind::Assign, TokenKind::Eof]);
        assert_eq!(kinds("==")[..2], [TokenKind::Eq, TokenKind::Eof]);
        assert_eq!(kinds("===")[..2], [TokenKind::ConstraintEq, TokenKind::Eof]);
        assert_eq!(
            kinds("==>")[..2],
            [TokenKind::RConstraintAssign, TokenKind::Eof]
        );
    }

    #[test]
    fn minus_disambiguation() {
        assert_eq!(kinds("-")[..2], [TokenKind::Minus, TokenKind::Eof]);
        assert_eq!(kinds("--")[..2], [TokenKind::Decrement, TokenKind::Eof]);
        assert_eq!(
            kinds("-->")[..2],
            [TokenKind::RSignalAssign, TokenKind::Eof]
        );
        assert_eq!(kinds("-=")[..2], [TokenKind::MinusAssign, TokenKind::Eof]);
    }

    #[test]
    fn star_disambiguation() {
        assert_eq!(kinds("*")[..2], [TokenKind::Star, TokenKind::Eof]);
        assert_eq!(kinds("**")[..2], [TokenKind::Power, TokenKind::Eof]);
        assert_eq!(kinds("**=")[..2], [TokenKind::PowerAssign, TokenKind::Eof]);
        assert_eq!(kinds("*=")[..2], [TokenKind::StarAssign, TokenKind::Eof]);
    }

    #[test]
    fn shift_disambiguation() {
        assert_eq!(kinds("<<")[..2], [TokenKind::ShiftL, TokenKind::Eof]);
        assert_eq!(kinds("<<=")[..2], [TokenKind::ShiftLAssign, TokenKind::Eof]);
        assert_eq!(kinds(">>")[..2], [TokenKind::ShiftR, TokenKind::Eof]);
        assert_eq!(kinds(">>=")[..2], [TokenKind::ShiftRAssign, TokenKind::Eof]);
    }

    // ── Compound assignment ──────────────────────────────────────────

    #[test]
    fn compound_assignment_ops() {
        assert_eq!(kinds("+=")[..2], [TokenKind::PlusAssign, TokenKind::Eof]);
        assert_eq!(kinds("-=")[..2], [TokenKind::MinusAssign, TokenKind::Eof]);
        assert_eq!(kinds("/=")[..2], [TokenKind::SlashAssign, TokenKind::Eof]);
        assert_eq!(kinds("\\=")[..2], [TokenKind::IntDivAssign, TokenKind::Eof]);
        assert_eq!(kinds("%=")[..2], [TokenKind::PercentAssign, TokenKind::Eof]);
        assert_eq!(kinds("&=")[..2], [TokenKind::BitAndAssign, TokenKind::Eof]);
        assert_eq!(kinds("|=")[..2], [TokenKind::BitOrAssign, TokenKind::Eof]);
        assert_eq!(kinds("^=")[..2], [TokenKind::BitXorAssign, TokenKind::Eof]);
    }

    // ── Increment / decrement ────────────────────────────────────────

    #[test]
    fn increment_decrement() {
        assert_eq!(
            kinds("i++ j--"),
            vec![
                TokenKind::Ident,
                TokenKind::Increment,
                TokenKind::Ident,
                TokenKind::Decrement,
                TokenKind::Eof,
            ]
        );
    }

    // ── Bitwise operators ────────────────────────────────────────────

    #[test]
    fn bitwise_ops() {
        assert_eq!(
            kinds("a & b | c ^ d ~ e"),
            vec![
                TokenKind::Ident,
                TokenKind::BitAnd,
                TokenKind::Ident,
                TokenKind::BitOr,
                TokenKind::Ident,
                TokenKind::BitXor,
                TokenKind::Ident,
                TokenKind::BitNot,
                TokenKind::Ident,
                TokenKind::Eof,
            ]
        );
    }

    // ── Keywords ─────────────────────────────────────────────────────

    #[test]
    fn circom_keywords() {
        assert_eq!(
            kinds("signal input output template component var function pragma"),
            vec![
                TokenKind::Signal,
                TokenKind::Input,
                TokenKind::Output,
                TokenKind::Template,
                TokenKind::Component,
                TokenKind::Var,
                TokenKind::Function,
                TokenKind::Pragma,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn control_keywords() {
        assert_eq!(
            kinds("if else for while do return assert log"),
            vec![
                TokenKind::If,
                TokenKind::Else,
                TokenKind::For,
                TokenKind::While,
                TokenKind::Do,
                TokenKind::Return,
                TokenKind::Assert,
                TokenKind::Log,
                TokenKind::Eof,
            ]
        );
    }

    #[test]
    fn modifier_keywords() {
        assert_eq!(
            kinds("parallel custom public bus include main"),
            vec![
                TokenKind::Parallel,
                TokenKind::Custom,
                TokenKind::Public,
                TokenKind::Bus,
                TokenKind::Include,
                TokenKind::MainKw,
                TokenKind::Eof,
            ]
        );
    }

    // ── Identifiers ──────────────────────────────────────────────────

    #[test]
    fn dollar_prefix_ident() {
        let tokens = Lexer::tokenize("$special").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Ident);
        assert_eq!(tokens[0].lexeme, "$special");
    }

    #[test]
    fn underscore_is_special() {
        assert_eq!(kinds("_")[..2], [TokenKind::Underscore, TokenKind::Eof]);
        // But _foo is a regular ident
        let tokens = Lexer::tokenize("_foo").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::Ident);
        assert_eq!(tokens[0].lexeme, "_foo");
    }

    // ── Numbers ──────────────────────────────────────────────────────

    #[test]
    fn decimal_number() {
        let tokens = Lexer::tokenize("42").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::DecNumber);
        assert_eq!(tokens[0].lexeme, "42");
    }

    #[test]
    fn hex_number() {
        let tokens = Lexer::tokenize("0xFF").unwrap();
        assert_eq!(tokens[0].kind, TokenKind::HexNumber);
        assert_eq!(tokens[0].lexeme, "0xFF");
    }

    #[test]
    fn hex_no_digits_error() {
        assert!(Lexer::tokenize("0x").is_err());
    }

    // ── Strings ──────────────────────────────────────────────────────

    #[test]
    fn string_literal() {
        let tokens = Lexer::tokenize(r#""hello world""#).unwrap();
        assert_eq!(tokens[0].kind, TokenKind::StringLit);
        assert_eq!(tokens[0].lexeme, "hello world");
    }

    #[test]
    fn unterminated_string() {
        assert!(Lexer::tokenize(r#""unterminated"#).is_err());
    }

    #[test]
    fn string_no_newline() {
        assert!(Lexer::tokenize("\"hello\nworld\"").is_err());
    }

    #[test]
    fn string_escape_sequences() {
        let tokens = Lexer::tokenize(r#""hello\nworld""#).unwrap();
        assert_eq!(tokens[0].kind, TokenKind::StringLit);
        assert_eq!(tokens[0].lexeme, "hello\nworld");

        let tokens = Lexer::tokenize(r#""tab\there""#).unwrap();
        assert_eq!(tokens[0].lexeme, "tab\there");

        let tokens = Lexer::tokenize(r#""escaped\\backslash""#).unwrap();
        assert_eq!(tokens[0].lexeme, "escaped\\backslash");

        let tokens = Lexer::tokenize(r#""escaped\"quote""#).unwrap();
        assert_eq!(tokens[0].lexeme, "escaped\"quote");
    }

    #[test]
    fn string_invalid_escape() {
        assert!(Lexer::tokenize(r#""bad\xescape""#).is_err());
    }

    // ── Comments ─────────────────────────────────────────────────────

    #[test]
    fn line_comment() {
        assert_eq!(
            kinds("1 // comment\n2"),
            vec![TokenKind::DecNumber, TokenKind::DecNumber, TokenKind::Eof]
        );
    }

    #[test]
    fn block_comment() {
        assert_eq!(
            kinds("1 /* block */ 2"),
            vec![TokenKind::DecNumber, TokenKind::DecNumber, TokenKind::Eof]
        );
    }

    #[test]
    fn unterminated_block_comment() {
        assert!(Lexer::tokenize("/* unterminated").is_err());
    }

    // ── Delimiters ───────────────────────────────────────────────────

    #[test]
    fn delimiters() {
        assert_eq!(
            kinds("()[]{},:;.?"),
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
                TokenKind::Dot,
                TokenKind::Question,
                TokenKind::Eof,
            ]
        );
    }

    // ── Ternary ──────────────────────────────────────────────────────

    #[test]
    fn ternary_op() {
        assert_eq!(
            kinds("a ? b : c"),
            vec![
                TokenKind::Ident,
                TokenKind::Question,
                TokenKind::Ident,
                TokenKind::Colon,
                TokenKind::Ident,
                TokenKind::Eof,
            ]
        );
    }

    // ── Span tracking ────────────────────────────────────────────────

    #[test]
    fn span_tracking() {
        let tokens = Lexer::tokenize("signal input x;").unwrap();
        // "signal" bytes 0..6
        assert_eq!(tokens[0].span.byte_start, 0);
        assert_eq!(tokens[0].span.byte_end, 6);
        assert_eq!(tokens[0].span.line_start, 1);
        assert_eq!(tokens[0].span.col_start, 1);
        // "input" bytes 7..12
        assert_eq!(tokens[1].span.byte_start, 7);
        assert_eq!(tokens[1].span.byte_end, 12);
        // "x" bytes 13..14
        assert_eq!(tokens[2].span.byte_start, 13);
        assert_eq!(tokens[2].span.byte_end, 14);
    }

    #[test]
    fn multiline_spans() {
        let tokens = Lexer::tokenize("a\nb").unwrap();
        assert_eq!(tokens[0].span.line_start, 1);
        assert_eq!(tokens[1].span.line_start, 2);
    }

    // ── Realistic Circom snippet ─────────────────────────────────────

    #[test]
    fn realistic_circom() {
        let src = r#"
pragma circom 2.1.6;
include "circomlib/poseidon.circom";

template Multiplier(n) {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main {public [a]} = Multiplier(2);
"#;
        let tokens = Lexer::tokenize(src).unwrap();
        // Should tokenize without error
        assert!(tokens.last().unwrap().kind == TokenKind::Eof);
        // Check key tokens are present
        let kinds: Vec<_> = tokens.iter().map(|t| &t.kind).collect();
        assert!(kinds.contains(&&TokenKind::Pragma));
        assert!(kinds.contains(&&TokenKind::Include));
        assert!(kinds.contains(&&TokenKind::Template));
        assert!(kinds.contains(&&TokenKind::Signal));
        assert!(kinds.contains(&&TokenKind::ConstraintAssign));
        assert!(kinds.contains(&&TokenKind::Component));
        assert!(kinds.contains(&&TokenKind::MainKw));
    }

    // ── Error on invalid <-- partial ─────────────────────────────────

    #[test]
    fn partial_signal_assign_error() {
        // `<-` without the third `-` is an error
        assert!(Lexer::tokenize("a <- b").is_err());
    }

    // ── Integer division ─────────────────────────────────────────────

    #[test]
    fn int_div_and_assign() {
        assert_eq!(
            kinds("a \\ b")[..4],
            [
                TokenKind::Ident,
                TokenKind::IntDiv,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
        assert_eq!(
            kinds("a \\= b")[..4],
            [
                TokenKind::Ident,
                TokenKind::IntDivAssign,
                TokenKind::Ident,
                TokenKind::Eof
            ]
        );
    }
}
