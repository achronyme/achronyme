//! Single-pass O(n) lexer for Circom 2.x syntax.

use diagnostics::{ParseError, Span};

use crate::token::{Token, TokenKind};

mod literals;

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
                            return Err(ParseError::with_code(
                                "unterminated block comment",
                                "E301",
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
                            Err(ParseError::with_code(
                                "unexpected `<-`, did you mean `<--`?",
                                "E302",
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
            _ => Err(ParseError::with_code(
                format!("unexpected character `{}`", ch as char),
                "E302",
                start.1,
                start.2,
            )),
        }
    }
}

#[cfg(test)]
mod tests;
