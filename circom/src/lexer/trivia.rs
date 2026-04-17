//! Whitespace and comment skipping.
//!
//! Called once at the top of `next_token` to advance past insignificant
//! characters before classifying the next real token. Block comments are
//! the only trivia that can fail — an unterminated `/* … */` produces a
//! diagnostic with E301.

use diagnostics::ParseError;

use super::Lexer;

impl<'a> Lexer<'a> {
    pub(super) fn skip_whitespace_and_comments(&mut self) -> Result<(), ParseError> {
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
}
