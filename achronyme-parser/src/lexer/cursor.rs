use super::*;

impl<'a> Lexer<'a> {
    pub(super) fn peek(&self) -> Option<u8> {
        self.source.get(self.pos).copied()
    }

    pub(super) fn peek2(&self) -> Option<u8> {
        self.source.get(self.pos + 1).copied()
    }

    pub(super) fn advance(&mut self) -> u8 {
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

    /// Advance `pos` by `byte_len` bytes but increment `col` only once.
    /// Used for multi-byte UTF-8 characters that occupy one visual column.
    pub(super) fn advance_multibyte(&mut self, byte_len: usize) {
        self.pos += byte_len;
        self.col += 1;
    }

    /// Convert a byte slice (known to be ASCII) to `&str`, propagating as
    /// `ParseError` instead of panicking on the (structurally impossible) failure.
    pub(super) fn ascii_str<'b>(&self, bytes: &'b [u8]) -> Result<&'b str, ParseError> {
        std::str::from_utf8(bytes).map_err(|_| {
            ParseError::new(
                "internal: invalid UTF-8 in ASCII slice",
                self.line,
                self.col,
            )
        })
    }

    /// Capture current position as start of a span.
    pub(super) fn start_pos(&self) -> (usize, usize, usize) {
        (self.pos, self.line, self.col)
    }

    /// Build a span from a captured start position to the current position.
    pub(super) fn make_span(&self, start: (usize, usize, usize)) -> Span {
        Span {
            byte_start: start.0,
            byte_end: self.pos,
            line_start: start.1,
            col_start: start.2,
            line_end: self.line,
            col_end: self.col,
        }
    }

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
}
