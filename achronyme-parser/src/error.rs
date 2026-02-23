/// Parse error with source location.

use std::fmt;

#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
}

impl ParseError {
    pub fn new(message: impl Into<String>, line: usize, col: usize) -> Self {
        Self {
            message: message.into(),
            line,
            col,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parse error at line {}, col {}: {}",
            self.line, self.col, self.message
        )
    }
}

impl std::error::Error for ParseError {}
