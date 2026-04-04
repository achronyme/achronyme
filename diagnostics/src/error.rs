/// Parse error with source location.
use std::fmt;

use crate::diagnostic::{Diagnostic, SpanRange};

#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub line: usize,
    pub col: usize,
    pub code: Option<String>,
}

impl ParseError {
    pub fn new(message: impl Into<String>, line: usize, col: usize) -> Self {
        Self {
            message: message.into(),
            line,
            col,
            code: None,
        }
    }

    pub fn with_code(message: impl Into<String>, code: &str, line: usize, col: usize) -> Self {
        Self {
            message: message.into(),
            line,
            col,
            code: Some(code.to_string()),
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

impl From<ParseError> for Diagnostic {
    fn from(err: ParseError) -> Self {
        let diag = Diagnostic::error(err.message, SpanRange::point(err.line, err.col, 0));
        if let Some(code) = err.code {
            diag.with_code(code)
        } else {
            diag
        }
    }
}
