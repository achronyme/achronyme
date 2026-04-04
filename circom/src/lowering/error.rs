//! Lowering errors for Circom → ProveIR translation.

use diagnostics::Span;

/// Errors that can occur during Circom → ProveIR lowering.
#[derive(Debug)]
pub struct LoweringError {
    pub message: String,
    pub span: Option<Span>,
}

impl LoweringError {
    pub fn new(message: impl Into<String>, span: &Span) -> Self {
        Self {
            message: message.into(),
            span: Some(span.clone()),
        }
    }

    pub fn without_span(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
        }
    }
}

impl std::fmt::Display for LoweringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(span) = &self.span {
            write!(f, "\n  --> {}:{}", span.line_start, span.col_start)?;
        }
        Ok(())
    }
}

impl std::error::Error for LoweringError {}
