//! Lowering errors for Circom → ProveIR translation.
//!
//! `LoweringError` wraps a `Diagnostic` so that errors from the lowering
//! phase carry structured information (code, span, labels, notes) and
//! render identically to the rest of Achronyme's diagnostic output.

use diagnostics::{Diagnostic, Span, SpanRange};

/// Errors that can occur during Circom → ProveIR lowering.
#[derive(Debug)]
pub struct LoweringError {
    pub diagnostic: Diagnostic,
}

impl LoweringError {
    /// Create a lowering error with a span.
    pub fn new(message: impl Into<String>, span: &Span) -> Self {
        Self {
            diagnostic: Diagnostic::error(message, SpanRange::from_span(span)),
        }
    }

    /// Create a lowering error without a span (for truly spanless errors).
    pub fn without_span(message: impl Into<String>) -> Self {
        Self {
            diagnostic: Diagnostic::error(message, SpanRange::point(0, 0, 0)),
        }
    }

    /// Create a lowering error with a specific error code.
    pub fn with_code(message: impl Into<String>, code: &str, span: &Span) -> Self {
        Self {
            diagnostic: Diagnostic::error(message, SpanRange::from_span(span))
                .with_code(code),
        }
    }

    /// Access the underlying diagnostic (for adding labels, notes, etc).
    pub fn into_diagnostic(self) -> Diagnostic {
        self.diagnostic
    }
}

impl std::fmt::Display for LoweringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.diagnostic.message)?;
        let span = &self.diagnostic.primary_span;
        if span.line_start > 0 {
            write!(f, "\n  --> {}:{}", span.line_start, span.col_start)?;
        }
        Ok(())
    }
}

impl std::error::Error for LoweringError {}
