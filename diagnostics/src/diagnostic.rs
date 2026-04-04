use std::fmt;
use std::path::PathBuf;

use crate::span::Span;

/// Byte-range span with line/column start and end positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanRange {
    pub file: Option<PathBuf>,
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: usize,
    pub col_start: usize,
    pub line_end: usize,
    pub col_end: usize,
}

impl SpanRange {
    pub fn new(
        byte_start: usize,
        byte_end: usize,
        line_start: usize,
        col_start: usize,
        line_end: usize,
        col_end: usize,
    ) -> Self {
        Self {
            file: None,
            byte_start,
            byte_end,
            line_start,
            col_start,
            line_end,
            col_end,
        }
    }

    pub fn with_file(mut self, file: PathBuf) -> Self {
        self.file = Some(file);
        self
    }

    pub fn point(line: usize, col: usize, byte_offset: usize) -> Self {
        Self {
            file: None,
            byte_start: byte_offset,
            byte_end: byte_offset,
            line_start: line,
            col_start: col,
            line_end: line,
            col_end: col,
        }
    }

    /// Create a `SpanRange` from a parser [`Span`].
    pub fn from_span(span: &Span) -> Self {
        Self {
            file: None,
            byte_start: span.byte_start,
            byte_end: span.byte_end,
            line_start: span.line_start,
            col_start: span.col_start,
            line_end: span.line_end,
            col_end: span.col_end,
        }
    }
}

impl From<Span> for SpanRange {
    fn from(span: Span) -> Self {
        Self {
            file: None,
            byte_start: span.byte_start,
            byte_end: span.byte_end,
            line_start: span.line_start,
            col_start: span.col_start,
            line_end: span.line_end,
            col_end: span.col_end,
        }
    }
}

impl From<&Span> for SpanRange {
    fn from(span: &Span) -> Self {
        Self {
            file: None,
            byte_start: span.byte_start,
            byte_end: span.byte_end,
            line_start: span.line_start,
            col_start: span.col_start,
            line_end: span.line_end,
            col_end: span.col_end,
        }
    }
}

impl fmt::Display for SpanRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(file) = &self.file {
            write!(f, "{}:", file.display())?;
        }
        write!(f, "{}:{}", self.line_start, self.col_start)?;
        if self.line_end != self.line_start || self.col_end != self.col_start {
            write!(f, "-{}:{}", self.line_end, self.col_end)?;
        }
        Ok(())
    }
}

/// Severity level for a diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Help,
    Note,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Note => write!(f, "note"),
            Severity::Help => write!(f, "help"),
        }
    }
}

/// A secondary label attached to a diagnostic, pointing to a related span.
#[derive(Clone, Debug)]
pub struct Label {
    pub span: SpanRange,
    pub message: String,
}

/// A suggested code replacement.
#[derive(Clone, Debug)]
pub struct Suggestion {
    pub span: SpanRange,
    pub replacement: String,
    pub message: String,
}

/// A unified diagnostic that any compilation phase can produce.
#[derive(Clone, Debug)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
    pub code: Option<String>,
    pub primary_span: SpanRange,
    pub labels: Vec<Label>,
    pub suggestions: Vec<Suggestion>,
    pub notes: Vec<String>,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.severity)?;
        if let Some(code) = &self.code {
            write!(f, "[{code}]")?;
        }
        write!(f, ": {}", self.message)?;
        write!(f, "\n  --> {}", self.primary_span)?;
        for label in &self.labels {
            write!(f, "\n  --> {}: {}", label.span, label.message)?;
        }
        for note in &self.notes {
            write!(f, "\n  = note: {note}")?;
        }
        for suggestion in &self.suggestions {
            write!(
                f,
                "\n  = help: {}: {}",
                suggestion.message, suggestion.replacement
            )?;
        }
        Ok(())
    }
}

impl Diagnostic {
    pub fn error(message: impl Into<String>, span: SpanRange) -> Self {
        Self {
            severity: Severity::Error,
            message: message.into(),
            code: None,
            primary_span: span,
            labels: Vec::new(),
            suggestions: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn warning(message: impl Into<String>, span: SpanRange) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
            code: None,
            primary_span: span,
            labels: Vec::new(),
            suggestions: Vec::new(),
            notes: Vec::new(),
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_label(mut self, span: SpanRange, message: impl Into<String>) -> Self {
        self.labels.push(Label {
            span,
            message: message.into(),
        });
        self
    }

    pub fn with_suggestion(
        mut self,
        span: SpanRange,
        replacement: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        self.suggestions.push(Suggestion {
            span,
            replacement: replacement.into(),
            message: message.into(),
        });
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}
