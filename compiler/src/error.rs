use std::fmt;

use achronyme_parser::ast::Span;
use achronyme_parser::diagnostic::SpanRange;
use achronyme_parser::Diagnostic;

/// Boxed span to keep error enum small.
pub type OptSpan = Option<Box<SpanRange>>;

/// Box a Span for use in error variants.
pub fn span_box(span: &Span) -> OptSpan {
    Some(Box::new(SpanRange::from(span)))
}

#[derive(Debug, Clone)]
pub enum CompilerError {
    ParseError(String),
    UnknownOperator(String, OptSpan),
    InvalidNumber(OptSpan),
    TooManyConstants(OptSpan),
    UnexpectedRule(String, OptSpan),
    RegisterOverflow(OptSpan),
    CompilerLimitation(String, OptSpan),
    CompileError(String, OptSpan),
    ModuleNotFound(String, OptSpan),
    CircularImport(String, OptSpan),
    ModuleLoadError(String),
    DuplicateModuleAlias(String, OptSpan),
    InternalError(String),
    /// A rich error that already carries a full Diagnostic (for structured suggestions).
    DiagnosticError(Box<Diagnostic>),
}

fn fmt_span(span: &OptSpan) -> String {
    match span {
        Some(s) => format!("[{}] ", s),
        None => String::new(),
    }
}

impl fmt::Display for CompilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompilerError::ParseError(msg) => write!(f, "parse error: {msg}"),
            CompilerError::UnknownOperator(msg, span) => {
                write!(f, "{}{msg}", fmt_span(span))
            }
            CompilerError::InvalidNumber(span) => {
                write!(f, "{}invalid number literal", fmt_span(span))
            }
            CompilerError::TooManyConstants(span) => {
                write!(f, "{}too many constants (limit 65536)", fmt_span(span))
            }
            CompilerError::UnexpectedRule(msg, span) => {
                write!(f, "{}unexpected rule: {msg}", fmt_span(span))
            }
            CompilerError::RegisterOverflow(span) => {
                write!(f, "{}register overflow (too many locals)", fmt_span(span))
            }
            CompilerError::CompilerLimitation(msg, span) => {
                write!(f, "{}compiler limitation: {msg}", fmt_span(span))
            }
            CompilerError::CompileError(msg, span) => {
                write!(f, "{}{msg}", fmt_span(span))
            }
            CompilerError::ModuleNotFound(path, span) => {
                write!(f, "{}module not found: {path}", fmt_span(span))
            }
            CompilerError::CircularImport(path, span) => {
                write!(f, "{}circular import: {path}", fmt_span(span))
            }
            CompilerError::ModuleLoadError(msg) => write!(f, "module load error: {msg}"),
            CompilerError::DuplicateModuleAlias(name, span) => {
                write!(f, "{}duplicate module alias: {name}", fmt_span(span))
            }
            CompilerError::InternalError(msg) => write!(f, "internal compiler error: {msg}"),
            CompilerError::DiagnosticError(diag) => write!(f, "{diag}"),
        }
    }
}

impl std::error::Error for CompilerError {}

impl CompilerError {
    /// Convert this error into a unified Diagnostic.
    pub fn to_diagnostic(&self) -> Diagnostic {
        // DiagnosticError already carries the full Diagnostic
        if let CompilerError::DiagnosticError(diag) = self {
            return *diag.clone();
        }

        let span = match self {
            CompilerError::UnknownOperator(_, s)
            | CompilerError::InvalidNumber(s)
            | CompilerError::TooManyConstants(s)
            | CompilerError::UnexpectedRule(_, s)
            | CompilerError::RegisterOverflow(s)
            | CompilerError::CompilerLimitation(_, s)
            | CompilerError::CompileError(_, s)
            | CompilerError::ModuleNotFound(_, s)
            | CompilerError::CircularImport(_, s)
            | CompilerError::DuplicateModuleAlias(_, s) => s.as_deref().cloned(),
            CompilerError::ParseError(_)
            | CompilerError::ModuleLoadError(_)
            | CompilerError::InternalError(_)
            | CompilerError::DiagnosticError(_) => None,
        };
        let primary = span.unwrap_or_else(|| SpanRange::point(0, 0, 0));
        Diagnostic::error(self.to_string(), primary)
    }
}
