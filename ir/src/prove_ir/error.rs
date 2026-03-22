//! Error types for ProveIR compilation.

use std::fmt;

use achronyme_parser::{Diagnostic, SpanRange};

use crate::error::OptSpan;

/// Errors emitted during ProveIR compilation (AST → ProveIR).
#[derive(Debug)]
pub enum ProveIrError {
    /// Reference to a variable not found in scope.
    UndeclaredVariable {
        name: String,
        span: OptSpan,
        suggestion: Option<String>,
    },
    /// An operation that has no circuit translation.
    UnsupportedOperation { description: String, span: OptSpan },
    /// A value type that cannot be represented in circuits.
    TypeNotConstrainable { type_name: String, span: OptSpan },
    /// A loop without statically-known bounds.
    UnboundedLoop { span: OptSpan },
    /// A builtin or method called with wrong arity.
    WrongArgumentCount {
        name: String,
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// Recursive function detected.
    RecursiveFunction { name: String },
    /// Array index out of bounds.
    IndexOutOfBounds {
        name: String,
        index: usize,
        length: usize,
        span: OptSpan,
    },
    /// Array length mismatch.
    ArrayLengthMismatch {
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// Type mismatch (e.g., scalar where array expected).
    TypeMismatch {
        expected: String,
        got: String,
        span: OptSpan,
    },
    /// Type annotation does not match inferred type.
    AnnotationMismatch {
        name: String,
        declared: String,
        inferred: String,
        span: OptSpan,
    },
    /// A static namespace member that cannot be used in circuits.
    StaticAccessNotConstrainable {
        type_name: String,
        member: String,
        reason: String,
        span: OptSpan,
    },
    /// A method that cannot be used in circuits.
    MethodNotConstrainable {
        method: String,
        reason: String,
        span: OptSpan,
    },
    /// For loop range exceeds maximum allowed iterations.
    RangeTooLarge {
        iterations: u64,
        max: u64,
        span: OptSpan,
    },
    /// Duplicate input declaration.
    DuplicateInput { name: String, span: OptSpan },
    /// Import statements are not yet supported in ProveIR.
    ImportsNotSupported { span: OptSpan },
    /// Module not found.
    ModuleNotFound(String),
    /// Circular import detected.
    CircularImport(String),
    /// Module loading error.
    ModuleLoadError(String),
    /// Parse error (propagated from parser).
    ParseError(Box<Diagnostic>),
}

impl fmt::Display for ProveIrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndeclaredVariable {
                name, suggestion, ..
            } => {
                write!(f, "undeclared variable in circuit: `{name}`")?;
                if let Some(s) = suggestion {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                Ok(())
            }
            Self::UnsupportedOperation { description, .. } => write!(f, "{description}"),
            Self::TypeNotConstrainable { type_name, .. } => {
                write!(
                    f,
                    "type '{type_name}' cannot be used in circuits \
                     (circuits operate on field elements only)"
                )
            }
            Self::UnboundedLoop { .. } => write!(
                f,
                "unbounded loops (while/forever) are not allowed in circuits \
                 (all iterations must be known at compile time)"
            ),
            Self::WrongArgumentCount {
                name,
                expected,
                got,
                ..
            } => write!(f, "`{name}` expects {expected} arguments, got {got}"),
            Self::RecursiveFunction { name } => {
                write!(f, "recursive function `{name}` is not allowed in circuits")
            }
            Self::IndexOutOfBounds {
                name,
                index,
                length,
                ..
            } => write!(
                f,
                "index {index} out of bounds for `{name}` (length {length})"
            ),
            Self::ArrayLengthMismatch { expected, got, .. } => {
                write!(f, "array length mismatch: expected {expected}, got {got}")
            }
            Self::TypeMismatch { expected, got, .. } => {
                write!(f, "type mismatch: expected {expected}, got {got}")
            }
            Self::AnnotationMismatch {
                name,
                declared,
                inferred,
                ..
            } => write!(
                f,
                "type annotation mismatch for `{name}`: declared {declared}, inferred {inferred}"
            ),
            Self::StaticAccessNotConstrainable {
                type_name,
                member,
                reason,
                ..
            } => write!(
                f,
                "`{type_name}::{member}` cannot be used in circuits: {reason}"
            ),
            Self::MethodNotConstrainable { method, reason, .. } => {
                write!(f, "`.{method}()` cannot be used in circuits: {reason}")
            }
            Self::RangeTooLarge {
                iterations, max, ..
            } => write!(
                f,
                "for loop has {iterations} iterations, exceeding maximum of {max}"
            ),
            Self::DuplicateInput { name, .. } => {
                write!(f, "duplicate input declaration: `{name}`")
            }
            Self::ImportsNotSupported { .. } => {
                write!(f, "imports not yet supported in ProveIR")
            }
            Self::ModuleNotFound(path) => write!(f, "module not found: `{path}`"),
            Self::CircularImport(path) => write!(f, "circular import detected: `{path}`"),
            Self::ModuleLoadError(msg) => write!(f, "module load error: {msg}"),
            Self::ParseError(diag) => write!(f, "parse error: {}", diag.message),
        }
    }
}

impl std::error::Error for ProveIrError {}

impl ProveIrError {
    /// Convert to a `Diagnostic` for unified error rendering.
    pub fn to_diagnostic(&self) -> Diagnostic {
        let span = match self {
            Self::UndeclaredVariable { span, .. }
            | Self::UnsupportedOperation { span, .. }
            | Self::TypeNotConstrainable { span, .. }
            | Self::UnboundedLoop { span }
            | Self::WrongArgumentCount { span, .. }
            | Self::IndexOutOfBounds { span, .. }
            | Self::ArrayLengthMismatch { span, .. }
            | Self::TypeMismatch { span, .. }
            | Self::AnnotationMismatch { span, .. }
            | Self::StaticAccessNotConstrainable { span, .. }
            | Self::MethodNotConstrainable { span, .. }
            | Self::RangeTooLarge { span, .. } => span.as_ref().map(|s| (**s).clone()),
            Self::DuplicateInput { span, .. } | Self::ImportsNotSupported { span } => {
                span.as_ref().map(|s| (**s).clone())
            }
            Self::ParseError(diag) => return (**diag).clone(),
            // Variants without span information — listed explicitly so new
            // variants with spans produce a compile error instead of silently
            // falling through.
            Self::RecursiveFunction { .. }
            | Self::ModuleNotFound(_)
            | Self::CircularImport(_)
            | Self::ModuleLoadError(_) => None,
        };

        let span = span.unwrap_or(SpanRange::new(0, 0, 0, 0, 0, 0));
        Diagnostic::error(self.to_string(), span)
    }
}
