use std::fmt;

use achronyme_parser::SpanRange;

/// Boxed span to keep error enum small.
pub type OptSpan = Option<Box<SpanRange>>;

/// Box a SpanRange for use in error variants.
pub fn span_box(span: Option<SpanRange>) -> OptSpan {
    span.map(Box::new)
}

/// Errors emitted during IR lowering.
#[derive(Debug)]
pub enum IrError {
    /// Reference to a variable not previously declared with `public` or `witness`.
    UndeclaredVariable(String, OptSpan),
    /// An operation that has no circuit translation.
    UnsupportedOperation(String, OptSpan),
    /// A value type that cannot be represented as a field element.
    TypeNotConstrainable(String, OptSpan),
    /// A loop without a statically-known bound.
    UnboundedLoop(OptSpan),
    /// The input failed to parse.
    ParseError(String),
    /// A variable was declared as both public and witness, or declared twice.
    DuplicateInput(String),
    /// A builtin function was called with the wrong number of arguments.
    WrongArgumentCount {
        builtin: String,
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// Array index is out of bounds.
    IndexOutOfBounds {
        name: String,
        index: usize,
        length: usize,
        span: OptSpan,
    },
    /// Two arrays that must have the same length differ.
    ArrayLengthMismatch {
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// A function calls itself (directly or mutually).
    RecursiveFunction(String),
    /// A type mismatch (e.g. scalar where array expected, or vice versa).
    TypeMismatch {
        expected: String,
        got: String,
        span: OptSpan,
    },
    /// A type annotation does not match the inferred type.
    ///
    /// ```
    /// use achronyme_parser::SpanRange;
    /// use ir::error::IrError;
    ///
    /// let err = IrError::AnnotationMismatch {
    ///     name: "x".into(),
    ///     declared: "Bool".into(),
    ///     inferred: "Field".into(),
    ///     span: Some(Box::new(SpanRange::point(1, 5, 4))),
    /// };
    /// assert!(format!("{err}").contains("Bool"));
    /// assert!(format!("{err}").contains("Field"));
    /// ```
    AnnotationMismatch {
        name: String,
        declared: String,
        inferred: String,
        span: OptSpan,
    },
    /// A module file could not be found.
    ModuleNotFound(String),
    /// A circular import was detected.
    CircularImport(String),
    /// An error occurred while loading a module.
    ModuleLoadError(String),
}

fn fmt_span(span: &OptSpan) -> String {
    match span {
        Some(s) => format!("[{}] ", s),
        None => String::new(),
    }
}

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrError::UndeclaredVariable(name, span) => {
                write!(
                    f,
                    "{}undeclared variable in circuit: `{name}`",
                    fmt_span(span)
                )
            }
            IrError::UnsupportedOperation(op, span) => {
                write!(
                    f,
                    "{}unsupported operation in circuit: {op}",
                    fmt_span(span)
                )
            }
            IrError::TypeNotConstrainable(ty, span) => {
                let msg = match ty.as_str() {
                    "string" | "nil" => format!(
                        "type '{ty}' cannot be used in circuits (circuits operate on field elements only)"
                    ),
                    "map" => "type 'map' cannot be used in circuits (circuits operate on field elements only — use arrays instead)".to_string(),
                    "decimal" => "decimal numbers cannot be used in circuits (field arithmetic is integer-only — use whole numbers)".to_string(),
                    _ => format!("type '{ty}' cannot be used in circuits"),
                };
                write!(f, "{}{msg}", fmt_span(span))
            }
            IrError::UnboundedLoop(span) => {
                write!(f, "{}unbounded loops (while/forever) are not allowed in circuits (all iterations must be known at compile time for constraint generation)", fmt_span(span))
            }
            IrError::ParseError(msg) => {
                write!(f, "parse error: {msg}")
            }
            IrError::DuplicateInput(name) => {
                write!(f, "duplicate input declaration: `{name}`")
            }
            IrError::WrongArgumentCount {
                builtin,
                expected,
                got,
                span,
            } => {
                write!(
                    f,
                    "{}`{builtin}` expects {expected} arguments, got {got}",
                    fmt_span(span)
                )
            }
            IrError::IndexOutOfBounds {
                name,
                index,
                length,
                span,
            } => {
                write!(
                    f,
                    "{}index {index} out of bounds for array `{name}` of length {length}",
                    fmt_span(span)
                )
            }
            IrError::ArrayLengthMismatch {
                expected,
                got,
                span,
            } => {
                write!(
                    f,
                    "{}array length mismatch: expected {expected}, got {got}",
                    fmt_span(span)
                )
            }
            IrError::RecursiveFunction(name) => {
                write!(f, "recursive function `{name}` is not allowed in circuits")
            }
            IrError::TypeMismatch {
                expected,
                got,
                span,
            } => {
                write!(
                    f,
                    "{}type mismatch: expected {expected}, got {got}",
                    fmt_span(span)
                )
            }
            IrError::AnnotationMismatch {
                name,
                declared,
                inferred,
                span,
            } => {
                write!(
                    f,
                    "{}type annotation mismatch for `{name}`: declared as {declared}, but expression has type {inferred}",
                    fmt_span(span)
                )
            }
            IrError::ModuleNotFound(path) => {
                write!(f, "module not found: {path}")
            }
            IrError::CircularImport(path) => {
                write!(f, "circular import detected: {path}")
            }
            IrError::ModuleLoadError(msg) => {
                write!(f, "module load error: {msg}")
            }
        }
    }
}

impl std::error::Error for IrError {}
