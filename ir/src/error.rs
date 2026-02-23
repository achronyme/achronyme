use std::fmt;

/// Source location for error reporting.
#[derive(Debug, Clone)]
pub struct SourceSpan {
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for SourceSpan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.col)
    }
}

/// Errors emitted during IR lowering.
#[derive(Debug)]
pub enum IrError {
    /// Reference to a variable not previously declared with `public` or `witness`.
    UndeclaredVariable(String, Option<SourceSpan>),
    /// An operation that has no circuit translation.
    UnsupportedOperation(String, Option<SourceSpan>),
    /// A value type that cannot be represented as a field element.
    TypeNotConstrainable(String, Option<SourceSpan>),
    /// A loop without a statically-known bound.
    UnboundedLoop(Option<SourceSpan>),
    /// The input failed to parse.
    ParseError(String),
    /// A variable was declared as both public and witness, or declared twice.
    DuplicateInput(String),
    /// A builtin function was called with the wrong number of arguments.
    WrongArgumentCount {
        builtin: String,
        expected: usize,
        got: usize,
        span: Option<SourceSpan>,
    },
    /// Array index is out of bounds.
    IndexOutOfBounds {
        name: String,
        index: usize,
        length: usize,
        span: Option<SourceSpan>,
    },
    /// Two arrays that must have the same length differ.
    ArrayLengthMismatch {
        expected: usize,
        got: usize,
        span: Option<SourceSpan>,
    },
    /// A function calls itself (directly or mutually).
    RecursiveFunction(String),
    /// A type mismatch (e.g. scalar where array expected, or vice versa).
    TypeMismatch {
        expected: String,
        got: String,
        span: Option<SourceSpan>,
    },
    /// A type annotation does not match the inferred type.
    ///
    /// ```
    /// use ir::error::{IrError, SourceSpan};
    ///
    /// let err = IrError::AnnotationMismatch {
    ///     name: "x".into(),
    ///     declared: "Bool".into(),
    ///     inferred: "Field".into(),
    ///     span: Some(SourceSpan { line: 1, col: 5 }),
    /// };
    /// assert!(format!("{err}").contains("Bool"));
    /// assert!(format!("{err}").contains("Field"));
    /// ```
    AnnotationMismatch {
        name: String,
        declared: String,
        inferred: String,
        span: Option<SourceSpan>,
    },
}

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrError::UndeclaredVariable(name, span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] undeclared variable in circuit: `{name}`")
                } else {
                    write!(f, "undeclared variable in circuit: `{name}`")
                }
            }
            IrError::UnsupportedOperation(op, span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] unsupported operation in circuit: {op}")
                } else {
                    write!(f, "unsupported operation in circuit: {op}")
                }
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
                if let Some(s) = span {
                    write!(f, "[{s}] {msg}")
                } else {
                    write!(f, "{msg}")
                }
            }
            IrError::UnboundedLoop(span) => {
                let msg = "unbounded loops (while/forever) are not allowed in circuits (all iterations must be known at compile time for constraint generation)";
                if let Some(s) = span {
                    write!(f, "[{s}] {msg}")
                } else {
                    write!(f, "{msg}")
                }
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
                if let Some(s) = span {
                    write!(
                        f,
                        "[{s}] `{builtin}` expects {expected} arguments, got {got}"
                    )
                } else {
                    write!(f, "`{builtin}` expects {expected} arguments, got {got}")
                }
            }
            IrError::IndexOutOfBounds {
                name,
                index,
                length,
                span,
            } => {
                if let Some(s) = span {
                    write!(
                        f,
                        "[{s}] index {index} out of bounds for array `{name}` of length {length}"
                    )
                } else {
                    write!(
                        f,
                        "index {index} out of bounds for array `{name}` of length {length}"
                    )
                }
            }
            IrError::ArrayLengthMismatch {
                expected,
                got,
                span,
            } => {
                if let Some(s) = span {
                    write!(
                        f,
                        "[{s}] array length mismatch: expected {expected}, got {got}"
                    )
                } else {
                    write!(f, "array length mismatch: expected {expected}, got {got}")
                }
            }
            IrError::RecursiveFunction(name) => {
                write!(f, "recursive function `{name}` is not allowed in circuits")
            }
            IrError::TypeMismatch {
                expected,
                got,
                span,
            } => {
                if let Some(s) = span {
                    write!(f, "[{s}] type mismatch: expected {expected}, got {got}")
                } else {
                    write!(f, "type mismatch: expected {expected}, got {got}")
                }
            }
            IrError::AnnotationMismatch {
                name,
                declared,
                inferred,
                span,
            } => {
                let msg = format!(
                    "type annotation mismatch for `{name}`: declared as {declared}, but expression has type {inferred}"
                );
                if let Some(s) = span {
                    write!(f, "[{s}] {msg}")
                } else {
                    write!(f, "{msg}")
                }
            }
        }
    }
}

impl std::error::Error for IrError {}
