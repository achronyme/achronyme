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
    /// A builtin function was called with the wrong number of arguments.
    WrongArgumentCount {
        builtin: String,
        expected: usize,
        got: usize,
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
                if let Some(s) = span {
                    write!(f, "[{s}] type `{ty}` cannot be represented in a circuit")
                } else {
                    write!(f, "type `{ty}` cannot be represented in a circuit")
                }
            }
            IrError::UnboundedLoop(span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] unbounded loops are not allowed in circuits")
                } else {
                    write!(f, "unbounded loops are not allowed in circuits")
                }
            }
            IrError::ParseError(msg) => {
                write!(f, "parse error: {msg}")
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
        }
    }
}

impl std::error::Error for IrError {}
