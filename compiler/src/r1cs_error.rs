use std::fmt;

use ir::SourceSpan;

/// Errors emitted by the R1CS compiler backend.
#[derive(Debug)]
pub enum R1CSError {
    /// Reference to a variable not previously declared with `public` or `witness`.
    UndeclaredVariable(String, Option<SourceSpan>),
    /// An operation that has no R1CS translation (e.g. `print`, closures).
    UnsupportedOperation(String, Option<SourceSpan>),
    /// A value type that cannot be represented as a field element (e.g. strings, lists).
    TypeNotConstrainable(String, Option<SourceSpan>),
    /// A loop without a statically-known bound (e.g. `forever`, `while`).
    UnboundedLoop(Option<SourceSpan>),
    /// A builtin function was called with the wrong number of arguments.
    WrongArgumentCount {
        builtin: String,
        expected: usize,
        got: usize,
        span: Option<SourceSpan>,
    },
    /// An error during IR evaluation (early validation).
    EvalError(String),
}

impl fmt::Display for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            R1CSError::UndeclaredVariable(name, span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] undeclared variable in circuit: `{name}`")
                } else {
                    write!(f, "undeclared variable in circuit: `{name}`")
                }
            }
            R1CSError::UnsupportedOperation(op, span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] unsupported operation in circuit: {op}")
                } else {
                    write!(f, "unsupported operation in circuit: {op}")
                }
            }
            R1CSError::TypeNotConstrainable(ty, span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] type `{ty}` cannot be represented in a circuit")
                } else {
                    write!(f, "type `{ty}` cannot be represented in a circuit")
                }
            }
            R1CSError::UnboundedLoop(span) => {
                if let Some(s) = span {
                    write!(f, "[{s}] unbounded loops are not allowed in circuits")
                } else {
                    write!(f, "unbounded loops are not allowed in circuits")
                }
            }
            R1CSError::WrongArgumentCount {
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
            R1CSError::EvalError(msg) => write!(f, "evaluation error: {msg}"),
        }
    }
}

impl std::error::Error for R1CSError {}
