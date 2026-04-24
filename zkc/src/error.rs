use std::fmt;

use ir::error::OptSpan;

fn fmt_span(span: &OptSpan) -> String {
    match span {
        Some(s) => format!("[{}] ", s),
        None => String::new(),
    }
}

/// Errors emitted by the R1CS compiler backend.
#[derive(Debug)]
pub enum R1CSError {
    /// Reference to a variable not previously declared with `public` or `witness`.
    UndeclaredVariable(String, OptSpan),
    /// An operation that has no R1CS translation (e.g. `print`, closures).
    UnsupportedOperation(String, OptSpan),
    /// A value type that cannot be represented as a field element (e.g. strings, lists).
    TypeNotConstrainable(String, OptSpan),
    /// A loop without a statically-known bound (e.g. `forever`, `while`).
    UnboundedLoop(OptSpan),
    /// A builtin function was called with the wrong number of arguments.
    WrongArgumentCount {
        builtin: String,
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// An error during IR evaluation (early validation).
    EvalError(String),
}

impl fmt::Display for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            R1CSError::UndeclaredVariable(name, span) => {
                write!(
                    f,
                    "{}undeclared variable in circuit: `{name}`",
                    fmt_span(span)
                )
            }
            R1CSError::UnsupportedOperation(op, span) => {
                write!(
                    f,
                    "{}unsupported operation in circuit: {op}",
                    fmt_span(span)
                )
            }
            R1CSError::TypeNotConstrainable(ty, span) => {
                write!(
                    f,
                    "{}type `{ty}` cannot be represented in a circuit",
                    fmt_span(span)
                )
            }
            R1CSError::UnboundedLoop(span) => {
                write!(
                    f,
                    "{}unbounded loops are not allowed in circuits",
                    fmt_span(span)
                )
            }
            R1CSError::WrongArgumentCount {
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
            R1CSError::EvalError(msg) => write!(f, "evaluation error: {msg}"),
        }
    }
}

impl std::error::Error for R1CSError {}
