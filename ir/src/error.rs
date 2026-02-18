use std::fmt;

/// Errors emitted during IR lowering.
#[derive(Debug)]
pub enum IrError {
    /// Reference to a variable not previously declared with `public` or `witness`.
    UndeclaredVariable(String),
    /// An operation that has no circuit translation.
    UnsupportedOperation(String),
    /// A value type that cannot be represented as a field element.
    TypeNotConstrainable(String),
    /// A loop without a statically-known bound.
    UnboundedLoop,
    /// The input failed to parse.
    ParseError(String),
    /// A builtin function was called with the wrong number of arguments.
    WrongArgumentCount {
        builtin: String,
        expected: usize,
        got: usize,
    },
}

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IrError::UndeclaredVariable(name) => {
                write!(f, "undeclared variable in circuit: `{name}`")
            }
            IrError::UnsupportedOperation(op) => {
                write!(f, "unsupported operation in circuit: {op}")
            }
            IrError::TypeNotConstrainable(ty) => {
                write!(f, "type `{ty}` cannot be represented in a circuit")
            }
            IrError::UnboundedLoop => {
                write!(f, "unbounded loops are not allowed in circuits")
            }
            IrError::ParseError(msg) => {
                write!(f, "parse error: {msg}")
            }
            IrError::WrongArgumentCount {
                builtin,
                expected,
                got,
            } => {
                write!(f, "`{builtin}` expects {expected} arguments, got {got}")
            }
        }
    }
}

impl std::error::Error for IrError {}
