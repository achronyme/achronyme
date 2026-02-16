use std::fmt;

/// Errors emitted by the R1CS compiler backend.
#[derive(Debug)]
pub enum R1CSError {
    /// Reference to a variable not previously declared with `public` or `witness`.
    UndeclaredVariable(String),
    /// An operation that has no R1CS translation (e.g. `print`, closures).
    UnsupportedOperation(String),
    /// A value type that cannot be represented as a field element (e.g. strings, lists).
    TypeNotConstrainable(String),
    /// A loop without a statically-known bound (e.g. `forever`, `while`).
    UnboundedLoop,
    /// The input failed to parse as a valid Achronyme program.
    ParseError(String),
}

impl fmt::Display for R1CSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            R1CSError::UndeclaredVariable(name) => {
                write!(f, "undeclared variable in circuit: `{name}`")
            }
            R1CSError::UnsupportedOperation(op) => {
                write!(f, "unsupported operation in circuit: {op}")
            }
            R1CSError::TypeNotConstrainable(ty) => {
                write!(f, "type `{ty}` cannot be represented in a circuit")
            }
            R1CSError::UnboundedLoop => {
                write!(f, "unbounded loops are not allowed in circuits")
            }
            R1CSError::ParseError(msg) => {
                write!(f, "parse error: {msg}")
            }
        }
    }
}

impl std::error::Error for R1CSError {}
