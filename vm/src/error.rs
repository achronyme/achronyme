use crate::machine::prove::ProveError;

#[derive(Debug)]
pub enum RuntimeError {
    StackOverflow,
    StackUnderflow,
    InvalidOpcode(u8),
    FunctionNotFound,
    InvalidOperand,
    DivisionByZero,
    IntegerOverflow,
    TypeMismatch(String),
    ArityMismatch(String),
    AssertionFailed,
    Unknown(String),
    OutOfBounds(String),
    SystemError(String),
    ProveBlockFailed(ProveError),
    ProveHandlerNotConfigured,
}

impl From<String> for RuntimeError {
    fn from(s: String) -> Self {
        RuntimeError::Unknown(s)
    }
}

impl From<&str> for RuntimeError {
    fn from(s: &str) -> Self {
        RuntimeError::Unknown(s.to_string())
    }
}
