
#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeError {
    StackOverflow,
    StackUnderflow,
    InvalidOpcode(u8),
    FunctionNotFound,
    InvalidOperand,
    DivisionByZero,
    TypeMismatch(String),
    Unknown(String),
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
