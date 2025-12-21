#[derive(Debug, Clone)]
pub enum CompilerError {
    ParseError(String),
    UnknownOperator(String),
    InvalidNumber,
    TooManyConstants,
    InvalidComplex,
    UnexpectedRule(String),
    MissingOperand,
    RegisterOverflow,
    CompilerLimitation(String),
}

impl From<String> for CompilerError {
    fn from(s: String) -> Self {
        CompilerError::ParseError(s)
    }
}

impl From<&str> for CompilerError {
    fn from(s: &str) -> Self {
        CompilerError::ParseError(s.to_string())
    }
}
