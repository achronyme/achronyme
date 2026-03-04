use std::fmt;

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
    BigIntOverflow,
    BigIntUnderflow,
    BigIntWidthMismatch,
    TypeMismatch(String),
    ArityMismatch(String),
    AssertionFailed,
    Unknown(String),
    OutOfBounds(String),
    SystemError(String),
    ProveBlockFailed(ProveError),
    ProveHandlerNotConfigured,
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuntimeError::StackOverflow => write!(f, "stack overflow"),
            RuntimeError::StackUnderflow => write!(f, "stack underflow"),
            RuntimeError::InvalidOpcode(op) => write!(f, "invalid opcode: {op}"),
            RuntimeError::FunctionNotFound => write!(f, "function not found"),
            RuntimeError::InvalidOperand => write!(f, "invalid operand"),
            RuntimeError::DivisionByZero => write!(f, "division by zero"),
            RuntimeError::IntegerOverflow => write!(f, "integer overflow"),
            RuntimeError::BigIntOverflow => write!(f, "BigInt overflow"),
            RuntimeError::BigIntUnderflow => write!(f, "BigInt underflow"),
            RuntimeError::BigIntWidthMismatch => write!(f, "BigInt width mismatch"),
            RuntimeError::TypeMismatch(msg) => write!(f, "type mismatch: {msg}"),
            RuntimeError::ArityMismatch(msg) => write!(f, "arity mismatch: {msg}"),
            RuntimeError::AssertionFailed => write!(f, "assertion failed"),
            RuntimeError::Unknown(msg) => write!(f, "{msg}"),
            RuntimeError::OutOfBounds(msg) => write!(f, "out of bounds: {msg}"),
            RuntimeError::SystemError(msg) => write!(f, "system error: {msg}"),
            RuntimeError::ProveBlockFailed(e) => write!(f, "prove block failed: {e}"),
            RuntimeError::ProveHandlerNotConfigured => {
                write!(f, "prove handler not configured")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}
