//! Error types for the VM and compiler

use crate::value::Value;
use std::fmt;

/// VM runtime errors
#[derive(Debug, Clone, PartialEq)]
pub enum VmError {
    /// Stack overflow (too many call frames)
    StackOverflow,

    /// Stack underflow (pop from empty stack)
    StackUnderflow,

    /// Invalid register access
    InvalidRegister(u8),

    /// Invalid constant pool index
    InvalidConstant(usize),

    /// Invalid function prototype index
    InvalidFunction(usize),

    /// Type error during operation
    TypeError {
        operation: String,
        expected: String,
        got: String,
    },

    /// Division by zero
    DivisionByZero,

    /// Invalid opcode
    InvalidOpcode(u8),

    /// Invalid generator state
    InvalidGenerator,

    /// Generator already exhausted
    GeneratorExhausted,

    /// Uncaught exception
    UncaughtException(Value),

    /// Runtime error with message
    Runtime(String),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmError::StackOverflow => write!(f, "Stack overflow"),
            VmError::StackUnderflow => write!(f, "Stack underflow"),
            VmError::InvalidRegister(reg) => write!(f, "Invalid register: R{}", reg),
            VmError::InvalidConstant(idx) => write!(f, "Invalid constant index: {}", idx),
            VmError::InvalidFunction(idx) => write!(f, "Invalid function index: {}", idx),
            VmError::TypeError {
                operation,
                expected,
                got,
            } => {
                write!(
                    f,
                    "Type error in {}: expected {}, got {}",
                    operation, expected, got
                )
            }
            VmError::DivisionByZero => write!(f, "Division by zero"),
            VmError::InvalidOpcode(op) => write!(f, "Invalid opcode: {}", op),
            VmError::InvalidGenerator => write!(f, "Invalid generator"),
            VmError::GeneratorExhausted => write!(f, "Generator exhausted"),
            VmError::UncaughtException(value) => write!(f, "Uncaught exception: {:?}", value),
            VmError::Runtime(msg) => write!(f, "Runtime error: {}", msg),
        }
    }
}

impl std::error::Error for VmError {}

/// Compiler errors
#[derive(Debug, Clone, PartialEq)]
pub enum CompileError {
    /// Too many registers in function (max 256)
    TooManyRegisters,

    /// Too many constants (max 65536)
    TooManyConstants,

    /// Too many upvalues (max 256)
    TooManyUpvalues,

    /// Too many parameters (max 256)
    TooManyParameters,

    /// Undefined variable
    UndefinedVariable(String),

    /// Yield outside generator
    YieldOutsideGenerator,

    /// Break outside loop
    BreakOutsideLoop,

    /// Continue outside loop
    ContinueOutsideLoop,

    /// Return outside function
    ReturnOutsideFunction,

    /// Invalid assignment target
    InvalidAssignmentTarget,

    /// Code too large (instruction offset overflow)
    CodeTooLarge,

    /// Invalid pattern in this context
    InvalidPattern(String),

    /// Feature not yet implemented
    NotYetImplemented(String),

    /// Compiler error with message
    Error(String),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompileError::TooManyRegisters => {
                write!(f, "Too many registers (max 256)")
            }
            CompileError::TooManyConstants => {
                write!(f, "Too many constants (max 65536)")
            }
            CompileError::TooManyUpvalues => {
                write!(f, "Too many upvalues (max 256)")
            }
            CompileError::TooManyParameters => {
                write!(f, "Too many parameters (max 256)")
            }
            CompileError::UndefinedVariable(name) => {
                write!(f, "Undefined variable: {}", name)
            }
            CompileError::YieldOutsideGenerator => {
                write!(f, "Yield outside generator function")
            }
            CompileError::BreakOutsideLoop => {
                write!(f, "Break statement outside loop")
            }
            CompileError::ContinueOutsideLoop => {
                write!(f, "Continue statement outside loop")
            }
            CompileError::ReturnOutsideFunction => {
                write!(f, "Return statement outside function")
            }
            CompileError::InvalidAssignmentTarget => {
                write!(f, "Invalid assignment target")
            }
            CompileError::CodeTooLarge => {
                write!(f, "Code too large (instruction offset overflow)")
            }
            CompileError::InvalidPattern(msg) => {
                write!(f, "Invalid pattern: {}", msg)
            }
            CompileError::NotYetImplemented(feature) => {
                write!(f, "Not yet implemented: {}", feature)
            }
            CompileError::Error(msg) => write!(f, "Compiler error: {}", msg),
        }
    }
}

impl std::error::Error for CompileError {}
