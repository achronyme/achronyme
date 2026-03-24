use std::fmt;

use memory::ArenaError;

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
    OutOfBounds(String),
    InstructionBudgetExhausted,
    ProveBlockFailed(ProveError),
    ProveHandlerNotConfigured,
    HeapLimitExceeded {
        limit: usize,
        allocated: usize,
    },
    /// Heap lookup returned None for a tagged value (GC or handle corruption).
    StaleHeapHandle {
        type_name: &'static str,
        context: &'static str,
    },
    /// Upvalue handle points to freed or missing slot.
    StaleUpvalue,
    /// Global variable not found.
    UndefinedGlobal {
        name: String,
    },
    /// Assignment to immutable global.
    ImmutableGlobal {
        name: String,
    },
    /// I/O operation failure.
    IoError {
        operation: String,
        detail: String,
    },
    /// Verify handler not configured.
    VerifyHandlerNotConfigured,
    /// Proof verification failed.
    VerificationFailed(String),
    /// Resource limit exceeded (e.g. string repeat size).
    ResourceLimitExceeded(String),
    /// Arena capacity exceeded (u32::MAX entries).
    ArenaCapacityExceeded,
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
            RuntimeError::OutOfBounds(msg) => write!(f, "out of bounds: {msg}"),
            RuntimeError::InstructionBudgetExhausted => {
                write!(f, "instruction budget exhausted")
            }
            RuntimeError::ProveBlockFailed(e) => write!(f, "prove block failed: {e}"),
            RuntimeError::ProveHandlerNotConfigured => {
                write!(f, "prove handler not configured")
            }
            RuntimeError::HeapLimitExceeded { limit, allocated } => {
                write!(
                    f,
                    "heap limit exceeded: {allocated} bytes allocated, limit is {limit} bytes"
                )
            }
            RuntimeError::StaleHeapHandle { type_name, context } => {
                write!(f, "stale {type_name} handle in {context}")
            }
            RuntimeError::StaleUpvalue => write!(f, "stale upvalue handle"),
            RuntimeError::UndefinedGlobal { name } => {
                write!(f, "undefined global variable: {name}")
            }
            RuntimeError::ImmutableGlobal { name } => {
                write!(f, "cannot assign to immutable global: {name}")
            }
            RuntimeError::IoError { operation, detail } => {
                write!(f, "{operation} failed: {detail}")
            }
            RuntimeError::VerifyHandlerNotConfigured => {
                write!(f, "verify handler not configured")
            }
            RuntimeError::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            RuntimeError::ResourceLimitExceeded(msg) => {
                write!(f, "resource limit exceeded: {msg}")
            }
            RuntimeError::ArenaCapacityExceeded => write!(f, "arena capacity exceeded u32::MAX"),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<ArenaError> for RuntimeError {
    fn from(e: ArenaError) -> Self {
        match e {
            ArenaError::CapacityExceeded => RuntimeError::ArenaCapacityExceeded,
        }
    }
}
