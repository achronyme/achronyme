use std::fmt;

use memory::ArenaError;

use crate::machine::prove::ProveError;

/// Extra detail for heap-limit errors.
#[derive(Debug)]
pub struct HeapLimitInfo {
    pub limit: usize,
    pub allocated: usize,
}

/// Extra detail for stale-handle errors.
#[derive(Debug)]
pub struct StaleHeapInfo {
    pub type_name: &'static str,
    pub context: &'static str,
}

/// Extra detail for I/O errors.
#[derive(Debug)]
pub struct IoErrorInfo {
    pub operation: String,
    pub detail: String,
}

/// Runtime error type — kept small (16 bytes) so that `Result<Value, RuntimeError>`
/// does not bloat the hot path. All data-carrying variants use `Box` to avoid
/// inflating the enum layout with inline `String` payloads.
#[derive(Debug)]
pub enum RuntimeError {
    // ── Zero-cost variants (no allocation) ──────────────────────────
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
    AssertionFailed,
    InstructionBudgetExhausted,
    ProveHandlerNotConfigured,
    StaleUpvalue,
    VerifyHandlerNotConfigured,
    ArenaCapacityExceeded,
    CircomHandlerNotConfigured,

    // ── Boxed variants (8-byte pointer, allocation on error only) ───
    TypeMismatch(Box<String>),
    ArityMismatch(Box<String>),
    OutOfBounds(Box<String>),
    ProveBlockFailed(Box<ProveError>),
    HeapLimitExceeded(Box<HeapLimitInfo>),
    StaleHeapHandle(Box<StaleHeapInfo>),
    UndefinedGlobal(Box<String>),
    ImmutableGlobal(Box<String>),
    IoError(Box<IoErrorInfo>),
    VerificationFailed(Box<String>),
    ResourceLimitExceeded(Box<String>),
}

// ── Convenience constructors (avoid `Box::new(...)` at every call site) ──

impl RuntimeError {
    #[inline]
    pub fn type_mismatch(msg: impl Into<String>) -> Self {
        Self::TypeMismatch(Box::new(msg.into()))
    }

    #[inline]
    pub fn arity_mismatch(msg: impl Into<String>) -> Self {
        Self::ArityMismatch(Box::new(msg.into()))
    }

    #[inline]
    pub fn out_of_bounds(msg: impl Into<String>) -> Self {
        Self::OutOfBounds(Box::new(msg.into()))
    }

    #[inline]
    pub fn prove_block_failed(e: ProveError) -> Self {
        Self::ProveBlockFailed(Box::new(e))
    }

    #[inline]
    pub fn heap_limit_exceeded(limit: usize, allocated: usize) -> Self {
        Self::HeapLimitExceeded(Box::new(HeapLimitInfo { limit, allocated }))
    }

    #[inline]
    pub fn stale_heap(type_name: &'static str, context: &'static str) -> Self {
        Self::StaleHeapHandle(Box::new(StaleHeapInfo { type_name, context }))
    }

    #[inline]
    pub fn undefined_global(name: impl Into<String>) -> Self {
        Self::UndefinedGlobal(Box::new(name.into()))
    }

    #[inline]
    pub fn immutable_global(name: impl Into<String>) -> Self {
        Self::ImmutableGlobal(Box::new(name.into()))
    }

    #[inline]
    pub fn io_error(operation: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::IoError(Box::new(IoErrorInfo {
            operation: operation.into(),
            detail: detail.into(),
        }))
    }

    #[inline]
    pub fn verification_failed(msg: impl Into<String>) -> Self {
        Self::VerificationFailed(Box::new(msg.into()))
    }

    #[inline]
    pub fn resource_limit_exceeded(msg: impl Into<String>) -> Self {
        Self::ResourceLimitExceeded(Box::new(msg.into()))
    }
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
            RuntimeError::HeapLimitExceeded(info) => {
                write!(
                    f,
                    "heap limit exceeded: {} bytes allocated, limit is {} bytes",
                    info.allocated, info.limit
                )
            }
            RuntimeError::StaleHeapHandle(info) => {
                write!(f, "stale {} handle in {}", info.type_name, info.context)
            }
            RuntimeError::StaleUpvalue => write!(f, "stale upvalue handle"),
            RuntimeError::UndefinedGlobal(name) => {
                write!(f, "undefined global variable: {name}")
            }
            RuntimeError::ImmutableGlobal(name) => {
                write!(f, "cannot assign to immutable global: {name}")
            }
            RuntimeError::IoError(info) => {
                write!(f, "{} failed: {}", info.operation, info.detail)
            }
            RuntimeError::VerifyHandlerNotConfigured => {
                write!(f, "verify handler not configured")
            }
            RuntimeError::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            RuntimeError::ResourceLimitExceeded(msg) => {
                write!(f, "resource limit exceeded: {msg}")
            }
            RuntimeError::ArenaCapacityExceeded => write!(f, "arena capacity exceeded u32::MAX"),
            RuntimeError::CircomHandlerNotConfigured => {
                write!(f, "circom template handler not configured")
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_error_is_compact() {
        assert!(
            std::mem::size_of::<RuntimeError>() <= 16,
            "RuntimeError grew to {} bytes — keep it ≤16 to avoid hot-path bloat",
            std::mem::size_of::<RuntimeError>()
        );
        assert!(
            std::mem::size_of::<Result<memory::Value, RuntimeError>>() <= 24,
            "Result<Value, RuntimeError> grew to {} bytes",
            std::mem::size_of::<Result<memory::Value, RuntimeError>>()
        );
    }
}
