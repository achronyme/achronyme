//! Execution result types

use crate::value::Value;

/// Result of instruction execution
#[derive(Debug)]
pub(crate) enum ExecutionResult {
    /// Continue to next instruction
    Continue,
    /// Return from function
    Return(Value),
    /// Yield from generator
    Yield(Value),
    /// Exception thrown (starts unwinding)
    Exception(Value),
}
