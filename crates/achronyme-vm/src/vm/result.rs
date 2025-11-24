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
    /// Await future: (Future/Generator, Destination Register)
    Await(Value, u8),
    /// Exception thrown (starts unwinding)
    Exception(Value),
}
