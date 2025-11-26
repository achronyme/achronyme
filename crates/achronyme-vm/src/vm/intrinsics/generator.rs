//! Generator intrinsic methods

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;

/// Intrinsic implementation for Generator.next()
///
/// This is a marker function that signals to the Call opcode that it should
/// perform special generator resumption logic. The actual work happens in
/// the Call opcode handler when it detects an intrinsic call.
///
/// This function should not be called directly - it's only used for registry lookup.
pub fn generator_next(_vm: &VM, _receiver: &Value, _args: &[Value]) -> Result<Value, VmError> {
    // This should never be called directly - the Call opcode intercepts intrinsic calls
    Err(VmError::Runtime(
        "generator_next intrinsic should be handled by Call opcode, not called directly"
            .to_string(),
    ))
}
