//! Built-in function execution
//!
//! This module handles execution of the CallBuiltin opcode, which calls
//! native Rust functions registered in the built-in registry.

use crate::error::VmError;
use crate::opcode::instruction::*;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;

impl VM {
    /// Execute CallBuiltin opcode
    ///
    /// Format: CallBuiltin dest(A), argc(B), builtin_idx(C)
    /// - dest: Register to store result
    /// - argc: Number of arguments
    /// - builtin_idx: Index in built-in registry (u8 in C field, or u16 in Bx field)
    ///
    /// Arguments are expected to be in consecutive registers starting at dest+1
    pub(crate) fn execute_call_builtin(
        &self,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let dest = decode_a(instruction);

        // Always use ABC format: A = dest, B = argc, C = builtin_idx
        // The compiler always emits ABC format for built-ins (limited to 256 functions)
        let builtin_idx = decode_c(instruction) as u16;
        let argc = decode_b(instruction);

        // Get function metadata
        let metadata = self
            .builtins
            .get_metadata(builtin_idx)
            .ok_or_else(|| VmError::Runtime(format!("Unknown builtin index: {}", builtin_idx)))?;

        // Collect arguments from consecutive registers
        let args_start = (dest as usize + 1) % 256;
        let mut args = Vec::with_capacity(argc as usize);

        for i in 0..argc {
            let reg_idx = ((args_start + i as usize) % 256) as u8;
            args.push(self.get_register(reg_idx)?.clone());
        }

        // Validate arity for non-variadic functions
        if metadata.arity >= 0 && args.len() != metadata.arity as usize {
            return Err(VmError::Runtime(format!(
                "{}() expects {} arguments, got {}",
                metadata.name,
                metadata.arity,
                args.len()
            )));
        }

        // Call the native function
        let native_fn = metadata.func;
        let result = native_fn(self, &args)?;

        // Store result in destination register
        self.set_register(dest, result)?;

        Ok(ExecutionResult::Continue)
    }
}
