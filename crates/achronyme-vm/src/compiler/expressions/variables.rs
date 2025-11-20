//! Variable expression compilation

use crate::compiler::constants;
use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};

impl Compiler {
    /// Compile variable reference
    pub(crate) fn compile_variable_ref(
        &mut self,
        name: &str,
    ) -> Result<RegResult, CompileError> {
        // Check if this is an upvalue first
        if let Some(upvalue_idx) = self.symbols.get_upvalue(name) {
            // Emit GET_UPVALUE instruction (this creates a copy, so it's temp)
            let dst = self.registers.allocate()?;
            self.emit(encode_abc(OpCode::GetUpvalue.as_u8(), dst, upvalue_idx, 0));
            return Ok(RegResult::temp(dst));
        }

        // Check if this is a local variable
        if let Ok(var_reg) = self.symbols.get(name) {
            // Regular local variable (not a temp, it's the variable itself)
            return Ok(RegResult::var(var_reg));
        }

        // If not a local variable or upvalue, check if it's a predefined constant
        if let Some(const_value) = constants::get_constant(name) {
            let reg = self.registers.allocate()?;
            let const_idx = self.add_constant(const_value)?;
            self.emit_load_const(reg, const_idx);
            return Ok(RegResult::temp(reg));
        }

        // Variable not found
        Err(CompileError::Error(format!("Undefined variable: {}", name)))
    }

    /// Compile recursive reference
    pub(crate) fn compile_rec_reference(&mut self) -> Result<RegResult, CompileError> {
        // 'rec' refers to the current function being defined
        // Register 255 is reserved for this purpose
        // This is a special variable, not a temp
        Ok(RegResult::var(255))
    }
}
