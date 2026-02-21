use crate::error::RuntimeError;
use memory::Value;

/// Trait for stack operations (registers)
pub trait StackOps {
    fn get_reg(&self, base: usize, reg: usize) -> Result<Value, RuntimeError>;
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) -> Result<(), RuntimeError>;
}

impl StackOps for super::vm::VM {
    #[inline(always)]
    fn get_reg(&self, base: usize, reg: usize) -> Result<Value, RuntimeError> {
        let idx = base + reg;
        self.stack.get(idx).copied().ok_or(RuntimeError::StackOverflow)
    }

    #[inline(always)]
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) -> Result<(), RuntimeError> {
        let idx = base + reg;
        let slot = self.stack.get_mut(idx).ok_or(RuntimeError::StackOverflow)?;
        *slot = val;
        Ok(())
    }
}
