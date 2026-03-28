use crate::error::RuntimeError;
use memory::Value;

/// Trait for stack operations (registers).
///
/// # Safety
///
/// `get_reg` and `set_reg` use unchecked indexing for performance.
/// This is safe because every frame entry validates `base + max_slots < STACK_MAX`
/// (see `interpreter.rs:34` and `control.rs:78`), and the stack is pre-allocated
/// with `STACK_MAX` (65 536) slots at VM creation. All register indices decoded
/// from bytecode are < `max_slots` (enforced by the compiler).
pub trait StackOps {
    fn get_reg(&self, base: usize, reg: usize) -> Result<Value, RuntimeError>;
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) -> Result<(), RuntimeError>;
}

impl StackOps for super::vm::VM {
    #[inline(always)]
    fn get_reg(&self, base: usize, reg: usize) -> Result<Value, RuntimeError> {
        let idx = base + reg;
        debug_assert!(idx < self.stack.len(), "register OOB: {idx}");
        // SAFETY: frame entry checks `base + max_slots < STACK_MAX` and
        // all register operands are < max_slots (compiler invariant).
        Ok(unsafe { *self.stack.get_unchecked(idx) })
    }

    #[inline(always)]
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) -> Result<(), RuntimeError> {
        let idx = base + reg;
        debug_assert!(idx < self.stack.len(), "register OOB: {idx}");
        // SAFETY: same invariant as get_reg.
        unsafe { *self.stack.get_unchecked_mut(idx) = val };
        Ok(())
    }
}
