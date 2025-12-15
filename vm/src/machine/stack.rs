use memory::Value;

/// Trait for stack operations (registers)
pub trait StackOps {
    fn get_reg(&self, base: usize, reg: usize) -> Value;
    fn set_reg(&mut self, base: usize, reg: usize, val: Value);
}

impl StackOps for super::vm::VM {
    #[inline(always)]
    fn get_reg(&self, base: usize, reg: usize) -> Value {
        // Safety Sandwich: Bounds check in debug builds only
        debug_assert!(
            base + reg < self.stack.len(),
            "VM OOB Read: Index {} >= Len {}",
            base + reg,
            self.stack.len()
        );
        unsafe { *self.stack.get_unchecked(base + reg) }
    }

    #[inline(always)]
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) {
        // Safety Sandwich: Bounds check in debug builds only
        debug_assert!(
            base + reg < self.stack.len(),
            "VM OOB Write: Index {} >= Len {}",
            base + reg,
            self.stack.len()
        );
        unsafe { *self.stack.get_unchecked_mut(base + reg) = val; }
    }
}
