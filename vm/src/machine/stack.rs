use memory::Value;

/// Trait for stack operations (registers)
pub trait StackOps {
    fn get_reg(&self, base: usize, reg: usize) -> Value;
    fn set_reg(&mut self, base: usize, reg: usize, val: Value);
}

impl StackOps for super::vm::VM {
    #[inline(always)]
    fn get_reg(&self, base: usize, reg: usize) -> Value {
        self.stack[base + reg]
    }

    #[inline(always)]
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) {
        self.stack[base + reg] = val;
    }
}
