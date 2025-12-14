use memory::Value;

/// Trait for stack operations (registers)
pub trait StackOps {
    fn get_reg(&self, base: usize, reg: usize) -> Value;
    fn set_reg(&mut self, base: usize, reg: usize, val: Value);
}

impl StackOps for super::vm::VM {
    #[inline]
    fn get_reg(&self, base: usize, reg: usize) -> Value {
        self.stack.get(base + reg).cloned().unwrap_or(Value::nil())
    }

    #[inline]
    fn set_reg(&mut self, base: usize, reg: usize, val: Value) {
        let idx = base + reg;
        if idx >= self.stack.len() {
            self.stack.resize(idx + 1, Value::nil());
        }
        self.stack[idx] = val;
    }
}
