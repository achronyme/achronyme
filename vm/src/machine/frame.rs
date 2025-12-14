/// Represents a single call frame in the execution stack.
///
/// Each frame tracks:
/// - `closure`: Handle to the Function object in the heap
/// - `ip`: Instruction Pointer (current bytecode index)
/// - `base`: Base offset in the value stack for this frame's registers
#[derive(Debug, Clone)]
pub struct CallFrame {
    pub closure: u32,
    pub ip: usize,
    pub base: usize,
}

impl CallFrame {
    pub fn new(closure: u32, base: usize) -> Self {
        Self {
            closure,
            ip: 0,
            base,
        }
    }
}
