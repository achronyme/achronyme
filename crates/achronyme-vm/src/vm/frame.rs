//! Call frame implementation

use crate::bytecode::FunctionPrototype;
use crate::error::VmError;
use crate::value::Value;
use std::cell::RefCell;
use std::rc::Rc;

/// Maximum number of registers per function (8-bit addressing)
pub const MAX_REGISTERS: usize = 256;

/// Exception handler entry
#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    /// Instruction pointer to jump to (catch block start)
    pub catch_ip: usize,
    /// Register to store the error value
    pub error_reg: u8,
}

/// Register window for a call frame
#[derive(Debug, Clone)]
pub struct RegisterWindow {
    /// Registers (max 256)
    registers: Vec<Value>,
}

impl RegisterWindow {
    /// Create a new register window with specified size
    pub fn new(size: usize) -> Self {
        Self {
            registers: vec![Value::Null; size.min(MAX_REGISTERS)],
        }
    }

    /// Resize register window to accommodate more registers
    pub fn resize(&mut self, new_size: usize) {
        let new_size = new_size.min(MAX_REGISTERS);
        if new_size > self.registers.len() {
            self.registers.resize(new_size, Value::Null);
        }
    }

    /// Get register value
    #[inline]
    pub fn get(&self, idx: u8) -> Result<&Value, VmError> {
        if idx as usize >= self.registers.len() {
            eprintln!(
                "ERROR: Trying to get R{} but only {} registers available",
                idx,
                self.registers.len()
            );
        }
        self.registers
            .get(idx as usize)
            .ok_or(VmError::InvalidRegister(idx))
    }

    /// Set register value
    #[inline]
    pub fn set(&mut self, idx: u8, value: Value) -> Result<(), VmError> {
        let idx = idx as usize;
        if idx >= self.registers.len() {
            eprintln!(
                "ERROR: Trying to set R{} but only {} registers available",
                idx,
                self.registers.len()
            );
            eprintln!("       Value: {:?}", value);
            return Err(VmError::InvalidRegister(idx as u8));
        }
        self.registers[idx] = value;
        Ok(())
    }

    /// Get mutable reference to register
    #[inline]
    pub fn get_mut(&mut self, idx: u8) -> Result<&mut Value, VmError> {
        self.registers
            .get_mut(idx as usize)
            .ok_or(VmError::InvalidRegister(idx))
    }
}

/// Call frame (function activation record)
#[derive(Debug, Clone)]
pub struct CallFrame {
    /// Function being executed
    pub function: Rc<FunctionPrototype>,

    /// Instruction pointer (current position in code)
    pub ip: usize,

    /// Register window for this frame
    pub registers: RegisterWindow,

    /// Captured upvalues (for closures)
    pub upvalues: Vec<Rc<RefCell<Value>>>,

    /// Return register in caller's frame
    pub return_register: Option<u8>,

    /// Generator reference (if this frame belongs to a generator)
    /// When this frame yields, it updates the generator state
    pub generator: Option<Value>,

    /// Exception handlers active in this frame
    pub handlers: Vec<ExceptionHandler>,
}

impl CallFrame {
    /// Create a new call frame
    pub fn new(function: Rc<FunctionPrototype>, return_register: Option<u8>) -> Self {
        // register_count is the number of registers needed
        // Since u8 can't represent 256, we use 255 to mean "all 256 registers"
        let size = if function.register_count == 255 {
            256
        } else {
            function.register_count as usize
        };
        let registers = RegisterWindow::new(size);

        Self {
            function,
            ip: 0,
            registers,
            upvalues: Vec::new(),
            return_register,
            generator: None,
            handlers: Vec::new(),
        }
    }

    /// Fetch current instruction and advance IP
    pub fn fetch(&mut self) -> Option<u32> {
        let instruction = self.function.code.get(self.ip).copied();
        if instruction.is_some() {
            self.ip += 1;
        }
        instruction
    }

    /// Get current instruction without advancing
    pub fn current_instruction(&self) -> Option<u32> {
        self.function.code.get(self.ip).copied()
    }

    /// Jump to offset (relative to current IP)
    pub fn jump(&mut self, offset: i16) {
        self.ip = (self.ip as isize + offset as isize) as usize;
    }

    /// Jump to absolute position
    pub fn jump_to(&mut self, pos: usize) {
        self.ip = pos;
    }
}

/// Generator state (suspended frame)
#[derive(Debug, Clone)]
pub struct SuspendedFrame {
    /// Saved call frame
    pub frame: CallFrame,

    /// Is the generator exhausted?
    pub done: bool,

    /// Sticky return value
    pub return_value: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::ConstantPool;

    #[test]
    fn test_register_window() {
        let mut window = RegisterWindow::new(10);

        window.set(0, Value::Number(42.0)).unwrap();
        window.set(1, Value::Boolean(true)).unwrap();

        assert_eq!(window.get(0).unwrap(), &Value::Number(42.0));
        assert_eq!(window.get(1).unwrap(), &Value::Boolean(true));

        assert!(window.set(255, Value::Null).is_err());
    }

    #[test]
    fn test_call_frame() {
        let constants = Rc::new(ConstantPool::new());
        let func = Rc::new(FunctionPrototype::new("test".to_string(), constants));
        let frame = CallFrame::new(func, None);

        assert_eq!(frame.ip, 0);
        assert_eq!(frame.return_register, None);
    }
}
