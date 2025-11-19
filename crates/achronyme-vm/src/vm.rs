//! Virtual Machine implementation

use crate::bytecode::{BytecodeModule, Closure, FunctionPrototype, UpvalueDescriptor};
use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_types::function::Function;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// Maximum number of registers per function (8-bit addressing)
pub const MAX_REGISTERS: usize = 256;

/// Maximum call stack depth
pub const MAX_CALL_DEPTH: usize = 10000;

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

    /// Get register value
    #[inline]
    pub fn get(&self, idx: u8) -> Result<&Value, VmError> {
        self.registers
            .get(idx as usize)
            .ok_or(VmError::InvalidRegister(idx))
    }

    /// Set register value
    #[inline]
    pub fn set(&mut self, idx: u8, value: Value) -> Result<(), VmError> {
        let idx = idx as usize;
        if idx >= self.registers.len() {
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
}

impl CallFrame {
    /// Create a new call frame
    pub fn new(function: Rc<FunctionPrototype>, return_register: Option<u8>) -> Self {
        // register_count is the number of registers needed
        // If register_count is 255, we need 256 registers (0-255) for recursion support
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

/// Virtual Machine
pub struct VM {
    /// Call stack
    frames: Vec<CallFrame>,

    /// Global variables
    globals: HashMap<String, Value>,

    /// Generator states (ID -> suspended frame)
    generators: HashMap<usize, SuspendedFrame>,

    /// Next generator ID
    next_generator_id: usize,
}

impl VM {
    /// Create a new VM
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(256),
            globals: HashMap::new(),
            generators: HashMap::new(),
            next_generator_id: 0,
        }
    }

    /// Execute a bytecode module
    pub fn execute(&mut self, module: BytecodeModule) -> Result<Value, VmError> {
        // Create main frame
        let main_frame = CallFrame::new(Rc::new(module.main), None);
        self.frames.push(main_frame);

        // Run until completion
        self.run()
    }

    /// Main execution loop
    fn run(&mut self) -> Result<Value, VmError> {
        loop {
            // Check stack depth
            if self.frames.len() > MAX_CALL_DEPTH {
                return Err(VmError::StackOverflow);
            }

            // Get current frame
            let frame = self.frames.last_mut().ok_or(VmError::StackUnderflow)?;

            // Fetch instruction
            let instruction = match frame.fetch() {
                Some(inst) => inst,
                None => {
                    // End of function, return null
                    if self.frames.len() == 1 {
                        // Main function ended
                        return Ok(Value::Null);
                    }
                    self.do_return(Value::Null)?;
                    continue;
                }
            };

            // Decode and dispatch
            let opcode_byte = decode_opcode(instruction);
            let opcode = OpCode::from_u8(opcode_byte)
                .ok_or(VmError::InvalidOpcode(opcode_byte))?;

            // Execute instruction
            match self.execute_instruction(opcode, instruction)? {
                ExecutionResult::Continue => continue,
                ExecutionResult::Return(value) => {
                    if self.frames.len() == 1 {
                        return Ok(value);
                    }
                    self.do_return(value)?;
                }
                ExecutionResult::Yield(value) => {
                    // For generators, we'll handle this later
                    return Ok(value);
                }
            }
        }
    }

    /// Execute a single instruction
    fn execute_instruction(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);
        let bx = decode_bx(instruction);

        match opcode {
            // ===== Constants & Moves =====
            OpCode::LoadConst => {
                let value = self.get_constant(bx as usize)?.clone();
                self.set_register(a, value)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadNull => {
                self.set_register(a, Value::Null)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadTrue => {
                self.set_register(a, Value::Boolean(true))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadFalse => {
                self.set_register(a, Value::Boolean(false))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::LoadImmI8 => {
                self.set_register(a, Value::Number(bx as i16 as f64))?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Move => {
                let value = self.get_register(b)?.clone();
                self.set_register(a, value)?;
                Ok(ExecutionResult::Continue)
            }

            // ===== Arithmetic =====
            OpCode::Add => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = self.add_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Sub => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;

                #[cfg(debug_assertions)]
                eprintln!("SUB DEBUG: R{} = R{} - R{} ({:?} - {:?})", a, b, c, left, right);

                let result = self.sub_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Mul => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;

                #[cfg(debug_assertions)]
                {
                    let r0 = self.get_register(0).ok();
                    eprintln!("MUL DEBUG: frame_depth={}, R{} = R{} * R{} ({:?} * {:?}), R0={:?}",
                              self.frames.len(), a, b, c, left, right, r0);
                }

                let result = self.mul_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Div => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = self.div_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Neg => {
                let value = self.get_register(b)?;
                let result = self.neg_value(value)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            // ===== Comparison =====
            OpCode::Eq => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = Value::Boolean(left == right);
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Lt => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = self.lt_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Le => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;

                #[cfg(debug_assertions)]
                eprintln!("LE DEBUG: R{} = R{} <= R{} ({:?} <= {:?})", a, b, c, left, right);

                let result = self.le_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Gt => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = self.gt_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Ge => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = self.ge_values(left, right)?;
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            OpCode::Ne => {
                let left = self.get_register(b)?;
                let right = self.get_register(c)?;
                let result = Value::Boolean(left != right);
                self.set_register(a, result)?;
                Ok(ExecutionResult::Continue)
            }

            // ===== Jumps =====
            OpCode::Jump => {
                let offset = decode_sbx(instruction);
                self.current_frame_mut()?.jump(offset);
                Ok(ExecutionResult::Continue)
            }

            OpCode::JumpIfTrue => {
                let cond = self.get_register(a)?;
                if self.is_truthy(cond) {
                    let offset = decode_sbx(instruction);
                    self.current_frame_mut()?.jump(offset);
                }
                Ok(ExecutionResult::Continue)
            }

            OpCode::JumpIfFalse => {
                let cond = self.get_register(a)?;
                if !self.is_truthy(cond) {
                    let offset = decode_sbx(instruction);
                    self.current_frame_mut()?.jump(offset);
                }
                Ok(ExecutionResult::Continue)
            }

            // ===== Return =====
            OpCode::Return => {
                let value = self.get_register(a)?.clone();

                #[cfg(debug_assertions)]
                {
                    let frame = self.current_frame()?;
                    eprintln!("RETURN DEBUG: IP={}, returning {:?} from R{}, will write to caller's R{:?}",
                              frame.ip, value, a, frame.return_register);
                }

                Ok(ExecutionResult::Return(value))
            }

            OpCode::ReturnNull => Ok(ExecutionResult::Return(Value::Null)),

            // ===== Functions =====
            OpCode::Closure => {
                let dst = a;
                let func_idx = bx as usize;

                // Get function prototype from current frame's function
                let prototype = self
                    .current_frame()?
                    .function
                    .functions
                    .get(func_idx)
                    .ok_or(VmError::InvalidFunction(func_idx))?
                    .clone();

                // Capture upvalues from current frame
                let mut upvalues = Vec::new();
                for upvalue_desc in &prototype.upvalues {
                    // For now, capture from current frame's registers
                    // TODO: Handle nested upvalues (upvalues from parent closure)
                    let value = self.get_register(upvalue_desc.register)?.clone();
                    upvalues.push(Rc::new(RefCell::new(value)));
                }

                // Create closure
                let closure = Closure::with_upvalues(Rc::new(prototype), upvalues);

                // Store as Function value using Rc<dyn Any>
                let func_value = Value::Function(Function::VmClosure(Rc::new(closure) as Rc<dyn std::any::Any>));
                self.set_register(dst, func_value)?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::Call => {
                let result_reg = a;
                let func_reg = b;
                let argc = c;

                let func_value = self.get_register(func_reg)?.clone();

                match func_value {
                    Value::Function(Function::VmClosure(closure_any)) => {
                        // Downcast from Rc<dyn Any> to Closure
                        let closure = closure_any
                            .downcast_ref::<Closure>()
                            .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?;

                        // Create new CallFrame
                        let mut new_frame = CallFrame::new(
                            closure.prototype.clone(),
                            Some(result_reg),
                        );

                        // DEBUG: Verify frame setup
                        #[cfg(debug_assertions)]
                        eprintln!("CALL DEBUG: depth={}, func_reg={}, argc={}, result_reg={}, frame_size={}",
                                  self.frames.len() + 1, func_reg, argc, result_reg, new_frame.registers.registers.len());

                        // Copy arguments to new frame's registers
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            let arg = self.get_register(arg_reg)?.clone();

                            #[cfg(debug_assertions)]
                            eprintln!("  Copying arg{}: R{} = {:?} -> new_frame.R{}",
                                      i, arg_reg, arg, i);

                            new_frame.registers.set(i, arg)?;
                        }

                        // Set upvalues
                        new_frame.upvalues = closure.upvalues.clone();

                        // Set register 255 to the closure itself for recursion
                        #[cfg(debug_assertions)]
                        eprintln!("  Setting R255 for recursion");

                        new_frame.registers.set(
                            255,
                            Value::Function(Function::VmClosure(Rc::new(closure.clone()) as Rc<dyn std::any::Any>)),
                        )?;

                        // Push frame
                        self.frames.push(new_frame);

                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "call".to_string(),
                        expected: "Function".to_string(),
                        got: format!("{:?}", func_value),
                    }),
                }
            }

            OpCode::GetUpvalue => {
                let dst = a;
                let upvalue_idx = b as usize;

                let upvalue = self
                    .current_frame()?
                    .upvalues
                    .get(upvalue_idx)
                    .ok_or(VmError::Runtime("Invalid upvalue index".to_string()))?;

                let value = upvalue.borrow().clone();
                self.set_register(dst, value)?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::SetUpvalue => {
                let upvalue_idx = a as usize;
                let src = b;

                let value = self.get_register(src)?.clone();
                let upvalue = self
                    .current_frame()?
                    .upvalues
                    .get(upvalue_idx)
                    .ok_or(VmError::Runtime("Invalid upvalue index".to_string()))?;

                *upvalue.borrow_mut() = value;

                Ok(ExecutionResult::Continue)
            }

            // ===== Not yet implemented =====
            _ => Err(VmError::Runtime(format!(
                "Opcode {} not yet implemented",
                opcode
            ))),
        }
    }

    // ===== Helper methods =====

    /// Get current call frame
    fn current_frame(&self) -> Result<&CallFrame, VmError> {
        self.frames.last().ok_or(VmError::StackUnderflow)
    }

    /// Get current call frame (mutable)
    fn current_frame_mut(&mut self) -> Result<&mut CallFrame, VmError> {
        self.frames.last_mut().ok_or(VmError::StackUnderflow)
    }

    /// Get register from current frame
    fn get_register(&self, idx: u8) -> Result<&Value, VmError> {
        self.current_frame()?.registers.get(idx)
    }

    /// Set register in current frame
    fn set_register(&mut self, idx: u8, value: Value) -> Result<(), VmError> {
        self.current_frame_mut()?.registers.set(idx, value)
    }

    /// Get constant from current frame's function
    fn get_constant(&self, idx: usize) -> Result<&Value, VmError> {
        self.current_frame()?
            .function
            .constants
            .get_constant(idx)
            .ok_or(VmError::InvalidConstant(idx))
    }

    /// Perform return from function
    fn do_return(&mut self, value: Value) -> Result<(), VmError> {
        let frame = self.frames.pop().ok_or(VmError::StackUnderflow)?;

        // If there's a return register in caller, set it
        if let Some(return_reg) = frame.return_register {
            if let Some(caller_frame) = self.frames.last_mut() {
                caller_frame.registers.set(return_reg, value)?;
            }
        }

        Ok(())
    }

    // ===== Value operations =====

    fn add_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a + b)),
            _ => Err(VmError::TypeError {
                operation: "addition".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} + {:?}", left, right),
            }),
        }
    }

    fn sub_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a - b)),
            _ => Err(VmError::TypeError {
                operation: "subtraction".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} - {:?}", left, right),
            }),
        }
    }

    fn mul_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a * b)),
            _ => Err(VmError::TypeError {
                operation: "multiplication".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} * {:?}", left, right),
            }),
        }
    }

    fn div_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                if *b == 0.0 {
                    Err(VmError::DivisionByZero)
                } else {
                    Ok(Value::Number(a / b))
                }
            }
            _ => Err(VmError::TypeError {
                operation: "division".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} / {:?}", left, right),
            }),
        }
    }

    fn neg_value(&self, value: &Value) -> Result<Value, VmError> {
        match value {
            Value::Number(n) => Ok(Value::Number(-n)),
            _ => Err(VmError::TypeError {
                operation: "negation".to_string(),
                expected: "Number".to_string(),
                got: format!("-{:?}", value),
            }),
        }
    }

    fn lt_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a < b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} < {:?}", left, right),
            }),
        }
    }

    fn le_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a <= b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} <= {:?}", left, right),
            }),
        }
    }

    fn gt_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a > b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} > {:?}", left, right),
            }),
        }
    }

    fn ge_values(&self, left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a >= b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} >= {:?}", left, right),
            }),
        }
    }

    fn is_truthy(&self, value: &Value) -> bool {
        match value {
            Value::Boolean(b) => *b,
            Value::Null => false,
            Value::Number(n) => *n != 0.0,
            _ => true,
        }
    }
}

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of instruction execution
#[derive(Debug)]
enum ExecutionResult {
    /// Continue to next instruction
    Continue,
    /// Return from function
    Return(Value),
    /// Yield from generator
    Yield(Value),
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let constants = Rc::new(crate::bytecode::ConstantPool::new());
        let func = Rc::new(FunctionPrototype::new("test".to_string(), constants));
        let frame = CallFrame::new(func, None);

        assert_eq!(frame.ip, 0);
        assert_eq!(frame.return_register, None);
    }
}
