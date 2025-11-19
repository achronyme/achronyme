//! Virtual Machine implementation

use crate::bytecode::BytecodeModule;
use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use std::collections::HashMap;
use std::rc::Rc;

// Module structure
mod execution;
mod frame;
mod ops;
mod result;

// Re-export public types
pub use frame::{CallFrame, RegisterWindow, SuspendedFrame, MAX_REGISTERS};

// Internal imports
use frame::CallFrame as InternalCallFrame;
use result::ExecutionResult;

/// Maximum call stack depth
pub const MAX_CALL_DEPTH: usize = 10000;

/// Virtual Machine
pub struct VM {
    /// Call stack
    pub(crate) frames: Vec<InternalCallFrame>,

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
        let main_frame = InternalCallFrame::new(Rc::new(module.main), None);
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
        match opcode {
            // Variable and constant operations
            OpCode::LoadConst | OpCode::LoadNull | OpCode::LoadTrue | OpCode::LoadFalse
            | OpCode::LoadImmI8 | OpCode::Move | OpCode::GetUpvalue | OpCode::SetUpvalue => {
                self.execute_variables(opcode, instruction)
            }

            // Arithmetic operations
            OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Neg => {
                self.execute_arithmetic(opcode, instruction)
            }

            // Comparison operations
            OpCode::Eq | OpCode::Lt | OpCode::Le | OpCode::Gt | OpCode::Ge | OpCode::Ne => {
                self.execute_comparison(opcode, instruction)
            }

            // Control flow
            OpCode::Jump | OpCode::JumpIfTrue | OpCode::JumpIfFalse | OpCode::Return
            | OpCode::ReturnNull => self.execute_control(opcode, instruction),

            // Functions and closures
            OpCode::Closure | OpCode::Call => self.execute_functions(opcode, instruction),

            // Vectors
            OpCode::NewVector | OpCode::VecPush | OpCode::VecGet | OpCode::VecSet => {
                self.execute_vectors(opcode, instruction)
            }

            // Records
            OpCode::NewRecord | OpCode::GetField | OpCode::SetField => {
                self.execute_records(opcode, instruction)
            }

            // Not yet implemented
            _ => Err(VmError::Runtime(format!(
                "Opcode {} not yet implemented",
                opcode
            ))),
        }
    }

    // ===== Helper methods =====

    /// Get current call frame
    pub(crate) fn current_frame(&self) -> Result<&InternalCallFrame, VmError> {
        self.frames.last().ok_or(VmError::StackUnderflow)
    }

    /// Get current call frame (mutable)
    pub(crate) fn current_frame_mut(&mut self) -> Result<&mut InternalCallFrame, VmError> {
        self.frames.last_mut().ok_or(VmError::StackUnderflow)
    }

    /// Get register from current frame
    pub(crate) fn get_register(&self, idx: u8) -> Result<&Value, VmError> {
        self.current_frame()?.registers.get(idx)
    }

    /// Set register in current frame
    pub(crate) fn set_register(&mut self, idx: u8, value: Value) -> Result<(), VmError> {
        self.current_frame_mut()?.registers.set(idx, value)
    }

    /// Get constant from current frame's function
    pub(crate) fn get_constant(&self, idx: usize) -> Result<&Value, VmError> {
        self.current_frame()?
            .function
            .constants
            .get_constant(idx)
            .ok_or(VmError::InvalidConstant(idx))
    }

    /// Get string from constant pool
    pub(crate) fn get_string(&self, idx: usize) -> Result<&str, VmError> {
        self.current_frame()?
            .function
            .constants
            .get_string(idx)
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
}

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}
