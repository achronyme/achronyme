//! Virtual Machine implementation

use crate::builtins::registry::BuiltinRegistry;
use crate::bytecode::BytecodeModule;
use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// Module structure
mod execution;
mod frame;
mod generator;
mod intrinsics;
mod iterator;
mod ops;
mod result;

// Re-export public types
pub use frame::{CallFrame, RegisterWindow, SuspendedFrame, MAX_REGISTERS};
pub use generator::{VmGeneratorRef, VmGeneratorState};
pub use iterator::{VmBuilder, VmIterator};

// Internal imports
use frame::CallFrame as InternalCallFrame;
use intrinsics::{IntrinsicFn, IntrinsicRegistry};
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
    #[allow(dead_code)]
    generators: HashMap<usize, SuspendedFrame>,

    /// Next generator ID
    #[allow(dead_code)]
    next_generator_id: usize,

    /// Built-in function registry
    pub(crate) builtins: BuiltinRegistry,

    /// Intrinsic method registry
    pub(crate) intrinsics: IntrinsicRegistry,

    /// Pending intrinsic calls (register -> (receiver, intrinsic_fn))
    /// Used to bind intrinsic methods to their receivers
    pub(crate) pending_intrinsic_calls: HashMap<u8, (Value, IntrinsicFn)>,

    /// Current module file path (for resolving relative imports)
    pub(crate) current_module: Option<String>,

    /// Global precision configuration
    /// None = full precision, Some(n) = round to n decimal places
    precision: Option<i32>,

    /// Epsilon threshold for considering values as zero
    epsilon: f64,
}

impl VM {
    /// Create a new VM
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(256),
            globals: HashMap::new(),
            generators: HashMap::new(),
            next_generator_id: 0,
            builtins: crate::builtins::create_builtin_registry(),
            intrinsics: IntrinsicRegistry::new(),
            pending_intrinsic_calls: HashMap::new(),
            current_module: None,
            precision: None, // Full precision by default
            epsilon: 1e-10,  // Default epsilon threshold
        }
    }

    /// Execute a bytecode module
    pub fn execute(&mut self, module: BytecodeModule) -> Result<Value, VmError> {
        // Set current module for import resolution
        self.current_module = Some(module.name.clone());

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
            let opcode = OpCode::from_u8(opcode_byte).ok_or(VmError::InvalidOpcode(opcode_byte))?;

            // Execute instruction
            match self.execute_instruction(opcode, instruction)? {
                ExecutionResult::Continue => continue,
                ExecutionResult::Return(value) => {
                    if self.frames.len() == 1 {
                        return Ok(value);
                    }
                    self.do_return(value)?;
                }
                ExecutionResult::Exception(error) => {
                    // Start unwinding
                    loop {
                        // Get current frame
                        let frame = match self.frames.last_mut() {
                            Some(f) => f,
                            None => {
                                // No more frames - uncaught exception
                                return Err(VmError::UncaughtException(error));
                            }
                        };

                        // Check if this frame has handlers
                        if let Some(handler) = frame.handlers.pop() {
                            // Found a handler!
                            // 1. Store error in the designated register
                            frame.registers.set(handler.error_reg, error.clone())?;
                            // 2. Jump to catch block
                            frame.jump_to(handler.catch_ip);
                            // 3. Resume execution
                            break;
                        }

                        // No handler in this frame
                        // Check if this is a generator frame and mark it as done
                        let is_generator = self
                            .frames
                            .last()
                            .and_then(|f| f.generator.as_ref())
                            .is_some();

                        if is_generator {
                            let gen_frame = self.frames.last().unwrap();
                            if let Some(ref gen_value) = gen_frame.generator {
                                if let Value::Generator(any_ref) = gen_value {
                                    if let Some(state_rc) =
                                        any_ref.downcast_ref::<std::cell::RefCell<
                                            crate::vm::generator::VmGeneratorState,
                                        >>()
                                    {
                                        let mut state = state_rc.borrow_mut();
                                        state.complete(None);
                                    }
                                }
                            }
                        }

                        // Pop frame and continue unwinding
                        self.frames.pop();
                    }
                    continue;
                }
                ExecutionResult::Yield(value) => {
                    // Pop the generator's frame and save it back
                    let gen_frame = self.frames.pop().ok_or(VmError::StackUnderflow)?;

                    // If this frame has a generator reference, update the generator state
                    if let Some(ref gen_value) = gen_frame.generator {
                        if let Value::Generator(any_ref) = gen_value {
                            if let Some(state_rc) = any_ref.downcast_ref::<std::cell::RefCell<crate::vm::generator::VmGeneratorState>>() {
                                let mut state = state_rc.borrow_mut();
                                // Save the frame state (clone before modifying to avoid borrow issues)
                                let mut saved_frame = gen_frame.clone();
                                saved_frame.generator = None; // Clear to avoid circular reference
                                state.frame = saved_frame;
                                drop(state);

                                // Create iterator result object: {value: <yielded>, done: false}
                                let mut result_map = std::collections::HashMap::new();
                                result_map.insert("value".to_string(), value);
                                result_map.insert("done".to_string(), Value::Boolean(false));
                                let result_record = Value::Record(Rc::new(RefCell::new(result_map)));

                                // Put iterator result record in the caller's return register
                                if let Some(return_reg) = gen_frame.return_register {
                                    if let Some(caller_frame) = self.frames.last_mut() {
                                        caller_frame.registers.set(return_reg, result_record)?;
                                    }
                                }

                                // Continue execution in caller frame
                                continue;
                            }
                        }
                    }

                    // No generator context - just return (shouldn't happen in normal execution)
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
            OpCode::LoadConst
            | OpCode::LoadNull
            | OpCode::LoadTrue
            | OpCode::LoadFalse
            | OpCode::LoadImmI8
            | OpCode::Move
            | OpCode::GetUpvalue
            | OpCode::SetUpvalue => self.execute_variables(opcode, instruction),

            // Arithmetic and logical operations
            OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Div
            | OpCode::Pow
            | OpCode::Neg
            | OpCode::Not => self.execute_arithmetic(opcode, instruction),

            // Comparison operations
            OpCode::Eq | OpCode::Lt | OpCode::Le | OpCode::Gt | OpCode::Ge | OpCode::Ne => {
                self.execute_comparison(opcode, instruction)
            }

            // Control flow
            OpCode::Jump
            | OpCode::JumpIfTrue
            | OpCode::JumpIfFalse
            | OpCode::JumpIfNull
            | OpCode::Return
            | OpCode::ReturnNull => self.execute_control(opcode, instruction),

            // Functions and closures
            OpCode::Closure | OpCode::Call | OpCode::TailCall => {
                self.execute_functions(opcode, instruction)
            }

            // Vectors
            OpCode::NewVector
            | OpCode::VecPush
            | OpCode::VecGet
            | OpCode::VecSet
            | OpCode::VecSlice => self.execute_vectors(opcode, instruction),

            // Records
            OpCode::NewRecord | OpCode::GetField | OpCode::SetField => {
                self.execute_records(opcode, instruction)
            }

            // Pattern Matching
            OpCode::MatchType
            | OpCode::MatchLit
            | OpCode::DestructureVec
            | OpCode::DestructureRec => self.execute_matching(opcode, instruction),

            // Generators
            OpCode::CreateGen | OpCode::Yield | OpCode::ResumeGen | OpCode::MakeIterator => {
                self.execute_generators(opcode, instruction)
            }

            // Exception Handling
            OpCode::Throw | OpCode::PushHandler | OpCode::PopHandler => {
                self.execute_exceptions(opcode, instruction)
            }

            // Type System
            OpCode::TypeCheck | OpCode::TypeAssert => self.execute_types(opcode, instruction),

            // Built-in Functions
            OpCode::CallBuiltin => self.execute_call_builtin(instruction),

            // Higher-Order Functions
            OpCode::IterInit => self.execute_iter_init(instruction),
            OpCode::IterNext => self.execute_iter_next(instruction),
            OpCode::BuildInit => self.execute_build_init(instruction),
            OpCode::BuildPush => self.execute_build_push(instruction),
            OpCode::BuildEnd => self.execute_build_end(instruction),

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

    /// Call a Value as a function with given arguments
    ///
    /// This is a helper method for HOF operations that need to call user-provided
    /// functions. It handles both VM closures and potentially other callable types.
    ///
    /// # Arguments
    /// * `func` - The function value to call
    /// * `args` - Slice of argument values
    ///
    /// # Returns
    /// * `Ok(Value)` - The return value from the function
    /// * `Err(VmError)` - If the call fails
    pub fn call_value(&mut self, func: &Value, args: &[Value]) -> Result<Value, VmError> {
        use crate::bytecode::Closure;
        use achronyme_types::function::Function;

        match func {
            Value::Function(Function::VmClosure(closure_any)) => {
                // Downcast from Rc<dyn Any> to Closure
                let closure = closure_any
                    .downcast_ref::<Closure>()
                    .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?;

                // Create new CallFrame (no return register needed for internal calls)
                let mut new_frame = CallFrame::new(closure.prototype.clone(), None);

                // Copy arguments to new frame's registers
                for (i, arg) in args.iter().enumerate() {
                    if i >= 256 {
                        return Err(VmError::Runtime("Too many arguments (max 256)".into()));
                    }
                    new_frame.registers.set(i as u8, arg.clone())?;
                }

                // Set upvalues
                new_frame.upvalues = closure.upvalues.clone();

                // Note: The 'rec' upvalue (index 0) is already set in new_frame.upvalues
                // No need to set register 255 anymore - 'rec' is accessed via GetUpvalue

                // Push frame
                self.frames.push(new_frame);

                // Execute until this frame returns
                loop {
                    // Check if we're still in the function we called
                    let frame_depth = self.frames.len();

                    // Get current frame
                    let frame = self.frames.last_mut().ok_or(VmError::StackUnderflow)?;

                    // Fetch instruction
                    let instruction = match frame.fetch() {
                        Some(inst) => inst,
                        None => {
                            // End of function, return null
                            if self.frames.len() == frame_depth {
                                self.frames.pop();
                                return Ok(Value::Null);
                            }
                            break;
                        }
                    };

                    // Decode and dispatch
                    let opcode_byte = decode_opcode(instruction);
                    let opcode =
                        OpCode::from_u8(opcode_byte).ok_or(VmError::InvalidOpcode(opcode_byte))?;

                    // Execute instruction
                    match self.execute_instruction(opcode, instruction)? {
                        ExecutionResult::Continue => {
                            // If we've returned from the function we called, extract the result
                            if self.frames.len() < frame_depth {
                                // The function returned, but we didn't capture the return value
                                // For HOF calls, we need to handle returns differently
                                return Ok(Value::Null);
                            }
                            continue;
                        }
                        ExecutionResult::Return(value) => {
                            // Pop the frame we created
                            if self.frames.len() >= frame_depth {
                                self.frames.pop();
                            }
                            return Ok(value);
                        }
                        ExecutionResult::Exception(error) => {
                            // Propagate exception
                            return Err(VmError::UncaughtException(error));
                        }
                        ExecutionResult::Yield(_) => {
                            return Err(VmError::Runtime(
                                "Cannot yield from function called via call_value".into(),
                            ));
                        }
                    }
                }

                Ok(Value::Null)
            }
            _ => Err(VmError::TypeError {
                operation: "function call".to_string(),
                expected: "Function or Closure".to_string(),
                got: format!("{:?}", func),
            }),
        }
    }

    /// Set a global variable (for REPL)
    pub fn set_global(&mut self, name: String, value: Value) {
        self.globals.insert(name, value);
    }

    /// Get a global variable (for REPL)
    pub fn get_global(&self, name: &str) -> Option<&Value> {
        self.globals.get(name)
    }

    /// Resume a generator by pushing its frame and continuing execution
    ///
    /// This is the core generator resume logic, extracted so it can be called
    /// from both the ResumeGen opcode and intrinsic dispatch.
    ///
    /// Returns ExecutionResult to indicate whether to continue, yield, etc.
    /// The yielded/returned value will be placed in the specified result_reg.
    pub(crate) fn resume_generator_internal(
        &mut self,
        gen_value: &Value,
        result_reg: u8,
    ) -> Result<ExecutionResult, VmError> {
        use crate::vm::execution::iterators::NativeIterator;

        // Extract generator from Value
        if let Value::Generator(any_ref) = gen_value {
            // First, try to downcast to native iterator
            if let Some(iter_rc) = any_ref.downcast_ref::<RefCell<NativeIterator>>() {
                // Handle native iterator
                let mut iter = iter_rc.borrow_mut();

                if let Some(value) = iter.next() {
                    // More elements available: {value: X, done: false}
                    drop(iter); // Release borrow
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), value);
                    result_map.insert("done".to_string(), Value::Boolean(false));
                    let result_record = Value::Record(Rc::new(RefCell::new(result_map)));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                } else {
                    // Iterator exhausted: {value: null, done: true}
                    drop(iter); // Release borrow
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(Rc::new(RefCell::new(result_map)));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                }
            }

            // Downcast from Rc<dyn Any> to Rc<RefCell<VmGeneratorState>>
            if let Some(state_rc) = any_ref.downcast_ref::<RefCell<VmGeneratorState>>() {
                let state = state_rc.borrow();

                // Check if generator is already exhausted
                if state.is_done() {
                    // Return iterator result object: {value: null, done: true}
                    drop(state); // Release borrow
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(Rc::new(RefCell::new(result_map)));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                }

                // Take the frame (clone it since we need to restore it later)
                let gen_frame = state.frame.clone();
                drop(state); // Release borrow before pushing frame

                // Push the generator's frame onto the stack
                // Set return register so the yielded value goes to result_reg
                // Set generator reference so Yield knows which generator to update
                let mut frame = gen_frame;
                frame.return_register = Some(result_reg);
                frame.generator = Some(gen_value.clone());
                self.frames.push(frame);

                return Ok(ExecutionResult::Continue);
            } else {
                return Err(VmError::Runtime(
                    "Invalid generator type (expected VM generator or native iterator)".to_string(),
                ));
            }
        } else {
            return Err(VmError::Runtime(format!(
                "Cannot resume non-generator value: {:?}",
                gen_value
            )));
        }
    }

    /// Set the global precision for number formatting and rounding
    pub fn set_precision(&mut self, decimals: i32) {
        if decimals < 0 {
            self.precision = None; // Full precision
        } else {
            self.precision = Some(decimals);
        }
    }

    /// Get the current precision setting
    pub fn get_precision(&self) -> Option<i32> {
        self.precision
    }

    /// Get the epsilon threshold
    pub fn get_epsilon(&self) -> f64 {
        self.epsilon
    }

    /// Apply precision rounding to a number
    pub fn apply_precision(&self, n: f64) -> f64 {
        if let Some(decimals) = self.precision {
            let factor = 10_f64.powi(decimals);
            (n * factor).round() / factor
        } else {
            n
        }
    }

    /// Check if a number is effectively zero (within epsilon)
    pub fn is_effectively_zero(&self, n: f64) -> bool {
        n.abs() < self.epsilon
    }

    /// Perform return from function
    fn do_return(&mut self, value: Value) -> Result<(), VmError> {
        let frame = self.frames.pop().ok_or(VmError::StackUnderflow)?;

        // Check if this is a generator frame
        if let Some(ref gen_value) = frame.generator {
            if let Value::Generator(any_ref) = gen_value {
                if let Some(state_rc) = any_ref
                    .downcast_ref::<std::cell::RefCell<crate::vm::generator::VmGeneratorState>>()
                {
                    let mut state = state_rc.borrow_mut();
                    // Mark generator as done
                    state.complete(Some(value.clone()));
                    drop(state);

                    // Create iterator result object: {value: null, done: true}
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(Rc::new(RefCell::new(result_map)));

                    // If there's a return register in caller, set it with the iterator result
                    if let Some(return_reg) = frame.return_register {
                        if let Some(caller_frame) = self.frames.last_mut() {
                            caller_frame.registers.set(return_reg, result_record)?;
                        }
                    }

                    return Ok(());
                }
            }
        }

        // Normal function return (not a generator)
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
