//! Virtual Machine implementation

use crate::builtins::registry::BuiltinRegistry;
use crate::bytecode::BytecodeModule;
use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_types::sync::{shared, Arc, RwLock, Shared};
use achronyme_types::value::EffectState;
use std::collections::HashMap;

/// Trait for notifying external systems (like GUI) when signals change.
/// This allows the reactive system to trigger UI updates without direct coupling.
pub trait SignalNotifier: Send + Sync {
    fn notify(&self);
}

// Module structure
mod execution;
mod frame;
mod generator;
pub(crate) mod intrinsics;
mod iterator;
mod ops;
mod result;

// Re-export public types
pub use frame::{CallFrame, RegisterWindow, SuspendedFrame, MAX_REGISTERS};
pub use generator::{VmGeneratorRef, VmGeneratorState};
pub use iterator::{VmBuilder, VmIterator};

// Internal imports
use frame::CallFrame as InternalCallFrame;
use intrinsics::IntrinsicRegistry;
use result::ExecutionResult;

/// Maximum call stack depth
pub const MAX_CALL_DEPTH: usize = 10000;

/// Virtual Machine
pub struct VM {
    // --- Thread-Local State (No Locks) ---
    /// Call stack - directly owned by the thread's VM instance
    pub(crate) frames: Vec<InternalCallFrame>,

    /// Generator states (ID -> suspended frame)
    #[allow(dead_code)]
    pub(crate) generators: HashMap<usize, SuspendedFrame>,

    /// Current module file path (for resolving relative imports)
    pub(crate) current_module: Option<String>,

    /// Root scope for active effects to keep them alive
    pub(crate) active_effects: Vec<Shared<EffectState>>,

    /// Current effect being tracked during execution.
    pub(crate) tracking_effect: Option<Shared<EffectState>>,

    // --- Shared State (Thread-Safe) ---
    /// Global variables - Shared across threads
    pub(crate) globals: Shared<HashMap<String, Value>>,

    /// Built-in function registry - Immutable after init
    pub(crate) builtins: Arc<BuiltinRegistry>,

    /// Intrinsic method registry - Immutable after init
    pub(crate) intrinsics: Arc<IntrinsicRegistry>,

    /// Configuration - Shared
    config: Shared<VMConfig>,

    /// Shared signal notifier
    signal_notifier: Shared<Option<Arc<dyn SignalNotifier>>>,
}

/// Configuration that rarely changes
pub struct VMConfig {
    /// Global precision configuration
    /// None = full precision, Some(n) = round to n decimal places
    precision: Option<i32>,

    /// Epsilon threshold for considering values as zero
    epsilon: f64,
}

// Thread-safety guarantees
// VM is Send because it owns its data, but it is NOT Sync because of the RefCells/local state?
// Actually, Vec and HashMap are Send. So VM is Send.
// It is NOT Sync because `frames` cannot be accessed concurrently without locks.
// But that's fine, a VM instance represents a single thread of execution.
unsafe impl Send for VM {}
// unsafe impl Sync for VM {} // Explicitly NOT Sync if we wanted to be strict, but auto traits handle it.

impl VM {
    /// Create a new VM
    pub fn new() -> Self {
        Self {
            frames: Vec::with_capacity(256),
            generators: HashMap::new(),
            current_module: None,
            active_effects: Vec::new(),
            tracking_effect: None,

            globals: shared(HashMap::new()),
            builtins: Arc::new(crate::builtins::create_builtin_registry()),
            intrinsics: Arc::new(IntrinsicRegistry::new()),
            config: shared(VMConfig {
                precision: None, // Full precision by default
                epsilon: 1e-10,  // Default epsilon threshold
            }),
            signal_notifier: shared(None),
        }
    }

    /// Create a child VM that shares globals and signal notifier
    pub fn new_child(&self) -> Self {
        Self {
            frames: Vec::with_capacity(256),
            generators: HashMap::new(),
            current_module: None,
            active_effects: Vec::new(),
            tracking_effect: None,

            globals: self.globals.clone(),
            builtins: self.builtins.clone(),
            intrinsics: self.intrinsics.clone(),
            config: self.config.clone(),
            signal_notifier: self.signal_notifier.clone(),
        }
    }

    // --- Reactive Context Methods ---

    pub fn set_tracking_effect(&mut self, effect: Option<Shared<EffectState>>) {
        self.tracking_effect = effect;
    }

    pub fn get_tracking_effect(&self) -> Option<Shared<EffectState>> {
        self.tracking_effect.clone()
    }

    pub fn set_signal_notifier(&self, notifier: Option<Arc<dyn SignalNotifier>>) {
        *self.signal_notifier.write() = notifier;
    }

    pub fn notify_signal_change(&self) {
        if let Some(notifier) = &*self.signal_notifier.read() {
            notifier.notify();
        }
    }

    /// Execute a bytecode module
    pub async fn execute(&mut self, module: BytecodeModule) -> Result<Value, VmError> {
        // Set current module for import resolution
        self.current_module = Some(module.name.clone());

        // Create main frame
        let main_frame = InternalCallFrame::new(Arc::new(module.main), None);
        self.frames.push(main_frame);

        // Run until completion
        self.run().await
    }

    /// Main execution loop
    pub(crate) async fn run(&mut self) -> Result<Value, VmError> {
        loop {
            // 1. Fetch instruction - No locks!
            if self.frames.len() > MAX_CALL_DEPTH {
                return Err(VmError::StackOverflow);
            }

            let (instruction, is_main_return) = match self.frames.last_mut() {
                Some(frame) => {
                    match frame.fetch() {
                        Some(inst) => (inst, false),
                        None => {
                            // End of function
                            if self.frames.len() == 1 {
                                return Ok(Value::Null);
                            }
                            (0, true) // Signal return
                        }
                    }
                }
                None => return Err(VmError::StackUnderflow),
            };

            if is_main_return {
                self.do_return(Value::Null)?;
                continue;
            }

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
                    // Unwinding logic - No locks!
                    loop {
                        let frame_idx = self.frames.len().checked_sub(1);
                        match frame_idx {
                            Some(idx) => {
                                // Check for handlers
                                // We need to access frame mutably, but we also need to index self.frames
                                // Splitting borrow is tricky with Vec index.
                                // We can just take the last frame since we are unwinding stack top-down.

                                // Peek at the last frame
                                let has_handler = self.frames[idx].handlers.last().is_some();

                                if has_handler {
                                    let frame = &mut self.frames[idx];
                                    let handler = frame.handlers.pop().unwrap();
                                    frame.registers.set(handler.error_reg, error.clone())?;
                                    frame.jump_to(handler.catch_ip);
                                    break; // Resume execution
                                }

                                // No handler, clean up generator if needed
                                let frame = &mut self.frames[idx];
                                if let Some(Value::Generator(any_ref)) = frame.generator.as_ref() {
                                    if let Some(gen_state_lock) = any_ref
                                        .downcast_ref::<RwLock<crate::vm::generator::VmGeneratorState>>()
                                    {
                                        let mut gen_state = gen_state_lock.write();
                                        gen_state.complete(None);
                                    }
                                }

                                self.frames.pop();
                            }
                            None => return Err(VmError::UncaughtException(error)),
                        }
                    }
                    continue;
                }
                ExecutionResult::Yield(value) => {
                    let gen_frame = self.frames.pop().ok_or(VmError::StackUnderflow)?;

                    if let Some(Value::Generator(any_ref)) = gen_frame.generator.as_ref() {
                        if let Some(gen_state_lock) =
                            any_ref.downcast_ref::<RwLock<crate::vm::generator::VmGeneratorState>>()
                        {
                            let mut gen_state = gen_state_lock.write();
                            let mut saved_frame = gen_frame.clone();
                            saved_frame.generator = None;
                            gen_state.frame = saved_frame;
                            drop(gen_state);

                            let mut result_map = HashMap::new();
                            result_map.insert("value".to_string(), value);
                            result_map.insert("done".to_string(), Value::Boolean(false));
                            let result_record = Value::Record(shared(result_map));

                            if let Some(return_reg) = gen_frame.return_register {
                                if let Some(caller_frame) = self.frames.last_mut() {
                                    caller_frame.registers.set(return_reg, result_record)?;
                                }
                            }
                            continue;
                        }
                    }
                    return Ok(value);
                }
                ExecutionResult::Await(value, dst_reg) => {
                    match value {
                        Value::Future(vm_future) => {
                            let future = vm_future.0.clone();
                            // Await future (suspends async task, not thread)
                            let result = future.await;
                            self.set_register(dst_reg, result)?;
                        }
                        Value::Generator(_) => {
                            match self.resume_generator_internal(&value, dst_reg)? {
                                ExecutionResult::Continue => continue,
                                _ => continue,
                            }
                        }
                        _ => {
                            return Err(VmError::Runtime(format!(
                                "Value not awaitable: {:?}",
                                value
                            )))
                        }
                    }
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
            | OpCode::SetUpvalue
            | OpCode::GetGlobal
            | OpCode::SetGlobal => self.execute_variables(opcode, instruction),

            // Arithmetic and logical operations
            OpCode::Add
            | OpCode::Sub
            | OpCode::Mul
            | OpCode::Div
            | OpCode::Mod
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
            | OpCode::VecSpread
            | OpCode::VecGet
            | OpCode::VecSet
            | OpCode::VecSlice
            | OpCode::RangeEx
            | OpCode::TensorGet => self.execute_vectors(opcode, instruction),

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
            OpCode::CreateGen
            | OpCode::Yield
            | OpCode::ResumeGen
            | OpCode::MakeIterator
            | OpCode::Await => self.execute_generators(opcode, instruction),

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

            _ => Err(VmError::Runtime(format!(
                "Opcode {} not yet implemented",
                opcode
            ))),
        }
    }

    // ===== Helper methods (Now Lock-Free or &mut self) =====

    /// Get register from current frame (cloned value)
    #[inline]
    pub(crate) fn get_register(&self, idx: u8) -> Result<Value, VmError> {
        let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;
        frame.registers.get(idx).cloned()
    }

    /// Set register in current frame
    #[inline]
    pub(crate) fn set_register(&mut self, idx: u8, value: Value) -> Result<(), VmError> {
        let frame = self.frames.last_mut().ok_or(VmError::StackUnderflow)?;
        frame.registers.set(idx, value)
    }

    /// Get constant from current frame's function
    #[inline]
    pub(crate) fn get_constant(&self, idx: usize) -> Result<Value, VmError> {
        let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;
        frame
            .function
            .constants
            .get_constant(idx)
            .cloned()
            .ok_or(VmError::InvalidConstant(idx))
    }

    /// Get string from constant pool
    #[inline]
    pub(crate) fn get_string(&self, idx: usize) -> Result<String, VmError> {
        let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;
        frame
            .function
            .constants
            .get_string(idx)
            .map(|s| s.to_string())
            .ok_or(VmError::InvalidConstant(idx))
    }

    /// Call a Value as a function with given arguments
    pub fn call_value(&mut self, func: &Value, args: &[Value]) -> Result<Value, VmError> {
        use crate::bytecode::Closure;
        use achronyme_types::function::Function;

        match func {
            Value::Function(Function::VmClosure(closure_any)) => {
                let closure = closure_any
                    .downcast_ref::<Closure>()
                    .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?;

                let mut new_frame = CallFrame::new(closure.prototype.clone(), None);

                for (i, arg) in args.iter().enumerate() {
                    if i >= 256 {
                        return Err(VmError::Runtime("Too many arguments (max 256)".into()));
                    }
                    new_frame.registers.set(i as u8, arg.clone())?;
                }

                new_frame.upvalues = closure.upvalues.clone();

                // Push frame
                self.frames.push(new_frame);

                let initial_depth = self.frames.len() - 1;

                loop {
                    let (instruction, should_return) = {
                        // Check if we're still in the function we called
                        if self.frames.len() <= initial_depth {
                            return Ok(Value::Null);
                        }

                        let frame = self.frames.last_mut().ok_or(VmError::StackUnderflow)?;

                        match frame.fetch() {
                            Some(inst) => (inst, false),
                            None => {
                                if self.frames.len() == initial_depth + 1 {
                                    self.frames.pop();
                                    return Ok(Value::Null);
                                }
                                (0, true)
                            }
                        }
                    };

                    if should_return {
                        break;
                    }

                    let opcode_byte = decode_opcode(instruction);
                    let opcode =
                        OpCode::from_u8(opcode_byte).ok_or(VmError::InvalidOpcode(opcode_byte))?;

                    match self.execute_instruction(opcode, instruction)? {
                        ExecutionResult::Continue => {
                            if self.frames.len() <= initial_depth {
                                return Ok(Value::Null);
                            }
                            continue;
                        }
                        ExecutionResult::Return(value) => {
                            if self.frames.len() > initial_depth {
                                self.frames.pop();
                            }
                            return Ok(value);
                        }
                        ExecutionResult::Exception(error) => {
                            return Err(VmError::UncaughtException(error));
                        }
                        ExecutionResult::Yield(_) => {
                            return Err(VmError::Runtime(
                                "Cannot yield from function called via call_value".into(),
                            ));
                        }
                        ExecutionResult::Await(_, _) => {
                            return Err(VmError::Runtime(
                                "Cannot await inside a synchronous call".into(),
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
    pub fn set_global(&self, name: String, value: Value) {
        self.globals.write().insert(name, value);
    }

    /// Get a global variable (for REPL)
    pub fn get_global(&self, name: &str) -> Option<Value> {
        self.globals.read().get(name).cloned()
    }

    /// Resume a generator
    pub(crate) fn resume_generator_internal(
        &mut self,
        gen_value: &Value,
        result_reg: u8,
    ) -> Result<ExecutionResult, VmError> {
        use crate::vm::execution::iterators::NativeIterator;

        if let Value::Generator(any_ref) = gen_value {
            if let Some(iter_lock) = any_ref.downcast_ref::<RwLock<NativeIterator>>() {
                let mut iter = iter_lock.write();
                let next_val = iter.next();
                drop(iter);

                if let Some(value) = next_val {
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), value);
                    result_map.insert("done".to_string(), Value::Boolean(false));
                    let result_record = Value::Record(shared(result_map));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                } else {
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(shared(result_map));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                }
            }

            if let Some(state_lock) = any_ref.downcast_ref::<RwLock<VmGeneratorState>>() {
                let state = state_lock.read();
                if state.is_done() {
                    drop(state);
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(shared(result_map));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                }

                let gen_frame = state.frame.clone();
                drop(state);

                let mut frame = gen_frame;
                frame.return_register = Some(result_reg);
                frame.generator = Some(gen_value.clone());

                self.frames.push(frame);

                return Ok(ExecutionResult::Continue);
            }

            return Err(VmError::Runtime("Invalid generator type".to_string()));
        }

        Err(VmError::Runtime(format!(
            "Cannot resume non-generator value: {:?}",
            gen_value
        )))
    }

    /// Set the global precision
    pub fn set_precision(&self, decimals: i32) {
        let mut config = self.config.write();
        if decimals < 0 {
            config.precision = None;
        } else {
            config.precision = Some(decimals);
        }
    }

    /// Get the current precision setting
    pub fn get_precision(&self) -> Option<i32> {
        self.config.read().precision
    }

    /// Get the epsilon threshold
    pub fn get_epsilon(&self) -> f64 {
        self.config.read().epsilon
    }

    /// Apply precision rounding to a number
    pub fn apply_precision(&self, n: f64) -> f64 {
        let config = self.config.read();
        if let Some(decimals) = config.precision {
            let factor = 10_f64.powi(decimals);
            (n * factor).round() / factor
        } else {
            n
        }
    }

    /// Check if a number is effectively zero
    pub fn is_effectively_zero(&self, n: f64) -> bool {
        n.abs() < self.config.read().epsilon
    }

    /// Perform return from function
    fn do_return(&mut self, value: Value) -> Result<(), VmError> {
        let frame = self.frames.pop().ok_or(VmError::StackUnderflow)?;

        if let Some(Value::Generator(any_ref)) = frame.generator.as_ref() {
            if let Some(gen_state_lock) =
                any_ref.downcast_ref::<RwLock<crate::vm::generator::VmGeneratorState>>()
            {
                let mut gen_state = gen_state_lock.write();
                gen_state.complete(Some(value.clone()));
                drop(gen_state);

                if frame.function.is_async {
                    if let Some(return_reg) = frame.return_register {
                        if let Some(caller_frame) = self.frames.last_mut() {
                            caller_frame.registers.set(return_reg, value)?;
                        }
                    }
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(shared(result_map));

                    if let Some(return_reg) = frame.return_register {
                        if let Some(caller_frame) = self.frames.last_mut() {
                            caller_frame.registers.set(return_reg, result_record)?;
                        }
                    }
                }

                return Ok(());
            }
        }

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
