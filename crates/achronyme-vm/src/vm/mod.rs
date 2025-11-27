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
    /// Mutable execution state
    pub(crate) state: Shared<VMState>,

    /// Global variables
    pub(crate) globals: Shared<HashMap<String, Value>>,

    /// Built-in function registry
    pub(crate) builtins: Arc<BuiltinRegistry>,

    /// Intrinsic method registry
    pub(crate) intrinsics: Arc<IntrinsicRegistry>,

    /// Configuration
    config: Shared<VMConfig>,

    /// Shared signal notifier - all child VMs share this with parent.
    /// This allows the notifier to be set at any time (e.g., when GUI starts)
    /// and all VMs (including previously spawned children) will see it.
    /// Uses Shared (Arc<RwLock>) so the reference is shared, not copied.
    signal_notifier: Shared<Option<Arc<dyn SignalNotifier>>>,
}

/// Mutable execution state, protected by RwLock
pub struct VMState {
    /// Call stack
    pub(crate) frames: Vec<InternalCallFrame>,

    /// Generator states (ID -> suspended frame)
    pub(crate) generators: HashMap<usize, SuspendedFrame>,

    /// Current module file path (for resolving relative imports)
    pub(crate) current_module: Option<String>,

    /// Root scope for active effects to keep them alive
    pub(crate) active_effects: Vec<Shared<EffectState>>,

    // --- Reactive Context (replaces thread_local TRACKING_CONTEXT) ---

    /// Current effect being tracked during execution.
    /// When an effect callback is running, this holds that effect so that
    /// signal reads can automatically register dependencies.
    pub(crate) tracking_effect: Option<Shared<EffectState>>,
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
unsafe impl Send for VM {}
unsafe impl Sync for VM {}

impl VM {
    /// Create a new VM
    pub fn new() -> Self {
        Self {
            state: shared(VMState {
                frames: Vec::with_capacity(256),
                generators: HashMap::new(),
                current_module: None,
                active_effects: Vec::new(),
                tracking_effect: None,
            }),
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
    ///
    /// The child VM shares the same `signal_notifier` reference as the parent,
    /// so if the parent sets a notifier later (e.g., when GUI starts), the child
    /// will automatically see it. This enables patterns like:
    /// ```
    /// spawn(animator)  // Child created before GUI
    /// gui_run(app)     // GUI sets notifier - child sees it too
    /// ```
    pub fn new_child(&self) -> Self {
        Self {
            state: shared(VMState {
                frames: Vec::with_capacity(256),
                generators: HashMap::new(),
                current_module: None,
                active_effects: Vec::new(),
                tracking_effect: None,
            }),
            globals: self.globals.clone(),
            builtins: self.builtins.clone(),
            intrinsics: self.intrinsics.clone(),
            config: self.config.clone(),
            // Share the same notifier reference (not a copy of the value)
            // This allows notifier to be set after child creation
            signal_notifier: self.signal_notifier.clone(),
        }
    }
    // --- Reactive Context Methods ---

    /// Set the current tracking effect (called when entering an effect callback)
    pub fn set_tracking_effect(&self, effect: Option<Shared<EffectState>>) {
        self.state.write().tracking_effect = effect;
    }

    /// Get the current tracking effect (called when reading a signal)
    pub fn get_tracking_effect(&self) -> Option<Shared<EffectState>> {
        self.state.read().tracking_effect.clone()
    }

    /// Register a signal notifier callback (called by GUI systems)
    ///
    /// This notifier is shared between parent and all child VMs, so setting it
    /// on the parent will make it visible to all children (even those created earlier).
    pub fn set_signal_notifier(&self, notifier: Option<Arc<dyn SignalNotifier>>) {
        *self.signal_notifier.write() = notifier;
    }

    /// Notify that a signal has changed (called after signal.set)
    ///
    /// This reads from the shared notifier, so it works correctly even when called
    /// from a child VM that was created before the notifier was set.
    pub fn notify_signal_change(&self) {
        if let Some(notifier) = &*self.signal_notifier.read() {
            notifier.notify();
        }
    }

    /// Execute a bytecode module
    pub async fn execute(&self, module: BytecodeModule) -> Result<Value, VmError> {
        {
            let mut state = self.state.write();
            // Set current module for import resolution
            state.current_module = Some(module.name.clone());

            // Create main frame
            let main_frame = InternalCallFrame::new(Arc::new(module.main), None);
            state.frames.push(main_frame);
        }

        // Run until completion
        self.run().await
    }

    /// Main execution loop
    pub(crate) async fn run(&self) -> Result<Value, VmError> {
        loop {
            // We need to hold the lock for as little time as possible,
            // but for the fetch-decode-execute loop, we might need to hold it
            // during the whole step or rely on granular locking.
            // For Phase 1, we'll lock for the frame access and then instruction execution.
            // However, `execute_instruction` needs to mutate state.
            
            // 1. Fetch instruction
            let (instruction, is_main_return) = {
                let mut state = self.state.write();
                
                // Check stack depth
                if state.frames.len() > MAX_CALL_DEPTH {
                    return Err(VmError::StackOverflow);
                }

                // Get current frame
                let frame = state.frames.last_mut().ok_or(VmError::StackUnderflow)?;

                match frame.fetch() {
                    Some(inst) => (inst, false),
                    None => {
                        // End of function, return null
                        if state.frames.len() == 1 {
                            // Main function ended
                            return Ok(Value::Null);
                        }
                        // We need to return from function. 
                        // We can't call do_return here because we hold the lock.
                        // We will signal this.
                        (0, true) // Dummy instruction, signal return
                    }
                }
            };

            if is_main_return {
                // Handle implicit return null
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
                    // Check if we are at the top level
                    let stack_len = self.state.read().frames.len();
                    if stack_len == 1 {
                        return Ok(value);
                    }
                    self.do_return(value)?;
                }
                ExecutionResult::Exception(error) => {
                    // Start unwinding
                    loop {
                        // We need to lock state to access frames
                        let mut state = self.state.write();
                        
                        // Get current frame
                        let frame_idx = state.frames.len().checked_sub(1);
                        
                        match frame_idx {
                            Some(idx) => {
                                let frame = &mut state.frames[idx];
                                
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
                                if let Some(Value::Generator(any_ref)) = frame.generator.as_ref() {
                                    if let Some(gen_state_lock) = any_ref
                                        .downcast_ref::<RwLock<crate::vm::generator::VmGeneratorState>>()
                                    {
                                        // We must drop state lock before acquiring generator lock to avoid deadlock?
                                        // Actually, here we are unwinding, so we might own the generator state via the frame?
                                        // No, generator state is shared.
                                        // Safe order: VMState lock -> GeneratorState lock? 
                                        // If we hold VMState lock, we shouldn't lock GeneratorState if GeneratorState lock might wait for VMState lock.
                                        // Generator execution usually holds VMState lock.
                                        
                                        // Let's clone the weak ref or similar if possible?
                                        // We can just write to it.
                                        let mut gen_state = gen_state_lock.write();
                                        gen_state.complete(None);
                                    }
                                }
                                
                                // Pop frame and continue unwinding
                                state.frames.pop();
                            },
                            None => {
                                // No more frames - uncaught exception
                                return Err(VmError::UncaughtException(error));
                            }
                        }
                    }
                    continue;
                }
                ExecutionResult::Yield(value) => {
                    let mut state = self.state.write();
                    
                    // Pop the generator's frame and save it back
                    let gen_frame = state.frames.pop().ok_or(VmError::StackUnderflow)?;

                    // If this frame has a generator reference, update the generator state
                    if let Some(Value::Generator(any_ref)) = gen_frame.generator.as_ref() {
                        if let Some(gen_state_lock) =
                            any_ref.downcast_ref::<RwLock<crate::vm::generator::VmGeneratorState>>()
                        {
                            let mut gen_state = gen_state_lock.write();
                            // Save the frame state
                            let mut saved_frame = gen_frame.clone();
                            saved_frame.generator = None; // Clear to avoid circular reference
                            gen_state.frame = saved_frame;
                            drop(gen_state);

                            // Create iterator result object
                            let mut result_map = std::collections::HashMap::new();
                            result_map.insert("value".to_string(), value);
                            result_map.insert("done".to_string(), Value::Boolean(false));
                            let result_record = Value::Record(shared(result_map));

                            // Put iterator result record in the caller's return register
                            if let Some(return_reg) = gen_frame.return_register {
                                if let Some(caller_frame) = state.frames.last_mut() {
                                    caller_frame.registers.set(return_reg, result_record)?;
                                }
                            }

                            // Continue execution in caller frame
                            continue;
                        }
                    }

                    // No generator context - just return
                    return Ok(value);
                }
                ExecutionResult::Await(value, dst_reg) => {
                    match value {
                        Value::Future(vm_future) => {
                            // Non-blocking await: yield to Tokio executor
                            let future = vm_future.0.clone();
                            let result = future.await;
                            // We need to lock state to set register
                            self.set_register(dst_reg, result)?;
                        }
                        Value::Generator(_) => {
                            // Awaiting a generator = Resuming/Starting it
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
        &self,
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

            // Not yet implemented
            _ => Err(VmError::Runtime(format!(
                "Opcode {} not yet implemented",
                opcode
            ))),
        }
    }

    // ===== Helper methods =====

    /// Get current call frame
    /// Note: This returns a clone or reference? We can't return reference to field inside lock.
    /// We can't easily return &InternalCallFrame without holding the lock.
    /// So internal helpers might need to take the LockGuard or we change how we access frames.
    /// For public/crate helpers, we might need to return clones or use a callback.
    /// 
    /// BUT: These helper methods are used inside `execute_*` methods which are on `&self`.
    /// The best pattern here is to have `execute_*` methods acquire the lock and do their work.
    /// 
    /// HOWEVER, `get_register` and `set_register` are very common.
    /// Let's make them lock internally.
    
    /// Get register from current frame (cloned value)
    pub(crate) fn get_register(&self, idx: u8) -> Result<Value, VmError> {
        let state = self.state.read();
        let frame = state.frames.last().ok_or(VmError::StackUnderflow)?;
        frame.registers.get(idx).cloned()
    }

    /// Set register in current frame
    pub(crate) fn set_register(&self, idx: u8, value: Value) -> Result<(), VmError> {
        let mut state = self.state.write();
        let frame = state.frames.last_mut().ok_or(VmError::StackUnderflow)?;
        frame.registers.set(idx, value)
    }

    /// Get constant from current frame's function
    pub(crate) fn get_constant(&self, idx: usize) -> Result<Value, VmError> {
        let state = self.state.read();
        let frame = state.frames.last().ok_or(VmError::StackUnderflow)?;
        frame
            .function
            .constants
            .get_constant(idx)
            .cloned()
            .ok_or(VmError::InvalidConstant(idx))
    }

    /// Get string from constant pool
    pub(crate) fn get_string(&self, idx: usize) -> Result<String, VmError> {
        let state = self.state.read();
        let frame = state.frames.last().ok_or(VmError::StackUnderflow)?;
        frame
            .function
            .constants
            .get_string(idx)
            .map(|s| s.to_string())
            .ok_or(VmError::InvalidConstant(idx))
    }

    /// Call a Value as a function with given arguments
    pub fn call_value(&self, func: &Value, args: &[Value]) -> Result<Value, VmError> {
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
                {
                    let mut state = self.state.write();
                    state.frames.push(new_frame);
                }

                // Execute until this frame returns
                // We need to capture the depth *before* pushing? No, *after* pushing.
                // Actually we need to know the depth of the *caller* to know when we return to it.
                let initial_depth = {
                    let state = self.state.read();
                    state.frames.len() - 1
                };

                loop {
                    let (instruction, should_return) = {
                        let mut state = self.state.write();
                        // Check if we're still in the function we called
                        if state.frames.len() <= initial_depth {
                            // We popped back to caller (or further)
                            // This shouldn't happen if we manage the loop correctly,
                            // but let's be safe.
                            return Ok(Value::Null);
                        }

                        let frame = state.frames.last_mut().ok_or(VmError::StackUnderflow)?;

                        match frame.fetch() {
                            Some(inst) => (inst, false),
                            None => {
                                if state.frames.len() == initial_depth + 1 {
                                    state.frames.pop();
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
                            let current_depth = self.state.read().frames.len();
                            if current_depth <= initial_depth {
                                return Ok(Value::Null);
                            }
                            continue;
                        }
                        ExecutionResult::Return(value) => {
                            let mut state = self.state.write();
                            if state.frames.len() > initial_depth {
                                state.frames.pop();
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
        &self,
        gen_value: &Value,
        result_reg: u8,
    ) -> Result<ExecutionResult, VmError> {
        use crate::vm::execution::iterators::NativeIterator;

        if let Value::Generator(any_ref) = gen_value {
            if let Some(iter_lock) = any_ref.downcast_ref::<RwLock<NativeIterator>>() {
                let mut iter = iter_lock.write();

                if let Some(value) = iter.next() {
                    drop(iter);
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), value);
                    result_map.insert("done".to_string(), Value::Boolean(false));
                    let result_record = Value::Record(shared(result_map));
                    self.set_register(result_reg, result_record)?;
                    return Ok(ExecutionResult::Continue);
                } else {
                    drop(iter);
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

                {
                    let mut vm_state = self.state.write();
                    vm_state.frames.push(frame);
                }

                return Ok(ExecutionResult::Continue);
            }

            return Err(VmError::Runtime(
                "Invalid generator type".to_string(),
            ));
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
    fn do_return(&self, value: Value) -> Result<(), VmError> {
        let mut state = self.state.write();
        let frame = state.frames.pop().ok_or(VmError::StackUnderflow)?;

        if let Some(Value::Generator(any_ref)) = frame.generator.as_ref() {
            if let Some(gen_state_lock) =
                any_ref.downcast_ref::<RwLock<crate::vm::generator::VmGeneratorState>>()
            {
                let mut gen_state = gen_state_lock.write();
                gen_state.complete(Some(value.clone()));
                drop(gen_state);

                if frame.function.is_async {
                    if let Some(return_reg) = frame.return_register {
                        if let Some(caller_frame) = state.frames.last_mut() {
                            caller_frame.registers.set(return_reg, value)?;
                        }
                    }
                    let mut result_map = HashMap::new();
                    result_map.insert("value".to_string(), Value::Null);
                    result_map.insert("done".to_string(), Value::Boolean(true));
                    let result_record = Value::Record(shared(result_map));

                    if let Some(return_reg) = frame.return_register {
                        if let Some(caller_frame) = state.frames.last_mut() {
                            caller_frame.registers.set(return_reg, result_record)?;
                        }
                    }
                }

                return Ok(());
            }
        }

        if let Some(return_reg) = frame.return_register {
            if let Some(caller_frame) = state.frames.last_mut() {
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
