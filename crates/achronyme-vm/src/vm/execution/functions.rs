//! Function and closure instruction execution

use crate::bytecode::Closure;
use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::frame::CallFrame;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use achronyme_types::function::Function;
use std::cell::RefCell;
use std::rc::Rc;

impl VM {
    /// Execute function and closure instructions
    pub(crate) fn execute_functions(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let b = decode_b(instruction);
        let c = decode_c(instruction);
        let bx = decode_bx(instruction);

        match opcode {
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

                // IMPORTANT: Upvalue 0 is reserved for 'rec' (self-reference)
                // We'll fill it with Null temporarily and update it after creating the closure
                for (idx, upvalue_desc) in prototype.upvalues.iter().enumerate() {
                    if idx == 0 {
                        // Reserve slot for 'rec' - will be filled with the closure itself below
                        upvalues.push(Rc::new(RefCell::new(Value::Null)));
                    } else {
                        // Check depth to determine capture source
                        if upvalue_desc.depth == 0 {
                            // Direct capture from current frame's register
                            let value = self.get_register(upvalue_desc.register)?.clone();
                            upvalues.push(Rc::new(RefCell::new(value)));
                        } else {
                            // Transitive capture from current frame's upvalue
                            let current_frame = self.current_frame()?;
                            let parent_upvalue = current_frame
                                .upvalues
                                .get(upvalue_desc.register as usize)
                                .ok_or_else(|| {
                                    VmError::Runtime(format!(
                                        "Invalid parent upvalue index: {} (frame has {} upvalues, depth={})",
                                        upvalue_desc.register,
                                        current_frame.upvalues.len(),
                                        upvalue_desc.depth
                                    ))
                                })?
                                .clone();
                            upvalues.push(parent_upvalue);
                        }
                    }
                }

                // Create closure
                let closure = Closure::with_upvalues(Rc::new(prototype), upvalues.clone());

                // Store as Function value using Rc<dyn Any>
                let closure_rc = Rc::new(closure);
                let func_value = Value::Function(Function::VmClosure(
                    closure_rc.clone() as Rc<dyn std::any::Any>
                ));

                // NOW fill upvalue 0 with the closure itself (for recursive calls via 'rec')
                if !upvalues.is_empty() {
                    *upvalues[0].borrow_mut() = func_value.clone();
                }

                self.set_register(dst, func_value)?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::Call => {
                let result_reg = a;
                let func_reg = b;
                let argc = c;

                // Get the function value first
                let func_value = self.get_register(func_reg)?.clone();

                match func_value {
                    Value::Function(Function::VmClosure(closure_any)) => {
                        // Downcast from Rc<dyn Any> to Closure
                        let closure = closure_any
                            .downcast_ref::<Closure>()
                            .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?;

                        // Create new CallFrame
                        let mut new_frame =
                            CallFrame::new(closure.prototype.clone(), Some(result_reg));

                        // Copy arguments to new frame's registers
                        // For missing arguments (argc < param_count), set to Null
                        // The function prologue will check for Null and fill in defaults
                        let param_count = closure.prototype.param_count;
                        for i in 0..param_count {
                            if i < argc {
                                // Copy provided argument
                                let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                                let arg = self.get_register(arg_reg)?.clone();
                                new_frame.registers.set(i, arg)?;
                            } else {
                                // Set to Null for missing arguments
                                new_frame.registers.set(i, Value::Null)?;
                            }
                        }

                        // Set upvalues
                        new_frame.upvalues = closure.upvalues.clone();

                        // Note: The 'rec' upvalue (index 0) is already set in the closure.upvalues
                        // No need to set register 255 anymore - 'rec' is accessed via GetUpvalue

                        // Push frame
                        self.frames.push(new_frame);

                        Ok(ExecutionResult::Continue)
                    }
                    Value::BoundMethod {
                        receiver,
                        method_name,
                    } => {
                        // 1. Resolve the intrinsic function
                        let discriminant =
                            crate::vm::intrinsics::TypeDiscriminant::from_value(&receiver)
                                .ok_or_else(|| {
                                    VmError::Runtime("Invalid receiver for bound method".into())
                                })?;

                        let intrinsic_fn = self
                            .intrinsics
                            .lookup(&discriminant, &method_name)
                            .ok_or_else(|| {
                                VmError::Runtime(format!("Method '{}' not found", method_name))
                            })?;

                        // Special handling for generator.next() which needs to resume the generator
                        if discriminant == crate::vm::intrinsics::TypeDiscriminant::Generator
                            && method_name == "next"
                        {
                            return self.resume_generator_internal(&receiver, result_reg);
                        }

                        // 2. Collect arguments
                        let mut args = Vec::new();
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?.clone());
                        }

                        // 3. Call the intrinsic function
                        let result = intrinsic_fn(self, &receiver, &args)?;
                        self.set_register(result_reg, result)?;
                        Ok(ExecutionResult::Continue)
                    }
                    _ => Err(VmError::TypeError {
                        operation: "call".to_string(),
                        expected: "Function".to_string(),
                        got: format!("{:?}", func_value),
                    }),
                }
            }

            OpCode::TailCall => {
                let func_reg = b;
                let argc = c;

                // 1. Get callee function from register
                let func_value = self.get_register(func_reg)?.clone();

                match func_value {
                    Value::Function(Function::VmClosure(closure_any)) => {
                        let closure = closure_any
                            .downcast_ref::<Closure>()
                            .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?
                            .clone();

                        // ... (Rest of existing closure logic) ...
                        // 3. CRITICAL: Close upvalues before recycling frame
                        // ...
                        // 4. CRITICAL: Safe argument copying
                        let mut args = Vec::with_capacity(argc as usize);
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?.clone());
                        }

                        // 5. Get current frame and recycle it
                        let current_frame = self.current_frame_mut()?;

                        // Replace function
                        current_frame.function = closure.prototype.clone();

                        // Reset IP to 0
                        current_frame.ip = 0;

                        // Set upvalues
                        current_frame.upvalues = closure.upvalues.clone();

                        let needed_registers = if closure.prototype.register_count == 255 {
                            256
                        } else {
                            closure.prototype.register_count as usize
                        };

                        current_frame.registers.resize(needed_registers);

                        // 6. Write arguments to frame base
                        let param_count = current_frame.function.param_count;
                        for i in 0..param_count {
                            if (i as usize) < args.len() {
                                current_frame.registers.set(i, args[i as usize].clone())?;
                            } else {
                                current_frame.registers.set(i, Value::Null)?;
                            }
                        }

                        // 7. Clear registers beyond the parameters
                        for i in param_count..current_frame.function.register_count {
                            current_frame.registers.set(i, Value::Null)?;
                        }

                        Ok(ExecutionResult::Continue)
                    }
                    Value::BoundMethod {
                        receiver,
                        method_name,
                    } => {
                        // Tail call optimization for intrinsic methods:
                        // Execute the intrinsic and immediately return its result.

                        // 1. Resolve the intrinsic function
                        let discriminant =
                            crate::vm::intrinsics::TypeDiscriminant::from_value(&receiver)
                                .ok_or_else(|| {
                                    VmError::Runtime("Invalid receiver for bound method".into())
                                })?;

                        let intrinsic_fn = self
                            .intrinsics
                            .lookup(&discriminant, &method_name)
                            .ok_or_else(|| {
                                VmError::Runtime(format!("Method '{}' not found", method_name))
                            })?;

                        // Special handling for generator.next()
                        if discriminant == crate::vm::intrinsics::TypeDiscriminant::Generator
                            && method_name == "next"
                        {
                            // Generators push frames, so we can't just execute and return.
                            // For now, treating as regular call then return is safer, although it consumes stack temporarily.
                            // Ideally we'd pop current frame before pushing generator frame.
                            // But resume_generator_internal relies on current frame structure.
                            // Fallback: Just error for now or implement non-optimized call.
                            // Let's try non-optimized: Call then Return.
                            // But wait, resume_generator_internal returns Continue, it doesn't return a Value immediately.
                            // It pushes a frame.
                            // If we run it, it pushes a frame. When that frame returns, it writes to a register.
                            // But we don't have a dest register in TailCall.
                            // So we can't support TCO for generators easily without more VM changes.
                            return Err(VmError::Runtime(
                                "Tail calls not currently supported for generator.next()".into(),
                            ));
                        }

                        // 2. Collect arguments
                        let mut args = Vec::new();
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?.clone());
                        }

                        // 3. Call the intrinsic function
                        let result = intrinsic_fn(self, &receiver, &args)?;

                        // 4. Return the result
                        // Since this is a tail call to a native function (which doesn't push a frame),
                        // we simply return the result, which will cause the current frame to be popped
                        // by the main execution loop (or call_value loop).
                        Ok(ExecutionResult::Return(result))
                    }
                    _ => Err(VmError::TypeError {
                        operation: "tail call".to_string(),
                        expected: "Function".to_string(),
                        got: format!("{:?}", func_value),
                    }),
                }
            }

            _ => unreachable!("Non-function opcode in function handler"),
        }
    }
}
