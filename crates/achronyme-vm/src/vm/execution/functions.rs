use crate::bytecode::Closure;
use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::frame::CallFrame;
use crate::vm::generator::VmGeneratorState;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use achronyme_types::function::Function;
use achronyme_types::sync::{shared, Arc, RwLock};

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
                let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;
                let prototype = frame
                    .function
                    .functions
                    .get(func_idx)
                    .ok_or(VmError::InvalidFunction(func_idx))?
                    .clone();

                // Capture upvalues from current frame
                let mut upvalues = Vec::new();

                // IMPORTANT: Upvalue 0 is reserved for 'rec' (self-reference)
                for (idx, upvalue_desc) in prototype.upvalues.iter().enumerate() {
                    if idx == 0 {
                        upvalues.push(shared(Value::Null));
                    } else {
                        if upvalue_desc.depth == 0 {
                            // Direct capture from current frame's register
                            let value = self.get_register(upvalue_desc.register)?;
                            upvalues.push(shared(value));
                        } else {
                            // Transitive capture from current frame's upvalue
                            let current_frame =
                                self.frames.last().ok_or(VmError::StackUnderflow)?;

                            let parent_upvalue = current_frame
                                .upvalues
                                .get(upvalue_desc.register as usize)
                                .ok_or_else(|| {
                                    VmError::Runtime(format!(
                                        "Invalid parent upvalue index: {}",
                                        upvalue_desc.register
                                    ))
                                })?
                                .clone();
                            upvalues.push(parent_upvalue);
                        }
                    }
                }

                // Create closure
                let closure = Closure::with_upvalues(Arc::new(prototype), upvalues.clone());

                let closure_arc = Arc::new(closure);
                let func_value = Value::Function(Function::VmClosure(
                    closure_arc as Arc<dyn std::any::Any + Send + Sync>,
                ));

                // NOW fill upvalue 0 with the closure itself
                if !upvalues.is_empty() {
                    *upvalues[0].write() = func_value.clone();
                }

                self.set_register(dst, func_value)?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::Call => {
                let result_reg = a;
                let func_reg = b;
                let argc = c;

                let func_value = self.get_register(func_reg)?;

                match func_value {
                    Value::Function(Function::VmClosure(closure_any)) => {
                        let closure = closure_any
                            .downcast_ref::<Closure>()
                            .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?;

                        let mut new_frame =
                            CallFrame::new(closure.prototype.clone(), Some(result_reg));

                        let param_count = closure.prototype.param_count;
                        for i in 0..param_count {
                            if i < argc {
                                let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                                let arg = self.get_register(arg_reg)?;
                                new_frame.registers.set(i, arg)?;
                            } else {
                                new_frame.registers.set(i, Value::Null)?;
                            }
                        }

                        new_frame.upvalues = closure.upvalues.clone();

                        if closure.prototype.is_async || closure.prototype.is_generator {
                            let state = VmGeneratorState::new(new_frame);
                            let state_lock = RwLock::new(state);
                            let gen_value = Value::Generator(Arc::new(state_lock));
                            self.set_register(result_reg, gen_value)?;
                        } else {
                            self.frames.push(new_frame);
                        }

                        Ok(ExecutionResult::Continue)
                    }
                    Value::BoundMethod {
                        receiver,
                        method_name,
                    } => {
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

                        if discriminant == crate::vm::intrinsics::TypeDiscriminant::Generator
                            && method_name == "next"
                        {
                            return self.resume_generator_internal(&receiver, result_reg);
                        }

                        let mut args = Vec::new();
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?);
                        }

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

                let func_value = self.get_register(func_reg)?;

                match func_value {
                    Value::Function(Function::VmClosure(closure_any)) => {
                        let closure = closure_any
                            .downcast_ref::<Closure>()
                            .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?
                            .clone();

                        let mut args = Vec::with_capacity(argc as usize);
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?);
                        }

                        let current_frame =
                            self.frames.last_mut().ok_or(VmError::StackUnderflow)?;

                        current_frame.function = closure.prototype.clone();
                        current_frame.ip = 0;
                        current_frame.upvalues = closure.upvalues.clone();

                        let needed_registers = if closure.prototype.register_count == 255 {
                            256
                        } else {
                            closure.prototype.register_count as usize
                        };

                        current_frame.registers.resize(needed_registers);

                        let param_count = current_frame.function.param_count;
                        for i in 0..param_count {
                            if (i as usize) < args.len() {
                                current_frame.registers.set(i, args[i as usize].clone())?;
                            } else {
                                current_frame.registers.set(i, Value::Null)?;
                            }
                        }

                        for i in param_count..current_frame.function.register_count {
                            current_frame.registers.set(i, Value::Null)?;
                        }

                        Ok(ExecutionResult::Continue)
                    }
                    Value::BoundMethod {
                        receiver,
                        method_name,
                    } => {
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

                        if discriminant == crate::vm::intrinsics::TypeDiscriminant::Generator
                            && method_name == "next"
                        {
                            return Err(VmError::Runtime(
                                "Tail calls not currently supported for generator.next()".into(),
                            ));
                        }

                        let mut args = Vec::new();
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?);
                        }

                        let result = intrinsic_fn(self, &receiver, &args)?;
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
