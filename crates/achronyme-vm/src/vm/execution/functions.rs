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
                        // Capture from current frame's registers
                        // TODO: Handle nested upvalues (upvalues from parent closure)
                        let value = self.get_register(upvalue_desc.register)?.clone();
                        upvalues.push(Rc::new(RefCell::new(value)));
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

                // FIRST: Check if this is a pending intrinsic call
                // We check if func_value is Null (our marker) AND there's a pending intrinsic entry
                if matches!(func_value, Value::Null) {
                    if let Some((receiver, intrinsic_fn)) =
                        self.pending_intrinsic_calls.remove(&func_reg)
                    {
                        // This is an intrinsic method call!
                        // Special handling for generator.next() which needs to resume the generator

                        // Check if this is a Generator.next() call specifically
                        if let Some(type_disc) =
                            crate::vm::intrinsics::TypeDiscriminant::from_value(&receiver)
                        {
                            if type_disc == crate::vm::intrinsics::TypeDiscriminant::Generator {
                                // This is generator.next() - use special resume logic
                                return self.resume_generator_internal(&receiver, result_reg);
                            }
                        }

                        // For other intrinsics (future expansion), collect arguments and call the function
                        let mut args = Vec::new();
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            args.push(self.get_register(arg_reg)?.clone());
                        }

                        // Call the intrinsic function
                        let result = intrinsic_fn(self, &receiver, &args)?;
                        self.set_register(result_reg, result)?;
                        return Ok(ExecutionResult::Continue);
                    }
                }

                // SECOND: Normal function call

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

                let closure = match func_value {
                    Value::Function(Function::VmClosure(closure_any)) => closure_any
                        .downcast_ref::<Closure>()
                        .ok_or(VmError::Runtime("Invalid VmClosure type".to_string()))?
                        .clone(),
                    _ => {
                        return Err(VmError::TypeError {
                            operation: "tail call".to_string(),
                            expected: "Function".to_string(),
                            got: format!("{:?}", func_value),
                        })
                    }
                };

                // 2. Validate arity (optional - for now we allow arity mismatch like regular CALL)
                // In production, you might want to enable this for safety
                // if argc != closure.prototype.param_count {
                //     return Err(VmError::Runtime(format!(
                //         "Arity mismatch: expected {} arguments, got {}",
                //         closure.prototype.param_count, argc
                //     )));
                // }

                // 3. CRITICAL: Close upvalues before recycling frame
                // Note: In a full implementation, this would close upvalues that point
                // to registers in the current frame. Since our current implementation
                // captures upvalues by value (not by reference to stack slots), we don't
                // need to do anything here. But in a future optimization where upvalues
                // point to stack locations, this would be critical.
                // self.close_upvalues(current_frame_base);

                // 4. CRITICAL: Safe argument copying - use temporary buffer to avoid overlap
                // Arguments are currently in registers func_reg+1, func_reg+2, ..., func_reg+argc
                // We need to move them to R0, R1, ..., R(argc-1)
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

                // Ensure register window is large enough for new function
                // Note: We don't resize the register window in this implementation
                // because it would be complex. The current frame's register window
                // should already be large enough (255 registers for recursion).
                // If needed in the future, we can add resize logic here.

                // 6. Write arguments to frame base (R0, R1, ...)
                // For missing arguments, set to Null (function prologue will fill defaults)
                let param_count = current_frame.function.param_count;
                for i in 0..param_count {
                    if (i as usize) < args.len() {
                        current_frame.registers.set(i, args[i as usize].clone())?;
                    } else {
                        current_frame.registers.set(i, Value::Null)?;
                    }
                }

                // 7. Clear registers beyond the parameters to avoid stale values
                // This is important for correctness when the new function has fewer parameters
                for i in param_count..current_frame.function.register_count {
                    current_frame.registers.set(i, Value::Null)?;
                }

                // Note: The 'rec' upvalue (index 0) is already set in current_frame.upvalues
                // No need to set register 255 anymore - 'rec' is accessed via GetUpvalue

                // Clear remaining registers (optional but recommended for GC)
                // Skip this for now as it's just an optimization

                Ok(ExecutionResult::Continue)
            }

            _ => unreachable!("Non-function opcode in function handler"),
        }
    }
}
