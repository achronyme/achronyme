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

                        // Copy arguments to new frame's registers
                        for i in 0..argc {
                            let arg_reg = func_reg.wrapping_add(1).wrapping_add(i);
                            let arg = self.get_register(arg_reg)?.clone();
                            new_frame.registers.set(i, arg)?;
                        }

                        // Set upvalues
                        new_frame.upvalues = closure.upvalues.clone();

                        // Set register 255 to the closure itself for recursion
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

            _ => unreachable!("Non-function opcode in function handler"),
        }
    }
}
