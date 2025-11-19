//! Generator instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use crate::vm::generator::{VmGeneratorState, VmGeneratorRef};
use std::rc::Rc;
use std::cell::RefCell;
use std::any::Any;

impl VM {
    /// Execute generator instructions
    pub(crate) fn execute_generators(
        &mut self,
        opcode: OpCode,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let a = decode_a(instruction);
        let bx = decode_bx(instruction);

        match opcode {
            OpCode::CreateGen => {
                // R[A] = Generator(proto[Bx])
                // Similar to Closure, but creates a suspended generator instead
                let dst = a;
                let proto_idx = bx as usize;

                // Get the function prototype
                let proto = self.current_frame()?
                    .function
                    .functions
                    .get(proto_idx)
                    .ok_or(VmError::InvalidFunction(proto_idx))?
                    .clone();

                // Create initial call frame for the generator (but don't execute it)
                let gen_frame = crate::vm::frame::CallFrame::new(Rc::new(proto), None);

                // TODO: Capture upvalues like in Closure

                // Create VM-specific generator state
                let state = VmGeneratorState::new(gen_frame);

                // Wrap in Rc<RefCell<>> for shared mutability
                let state_rc: VmGeneratorRef = Rc::new(RefCell::new(state));

                // Type-erase to Rc<dyn Any> for storage in Value::Generator
                let any_rc: Rc<dyn Any> = state_rc;

                // Store as generator value
                self.set_register(dst, Value::Generator(any_rc))?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::Yield => {
                // Yield R[A]
                // 1. Get the value to yield
                let value = self.get_register(a)?.clone();

                // 2. This should suspend execution and return control to caller
                // The caller (ResumeGen) will handle saving the frame state
                Ok(ExecutionResult::Yield(value))
            }

            OpCode::ResumeGen => {
                // R[A] = R[B].next()
                // Resume generator execution
                let dst = a;
                let gen_reg = decode_b(instruction);

                let gen_value = self.get_register(gen_reg)?.clone();

                // Extract generator from Value
                if let Value::Generator(any_ref) = &gen_value {
                    // Downcast from Rc<dyn Any> to Rc<RefCell<VmGeneratorState>>
                    if let Some(state_rc) = any_ref.downcast_ref::<RefCell<VmGeneratorState>>() {
                        let state = state_rc.borrow();

                        // Check if generator is already exhausted
                        if state.is_done() {
                            // Return the stored return value (or null)
                            let result = state.return_value.clone().unwrap_or(Value::Null);
                            drop(state); // Release borrow
                            self.set_register(dst, result)?;
                            return Ok(ExecutionResult::Continue);
                        }

                        // Take the frame (clone it since we need to restore it later)
                        let gen_frame = state.frame.clone();
                        drop(state); // Release borrow before pushing frame

                        // Push the generator's frame onto the stack
                        // Set return register so the yielded value goes to R[A]
                        // Set generator reference so Yield knows which generator to update
                        let mut frame = gen_frame;
                        frame.return_register = Some(dst);
                        frame.generator = Some(gen_value.clone());
                        self.frames.push(frame);

                        Ok(ExecutionResult::Continue)
                    } else {
                        Err(VmError::Runtime("Invalid generator type (expected VM generator)".to_string()))
                    }
                } else {
                    Err(VmError::Runtime(format!("Cannot resume non-generator value: {:?}", gen_value)))
                }
            }

            _ => unreachable!("Non-generator opcode in generator handler"),
        }
    }
}
