//! Generator instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::execution::iterators::{NativeIterator, StringIterator, VectorIterator};
use crate::vm::generator::{VmGeneratorRef, VmGeneratorState};
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

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
                let proto = self
                    .current_frame()?
                    .function
                    .functions
                    .get(proto_idx)
                    .ok_or(VmError::InvalidFunction(proto_idx))?
                    .clone();

                // Capture upvalues from current frame (same as Closure)
                let mut upvalues = Vec::new();
                for upvalue_desc in &proto.upvalues {
                    // Capture from current frame's registers
                    let value = self.get_register(upvalue_desc.register)?.clone();
                    upvalues.push(std::rc::Rc::new(std::cell::RefCell::new(value)));
                }

                // Create initial call frame for the generator
                let proto_rc = std::rc::Rc::new(proto);
                let mut gen_frame = crate::vm::frame::CallFrame::new(proto_rc, None);

                // Set captured upvalues
                gen_frame.upvalues = upvalues;

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

                // Use the shared resume logic
                self.resume_generator_internal(&gen_value, dst)
            }

            OpCode::MakeIterator => {
                // R[A] = MakeIterator(R[B])
                // Wraps vectors/strings in native iterators, passes generators through
                let dst = a;
                let src = decode_b(instruction);

                let value = self.get_register(src)?.clone();

                match value {
                    // Generators pass through unchanged
                    Value::Generator(_) => {
                        self.set_register(dst, value)?;
                    }

                    // Vectors get wrapped in VectorIterator
                    Value::Vector(vec_ref) => {
                        let iter = NativeIterator::Vector(VectorIterator::new(vec_ref));
                        let iter_rc: Rc<dyn Any> = Rc::new(RefCell::new(iter));
                        self.set_register(dst, Value::Generator(iter_rc))?;
                    }

                    // Strings get wrapped in StringIterator
                    Value::String(s) => {
                        let iter = NativeIterator::String(StringIterator::new(s));
                        let iter_rc: Rc<dyn Any> = Rc::new(RefCell::new(iter));
                        self.set_register(dst, Value::Generator(iter_rc))?;
                    }

                    // Other types cannot be iterated
                    _ => {
                        return Err(VmError::Runtime(format!(
                            "Cannot iterate over type: {:?}",
                            value
                        )));
                    }
                }

                Ok(ExecutionResult::Continue)
            }

            OpCode::Await => {
                // R[A] = await R[B]
                let dst = a;
                let src = decode_b(instruction);
                let future = self.get_register(src)?.clone();

                // Suspend and wait for future
                Ok(ExecutionResult::Await(future, dst))
            }

            _ => unreachable!("Non-generator opcode in generator handler"),
        }
    }
}
