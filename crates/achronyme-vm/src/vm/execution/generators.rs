//! Generator instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::execution::iterators::{NativeIterator, StringIterator, VectorIterator};
use crate::vm::generator::{VmGeneratorRef, VmGeneratorState};
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use achronyme_types::sync::{shared, Arc, RwLock};
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
                let frame = self.frames.last().ok_or(VmError::StackUnderflow)?;
                let proto = frame
                    .function
                    .functions
                    .get(proto_idx)
                    .ok_or(VmError::InvalidFunction(proto_idx))?
                    .clone();

                // Capture upvalues from current frame (same as Closure)
                let mut upvalues = Vec::new();
                for upvalue_desc in &proto.upvalues {
                    // Capture from current frame's registers
                    let value = self.get_register(upvalue_desc.register)?;
                    upvalues.push(shared(value));
                }

                // Create initial call frame for the generator
                let proto_arc = Arc::new(proto);
                let mut gen_frame = crate::vm::frame::CallFrame::new(proto_arc, None);

                // Set captured upvalues
                gen_frame.upvalues = upvalues;

                // Create VM-specific generator state
                let state = VmGeneratorState::new(gen_frame);

                // Wrap in Arc<RwLock<>> for shared mutability
                let state_lock: VmGeneratorRef = shared(state);

                // Type-erase to Arc<dyn Any + Send + Sync> for storage in Value::Generator
                let any_arc: Arc<dyn Any + Send + Sync> = state_lock;

                // Store as generator value
                self.set_register(dst, Value::Generator(any_arc))?;

                Ok(ExecutionResult::Continue)
            }

            OpCode::Yield => {
                // Yield R[A]
                // 1. Get the value to yield
                let value = self.get_register(a)?;

                // 2. This should suspend execution and return control to caller
                // The caller (ResumeGen) will handle saving the frame state
                Ok(ExecutionResult::Yield(value))
            }

            OpCode::ResumeGen => {
                // R[A] = R[B].next()
                // Resume generator execution
                let dst = a;
                let gen_reg = decode_b(instruction);

                let gen_value = self.get_register(gen_reg)?;

                // Use the shared resume logic
                self.resume_generator_internal(&gen_value, dst)
            }

            OpCode::MakeIterator => {
                // R[A] = MakeIterator(R[B])
                // Wraps vectors/strings in native iterators, passes generators through
                let dst = a;
                let src = decode_b(instruction);

                let value = self.get_register(src)?;

                match value {
                    // Generators pass through unchanged
                    Value::Generator(_) => {
                        self.set_register(dst, value)?;
                    }

                    // Vectors get wrapped in VectorIterator
                    Value::Vector(vec_ref) => {
                        let iter = NativeIterator::Vector(VectorIterator::new(vec_ref));
                        // Wrap NativeIterator in RwLock and Arc<dyn Any + Send + Sync>
                        let iter_lock = RwLock::new(iter);
                        let iter_arc: Arc<dyn Any + Send + Sync> = Arc::new(iter_lock);
                        self.set_register(dst, Value::Generator(iter_arc))?;
                    }

                    // Strings get wrapped in StringIterator
                    Value::String(s) => {
                        let iter = NativeIterator::String(StringIterator::new(s));
                        let iter_lock = RwLock::new(iter);
                        let iter_arc: Arc<dyn Any + Send + Sync> = Arc::new(iter_lock);
                        self.set_register(dst, Value::Generator(iter_arc))?;
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
                let future = self.get_register(src)?;

                // Suspend and wait for future
                Ok(ExecutionResult::Await(future, dst))
            }

            _ => unreachable!("Non-generator opcode in generator handler"),
        }
    }
}
