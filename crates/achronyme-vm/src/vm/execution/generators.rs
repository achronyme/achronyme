//! Generator instruction execution

use crate::error::VmError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use crate::vm::generator::{VmGeneratorState, VmGeneratorRef};
use crate::vm::execution::iterators::{NativeIterator, VectorIterator, StringIterator};
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
                    // First, try to downcast to native iterator
                    if let Some(iter_rc) = any_ref.downcast_ref::<RefCell<NativeIterator>>() {
                        // Handle native iterator
                        let mut iter = iter_rc.borrow_mut();

                        if let Some(value) = iter.next() {
                            // More elements available: {value: X, done: false}
                            drop(iter); // Release borrow
                            let mut result_map = std::collections::HashMap::new();
                            result_map.insert("value".to_string(), value);
                            result_map.insert("done".to_string(), Value::Boolean(false));
                            let result_record = Value::Record(Rc::new(RefCell::new(result_map)));
                            self.set_register(dst, result_record)?;
                            return Ok(ExecutionResult::Continue);
                        } else {
                            // Iterator exhausted: {value: null, done: true}
                            drop(iter); // Release borrow
                            let mut result_map = std::collections::HashMap::new();
                            result_map.insert("value".to_string(), Value::Null);
                            result_map.insert("done".to_string(), Value::Boolean(true));
                            let result_record = Value::Record(Rc::new(RefCell::new(result_map)));
                            self.set_register(dst, result_record)?;
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
                            let mut result_map = std::collections::HashMap::new();
                            result_map.insert("value".to_string(), Value::Null);
                            result_map.insert("done".to_string(), Value::Boolean(true));
                            let result_record = Value::Record(Rc::new(RefCell::new(result_map)));
                            self.set_register(dst, result_record)?;
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
                        Err(VmError::Runtime("Invalid generator type (expected VM generator or native iterator)".to_string()))
                    }
                } else {
                    Err(VmError::Runtime(format!("Cannot resume non-generator value: {:?}", gen_value)))
                }
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

            _ => unreachable!("Non-generator opcode in generator handler"),
        }
    }
}
