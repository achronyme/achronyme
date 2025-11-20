//! Higher-Order Function (HOF) opcode execution handlers
//!
//! This module implements the VM execution logic for HOF-related opcodes:
//! - IterInit: Create iterators from collections
//! - IterNext: Get next value from iterator
//! - BuildInit: Create collection builders
//! - BuildPush: Add value to builder
//! - BuildEnd: Finalize builder to collection

use crate::error::VmError;
use crate::opcode::instruction::*;
use crate::value::Value;
use crate::vm::iterator::{VmBuilder, VmIterator};
use crate::vm::result::ExecutionResult;
use crate::vm::VM;
use std::cell::RefCell;
use std::rc::Rc;

impl VM {
    /// Execute IterInit opcode: Create iterator from collection
    ///
    /// Instruction format: ABC
    /// - A: Destination register for iterator
    /// - B: Source register containing collection
    /// - C: Unused
    ///
    /// Creates a VmIterator from the source collection and stores it as an opaque
    /// Value::Iterator in the destination register.
    pub(crate) fn execute_iter_init(&mut self, instruction: u32) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let src = decode_b(instruction);

        let source_value = self.get_register(src)?.clone();
        let iterator = VmIterator::from_value(&source_value)?;

        // Store iterator as an opaque value using Rc<dyn Any>
        let iterator_value = Value::Iterator(Rc::new(RefCell::new(iterator)));
        self.set_register(dst, iterator_value)?;

        Ok(ExecutionResult::Continue)
    }

    /// Execute IterNext opcode: Get next value from iterator
    ///
    /// Instruction format: ABC (followed by u16 jump offset)
    /// - A: Destination register for next value
    /// - B: Iterator register
    /// - C: Unused
    /// - Next u16: Jump offset if iterator is exhausted
    ///
    /// Attempts to get the next value from the iterator. If successful, stores
    /// the value in the destination register and continues. If the iterator is
    /// exhausted, reads the next u16 as a jump offset and jumps forward.
    pub(crate) fn execute_iter_next(&mut self, instruction: u32) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let iter_reg = decode_b(instruction);

        // Get iterator value
        let iter_value = self.get_register(iter_reg)?.clone();

        // Extract the VmIterator from the opaque Value::Iterator
        let mut iterator = match iter_value {
            Value::Iterator(rc) => {
                // Downcast from Rc<dyn Any> to Rc<RefCell<VmIterator>>
                let iter_rc = rc
                    .downcast_ref::<RefCell<VmIterator>>()
                    .ok_or_else(|| VmError::Runtime("Invalid iterator type".into()))?;
                iter_rc.borrow_mut().clone()
            }
            _ => return Err(VmError::Runtime("Expected iterator".into())),
        };

        // Try to get next value
        match iterator.next() {
            Some(value) => {
                // Store value in destination
                self.set_register(dst, value)?;

                // Store updated iterator back
                let updated_iter = Value::Iterator(Rc::new(RefCell::new(iterator)));
                self.set_register(iter_reg, updated_iter)?;

                // Skip the jump offset (we're not jumping)
                let frame = self.current_frame_mut()?;
                frame.ip += 2; // Skip 2 bytes (u16)

                Ok(ExecutionResult::Continue)
            }
            None => {
                // Iterator exhausted - read next instruction for jump offset
                let frame = self.current_frame_mut()?;
                let offset_hi = frame.fetch().ok_or(VmError::Runtime("Missing jump offset".into()))?;
                let offset_lo = frame.fetch().ok_or(VmError::Runtime("Missing jump offset".into()))?;
                let jump_offset = ((offset_hi as u16) << 8) | (offset_lo as u16);

                // Jump forward
                frame.ip += jump_offset as usize;

                Ok(ExecutionResult::Continue)
            }
        }
    }

    /// Execute BuildInit opcode: Create builder
    ///
    /// Instruction format: ABC
    /// - A: Destination register for builder
    /// - B: Hint register (0 = default vector builder, else use value as hint)
    /// - C: Unused
    ///
    /// Creates a VmBuilder with an optional type hint. The hint value guides
    /// what type of collection to build (e.g., Tensor hint creates TensorBuilder).
    pub(crate) fn execute_build_init(&mut self, instruction: u32) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let hint_reg = decode_b(instruction);

        let builder = if hint_reg == 0 {
            VmBuilder::new_vector()
        } else {
            let hint = self.get_register(hint_reg)?;
            VmBuilder::from_hint(hint)
        };

        // Store builder as an opaque value
        let builder_value = Value::Builder(Rc::new(RefCell::new(builder)));
        self.set_register(dst, builder_value)?;

        Ok(ExecutionResult::Continue)
    }

    /// Execute BuildPush opcode: Add value to builder
    ///
    /// Instruction format: ABC
    /// - A: Builder register
    /// - B: Value register to push
    /// - C: Unused
    ///
    /// Pushes a value into the builder. The builder may decay its type if an
    /// incompatible value is pushed (e.g., TensorBuilder receiving a String).
    pub(crate) fn execute_build_push(&mut self, instruction: u32) -> Result<ExecutionResult, VmError> {
        let builder_reg = decode_a(instruction);
        let value_reg = decode_b(instruction);

        let builder_value = self.get_register(builder_reg)?.clone();
        let value = self.get_register(value_reg)?.clone();

        // Extract builder, push value, and store back
        let mut builder = match builder_value {
            Value::Builder(rc) => {
                let builder_rc = rc
                    .downcast_ref::<RefCell<VmBuilder>>()
                    .ok_or_else(|| VmError::Runtime("Invalid builder type".into()))?;
                builder_rc.borrow_mut().clone()
            }
            _ => return Err(VmError::Runtime("Expected builder".into())),
        };

        // Push value (may cause builder to decay)
        builder.push(value)?;

        // Store updated builder back
        let updated_builder = Value::Builder(Rc::new(RefCell::new(builder)));
        self.set_register(builder_reg, updated_builder)?;

        Ok(ExecutionResult::Continue)
    }

    /// Execute BuildEnd opcode: Finalize builder to collection
    ///
    /// Instruction format: ABC
    /// - A: Destination register for final collection
    /// - B: Builder register
    /// - C: Unused
    ///
    /// Consumes the builder and produces the final collection value.
    pub(crate) fn execute_build_end(&mut self, instruction: u32) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let builder_reg = decode_b(instruction);

        let builder_value = self.get_register(builder_reg)?.clone();

        // Extract and finalize builder
        let builder = match builder_value {
            Value::Builder(rc) => {
                let builder_rc = rc
                    .downcast_ref::<RefCell<VmBuilder>>()
                    .ok_or_else(|| VmError::Runtime("Invalid builder type".into()))?;
                // Take ownership by cloning
                builder_rc.borrow().clone()
            }
            _ => return Err(VmError::Runtime("Expected builder".into())),
        };

        let result = builder.finalize()?;
        self.set_register(dst, result)?;

        Ok(ExecutionResult::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::instruction::*;
    use crate::opcode::OpCode;

    #[test]
    fn test_iter_init_vector() {
        let mut vm = VM::new();
        // Create a test vector
        let vec = vec![Value::Number(1.0), Value::Number(2.0)];
        let vec_value = Value::Vector(Rc::new(RefCell::new(vec)));

        // Set up: R[1] = vector
        let mut proto = crate::bytecode::FunctionPrototype::new(
            "test".to_string(),
            Rc::new(crate::bytecode::ConstantPool::new()),
        );
        proto.register_count = 10; // Allocate enough registers for testing
        vm.frames.push(crate::vm::frame::CallFrame::new(Rc::new(proto), None));
        vm.set_register(1, vec_value).unwrap();

        // Execute: R[0] = Iterator(R[1])
        let instruction = encode_abc(OpCode::IterInit.as_u8(), 0, 1, 0);
        let result = vm.execute_iter_init(instruction).unwrap();

        assert!(matches!(result, ExecutionResult::Continue));
        assert!(matches!(vm.get_register(0).unwrap(), Value::Iterator(_)));
    }

    #[test]
    fn test_build_init_and_push() {
        let mut vm = VM::new();

        // Set up frame
        let mut proto = crate::bytecode::FunctionPrototype::new(
            "test".to_string(),
            Rc::new(crate::bytecode::ConstantPool::new()),
        );
        proto.register_count = 10; // Allocate enough registers for testing
        vm.frames.push(crate::vm::frame::CallFrame::new(Rc::new(proto), None));

        // Execute: R[0] = Builder()
        let instruction = encode_abc(OpCode::BuildInit.as_u8(), 0, 0, 0);
        vm.execute_build_init(instruction).unwrap();

        assert!(matches!(vm.get_register(0).unwrap(), Value::Builder(_)));

        // Set up value to push
        vm.set_register(1, Value::Number(42.0)).unwrap();

        // Execute: R[0].push(R[1])
        let instruction = encode_abc(OpCode::BuildPush.as_u8(), 0, 1, 0);
        vm.execute_build_push(instruction).unwrap();

        // Finalize: R[2] = R[0].finalize()
        let instruction = encode_abc(OpCode::BuildEnd.as_u8(), 2, 0, 0);
        vm.execute_build_end(instruction).unwrap();

        match vm.get_register(2).unwrap() {
            Value::Vector(vec) => {
                let v = vec.borrow();
                assert_eq!(v.len(), 1);
                assert_eq!(v[0], Value::Number(42.0));
            }
            _ => panic!("Expected Vector"),
        }
    }
}
