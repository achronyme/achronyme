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
use achronyme_types::sync::{Arc, RwLock};

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
    pub(crate) fn execute_iter_init(
        &mut self,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let src = decode_b(instruction);

        let source_value = self.get_register(src)?.clone();
        let iterator = VmIterator::from_value(&source_value)?;

        // Store iterator as an opaque value using Arc<dyn Any>
        // VmIterator is not Send/Sync by default if it holds Rc, but we migrated it to use Shared (Arc<RwLock>)
        // so it should be Send + Sync.
        // We need to wrap it in Arc<RwLock> to allow mutation during next(),
        // but Value::Iterator expects Arc<dyn Any + Send + Sync>.
        // Wait, Value::Iterator holds Arc<dyn Any>. Is it just Any or RwLock<Any>?
        // The definition is: Iterator(Arc<dyn Any + Send + Sync>)
        // We want to store a mutable iterator.
        // So we wrap VmIterator in RwLock, then in Arc.
        let iter_lock = RwLock::new(iterator);
        let iterator_value = Value::Iterator(Arc::new(iter_lock));
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
    pub(crate) fn execute_iter_next(
        &mut self,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let iter_reg = decode_b(instruction);

        // Get iterator value
        let iter_value = self.get_register(iter_reg)?.clone();

        let next_val = match &iter_value {
            Value::Iterator(arc) => {
                let iter_lock = arc
                    .downcast_ref::<RwLock<VmIterator>>()
                    .ok_or_else(|| VmError::Runtime("Invalid iterator type".into()))?;
                iter_lock.write().next()
            }
            _ => return Err(VmError::Runtime("Expected iterator".into())),
        };

        // Try to get next value
        match next_val {
            Some(value) => {
                // Store value in destination
                self.set_register(dst, value)?;

                // No need to store updated iterator back because we modified it in place via RwLock!

                // Skip the jump offset (we're not jumping)
                let frame = self.current_frame_mut()?;
                frame.ip += 2; // Skip 2 bytes (u16)

                Ok(ExecutionResult::Continue)
            }
            None => {
                // Iterator exhausted - read next instruction for jump offset
                let frame = self.current_frame_mut()?;
                let offset_hi = frame
                    .fetch()
                    .ok_or(VmError::Runtime("Missing jump offset".into()))?;
                let offset_lo = frame
                    .fetch()
                    .ok_or(VmError::Runtime("Missing jump offset".into()))?;
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
    pub(crate) fn execute_build_init(
        &mut self,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let hint_reg = decode_b(instruction);

        let builder = if hint_reg == 0 {
            VmBuilder::new_vector()
        } else {
            let hint = self.get_register(hint_reg)?;
            VmBuilder::from_hint(hint)
        };

        // Store builder as an opaque value using Arc<RwLock<VmBuilder>>
        let builder_value = Value::Builder(Arc::new(RwLock::new(builder)));
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
    pub(crate) fn execute_build_push(
        &mut self,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let builder_reg = decode_a(instruction);
        let value_reg = decode_b(instruction);

        let builder_value = self.get_register(builder_reg)?.clone();
        let value = self.get_register(value_reg)?.clone();

        // Extract builder and push value
        match builder_value {
            Value::Builder(arc) => {
                let builder_lock = arc
                    .downcast_ref::<RwLock<VmBuilder>>()
                    .ok_or_else(|| VmError::Runtime("Invalid builder type".into()))?;
                builder_lock.write().push(value)?;
            }
            _ => return Err(VmError::Runtime("Expected builder".into())),
        };

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
    pub(crate) fn execute_build_end(
        &mut self,
        instruction: u32,
    ) -> Result<ExecutionResult, VmError> {
        let dst = decode_a(instruction);
        let builder_reg = decode_b(instruction);

        let builder_value = self.get_register(builder_reg)?.clone();

        // Extract and finalize builder
        let result = match builder_value {
            Value::Builder(arc) => {
                let builder_lock = arc
                    .downcast_ref::<RwLock<VmBuilder>>()
                    .ok_or_else(|| VmError::Runtime("Invalid builder type".into()))?;

                // We need to consume the builder.
                // Since it's in an Arc<RwLock>, we clone the inner data.
                let builder = builder_lock.read().clone();
                builder.finalize()?
            }
            _ => return Err(VmError::Runtime("Expected builder".into())),
        };

        self.set_register(dst, result)?;

        Ok(ExecutionResult::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcode::OpCode;
    use achronyme_types::sync::{shared, Arc, RwLock};

    #[test]
    fn test_iter_init_vector() {
        let mut vm = VM::new();
        // Create a test vector
        let vec = vec![Value::Number(1.0), Value::Number(2.0)];
        let vec_value = Value::Vector(shared(vec));

        // Set up: R[1] = vector
        let constants = Arc::new(crate::bytecode::ConstantPool::new());
        let mut proto = crate::bytecode::FunctionPrototype::new("test".to_string(), constants);
        proto.register_count = 10; // Allocate enough registers for testing
        let proto_arc = Arc::new(proto);
        vm.frames
            .push(crate::vm::frame::CallFrame::new(proto_arc, None));
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
        let constants = Arc::new(crate::bytecode::ConstantPool::new());
        let mut proto = crate::bytecode::FunctionPrototype::new("test".to_string(), constants);
        proto.register_count = 10; // Allocate enough registers for testing
        let proto_arc = Arc::new(proto);
        vm.frames
            .push(crate::vm::frame::CallFrame::new(proto_arc, None));

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
                let v = vec.read();
                assert_eq!(v.len(), 1);
                assert_eq!(v[0], Value::Number(42.0));
            }
            _ => panic!("Expected Vector"),
        }
    }
}
