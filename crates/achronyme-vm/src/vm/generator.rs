//! Generator state management for stackless coroutines

use crate::value::Value;
use crate::vm::frame::CallFrame;
use achronyme_types::sync::{Arc, Shared};

/// VM-specific generator state
/// This is the concrete type stored inside Value::Generator(Arc<dyn Any>)
#[derive(Debug)]
pub struct VmGeneratorState {
    /// The frozen call frame (contains IP, registers, upvalues)
    pub frame: CallFrame,

    /// Is the generator exhausted?
    pub done: bool,

    /// Last value returned (for iterators that need post-termination access)
    pub return_value: Option<Value>,
}

/// Shared reference to VM generator state
/// Uses Shared (Arc<RwLock>) for shared mutability
pub type VmGeneratorRef = Shared<VmGeneratorState>;

impl VmGeneratorState {
    /// Create a new generator with the given call frame
    pub fn new(frame: CallFrame) -> Self {
        Self {
            frame,
            done: false,
            return_value: None,
        }
    }

    /// Check if generator is done
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Mark generator as completed with optional return value
    pub fn complete(&mut self, return_value: Option<Value>) {
        self.done = true;
        self.return_value = return_value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::ConstantPool;
    use crate::bytecode::FunctionPrototype;
    use achronyme_types::sync::Arc;

    #[test]
    fn test_generator_state_creation() {
        let constants = Arc::new(ConstantPool::new());
        let proto = FunctionPrototype::new("test_gen".to_string(), constants);
        let frame = CallFrame::new(Arc::new(proto), None);

        let state = VmGeneratorState::new(frame);
        assert!(!state.is_done());
        assert!(state.return_value.is_none());
    }

    #[test]
    fn test_generator_completion() {
        let constants = Arc::new(ConstantPool::new());
        let proto = FunctionPrototype::new("test_gen".to_string(), constants);
        let frame = CallFrame::new(Arc::new(proto), None);

        let mut state = VmGeneratorState::new(frame);

        // Complete with return value
        state.complete(Some(Value::Number(42.0)));
        assert!(state.is_done());
        assert_eq!(state.return_value, Some(Value::Number(42.0)));
    }
}
