//! Bytecode format and data structures

use crate::value::Value;
use std::cell::RefCell;
use std::rc::Rc;

/// Constant pool for bytecode
#[derive(Debug, Clone)]
pub struct ConstantPool {
    /// Runtime constant values
    pub constants: Vec<Value>,

    /// Interned strings (for field names, identifiers)
    pub strings: Vec<String>,
}

impl ConstantPool {
    /// Create a new empty constant pool
    pub fn new() -> Self {
        Self {
            constants: Vec::new(),
            strings: Vec::new(),
        }
    }

    /// Add a constant value and return its index
    pub fn add_constant(&mut self, value: Value) -> usize {
        self.constants.push(value);
        self.constants.len() - 1
    }

    /// Add a string and return its index
    pub fn add_string(&mut self, s: String) -> usize {
        // Check if string already exists (interning)
        if let Some(idx) = self.strings.iter().position(|existing| existing == &s) {
            return idx;
        }

        self.strings.push(s);
        self.strings.len() - 1
    }

    /// Get constant by index
    pub fn get_constant(&self, idx: usize) -> Option<&Value> {
        self.constants.get(idx)
    }

    /// Get string by index
    pub fn get_string(&self, idx: usize) -> Option<&str> {
        self.strings.get(idx).map(|s| s.as_str())
    }
}

impl Default for ConstantPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Upvalue descriptor for closures
#[derive(Debug, Clone)]
pub struct UpvalueDescriptor {
    /// Depth of upvalue (0 = immediate parent, 1 = grandparent, etc.)
    pub depth: u8,

    /// Register index in parent frame
    pub register: u8,

    /// Is this upvalue mutable?
    pub is_mutable: bool,
}

/// Function prototype (compiled function)
#[derive(Debug, Clone)]
pub struct FunctionPrototype {
    /// Function name (for debugging)
    pub name: String,

    /// Number of parameters
    pub param_count: u8,

    /// Number of registers needed
    pub register_count: u8,

    /// Bytecode instructions (32-bit each)
    pub code: Vec<u32>,

    /// Upvalue descriptors (for closures)
    pub upvalues: Vec<UpvalueDescriptor>,

    /// Nested function prototypes
    pub functions: Vec<FunctionPrototype>,

    /// Constant pool (shared with nested functions)
    pub constants: Rc<ConstantPool>,

    /// Is this a generator function?
    pub is_generator: bool,

    /// Debug information
    pub debug_info: Option<DebugInfo>,

    /// Default value expressions for parameters (stored as nested function indices)
    /// Each entry is Option<func_idx> where func_idx points to a zero-parameter
    /// function that computes the default value
    pub param_defaults: Vec<Option<usize>>,
}

impl FunctionPrototype {
    /// Create a new function prototype
    pub fn new(name: String, constants: Rc<ConstantPool>) -> Self {
        Self {
            name,
            param_count: 0,
            register_count: 0,
            code: Vec::new(),
            upvalues: Vec::new(),
            functions: Vec::new(),
            constants,
            is_generator: false,
            debug_info: None,
            param_defaults: Vec::new(),
        }
    }

    /// Add an instruction and return its position
    pub fn add_instruction(&mut self, instruction: u32) -> usize {
        self.code.push(instruction);
        self.code.len() - 1
    }

    /// Get instruction at position
    pub fn get_instruction(&self, pos: usize) -> Option<u32> {
        self.code.get(pos).copied()
    }

    /// Patch instruction at position
    pub fn patch_instruction(&mut self, pos: usize, instruction: u32) {
        if pos < self.code.len() {
            self.code[pos] = instruction;
        }
    }
}

/// Debug information for a function
#[derive(Debug, Clone)]
pub struct DebugInfo {
    /// Line number for each instruction
    pub line_numbers: Vec<u32>,

    /// Local variable names
    pub local_names: Vec<String>,
}

/// Bytecode module (compiled program)
#[derive(Debug, Clone)]
pub struct BytecodeModule {
    /// Module name
    pub name: String,

    /// Main function (entry point)
    pub main: FunctionPrototype,

    /// Module-level constant pool
    pub constants: Rc<ConstantPool>,
}

impl BytecodeModule {
    /// Create a new bytecode module
    pub fn new(name: String) -> Self {
        let constants = Rc::new(ConstantPool::new());
        let main = FunctionPrototype::new("<main>".to_string(), constants.clone());

        Self {
            name,
            main,
            constants,
        }
    }
}

/// Runtime closure (function + captured upvalues)
#[derive(Debug, Clone)]
pub struct Closure {
    /// Function prototype
    pub prototype: Rc<FunctionPrototype>,

    /// Captured upvalues (shared mutable references)
    pub upvalues: Vec<Rc<RefCell<Value>>>,
}

impl Closure {
    /// Create a new closure
    pub fn new(prototype: Rc<FunctionPrototype>) -> Self {
        Self {
            prototype,
            upvalues: Vec::new(),
        }
    }

    /// Create closure with upvalues
    pub fn with_upvalues(
        prototype: Rc<FunctionPrototype>,
        upvalues: Vec<Rc<RefCell<Value>>>,
    ) -> Self {
        Self {
            prototype,
            upvalues,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_pool() {
        let mut pool = ConstantPool::new();

        let idx1 = pool.add_constant(Value::Number(42.0));
        let idx2 = pool.add_constant(Value::Boolean(true));

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(pool.get_constant(0), Some(&Value::Number(42.0)));
        assert_eq!(pool.get_constant(1), Some(&Value::Boolean(true)));
    }

    #[test]
    fn test_string_interning() {
        let mut pool = ConstantPool::new();

        let idx1 = pool.add_string("hello".to_string());
        let idx2 = pool.add_string("world".to_string());
        let idx3 = pool.add_string("hello".to_string()); // Should reuse idx1

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Interned
        assert_eq!(pool.strings.len(), 2); // Only 2 unique strings
    }

    #[test]
    fn test_function_prototype() {
        let constants = Rc::new(ConstantPool::new());
        let mut func = FunctionPrototype::new("test".to_string(), constants);

        func.param_count = 2;
        func.register_count = 10;

        let pos = func.add_instruction(0x12345678);
        assert_eq!(pos, 0);
        assert_eq!(func.get_instruction(0), Some(0x12345678));

        func.patch_instruction(0, 0x87654321);
        assert_eq!(func.get_instruction(0), Some(0x87654321));
    }
}
