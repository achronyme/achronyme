//! Bytecode compiler (AST to bytecode)

use crate::builtins::registry::BuiltinRegistry;
use crate::bytecode::{BytecodeModule, ConstantPool, FunctionPrototype};
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_parser::ast::AstNode;
use achronyme_parser::type_annotation::TypeAnnotation;
use std::collections::HashMap;
use std::rc::Rc;

// Module structure
mod constants;
mod context;
mod expressions;
mod patterns;
pub(crate) mod registers;
mod statements;
pub(crate) mod symbols;

// Internal imports
use context::LoopContext;
use registers::{RegResult, RegisterAllocator};
use symbols::SymbolTable;

/// Bytecode compiler
pub struct Compiler {
    /// Current function being compiled
    pub(crate) function: FunctionPrototype,

    /// Register allocator
    pub(crate) registers: RegisterAllocator,

    /// Symbol table
    pub(crate) symbols: SymbolTable,

    /// Loop context stack
    pub(crate) loops: Vec<LoopContext>,

    /// Parent compiler (for nested functions)
    parent: Option<Box<Compiler>>,

    /// Built-in function registry (shared across all compilers)
    pub(crate) builtins: Rc<BuiltinRegistry>,

    /// Type registry for storing type aliases
    pub(crate) type_registry: HashMap<String, TypeAnnotation>,

    /// Exported values (name -> register index)
    pub(crate) exported_values: HashMap<String, u8>,

    /// Exported types (name -> type definition)
    pub(crate) exported_types: HashMap<String, TypeAnnotation>,
}

impl Compiler {
    /// Create a new compiler for a module
    pub fn new(_module_name: String) -> Self {
        let constants = Rc::new(ConstantPool::new());
        let function = FunctionPrototype::new("<main>".to_string(), constants);

        Self {
            function,
            registers: RegisterAllocator::new(),
            symbols: SymbolTable::new(),
            loops: Vec::new(),
            parent: None,
            builtins: Rc::new(crate::builtins::create_builtin_registry()),
            type_registry: HashMap::new(),
            exported_values: HashMap::new(),
            exported_types: HashMap::new(),
        }
    }

    /// Compile AST nodes to bytecode module
    pub fn compile(&mut self, nodes: &[AstNode]) -> Result<BytecodeModule, CompileError> {
        // Compile all nodes (usually just one Sequence node)
        let mut last_res: Option<RegResult> = None;
        for node in nodes {
            // Check if it's the last statement that returns a value
            // Yield can be both statement and expression, but we treat it as expression
            let is_expression = !matches!(
                node,
                AstNode::VariableDecl { .. }
                    | AstNode::MutableDecl { .. }
                    | AstNode::LetDestructuring { .. }
                    | AstNode::MutableDestructuring { .. }
                    | AstNode::Assignment { .. }
                    | AstNode::Import { .. }
                    | AstNode::Export { .. }
                    | AstNode::TypeAlias { .. }
                    | AstNode::Return { .. }
            );

            if is_expression {
                let res = self.compile_expression(node)?;
                last_res = Some(res);
            } else {
                self.compile_statement(node)?;
            }
        }

        // Emit return with last value or null
        if let Some(res) = last_res {
            self.emit(encode_abc(OpCode::Return.as_u8(), res.reg(), 0, 0));
        } else {
            self.emit_return_null();
        }

        // Update register count
        self.function.register_count = self.registers.max_used();

        // Create module
        let module = BytecodeModule {
            name: "<main>".to_string(),
            main: self.function.clone(),
            constants: self.function.constants.clone(),
        };

        Ok(module)
    }

    // ===== Helper methods =====

    /// Add constant to pool
    pub(crate) fn add_constant(&mut self, value: Value) -> Result<usize, CompileError> {
        // Try to get mutable access to the constant pool
        if let Some(pool) = Rc::get_mut(&mut self.function.constants) {
            let idx = pool.add_constant(value);

            if idx > u16::MAX as usize {
                return Err(CompileError::TooManyConstants);
            }

            Ok(idx)
        } else {
            // Constant pool is shared, we need to make a copy
            // This can happen with nested lambdas
            let pool_clone = (*self.function.constants).clone();
            self.function.constants = Rc::new(pool_clone);

            // Now we can get mutable access
            let pool = Rc::get_mut(&mut self.function.constants)
                .expect("Just created new Rc, should be unique");

            let idx = pool.add_constant(value);

            if idx > u16::MAX as usize {
                return Err(CompileError::TooManyConstants);
            }

            Ok(idx)
        }
    }

    /// Add string to constant pool (for field names, etc.)
    pub(crate) fn add_string(&mut self, s: String) -> Result<usize, CompileError> {
        // Try to get mutable access to the constant pool
        if let Some(pool) = Rc::get_mut(&mut self.function.constants) {
            let idx = pool.add_string(s);

            if idx > u8::MAX as usize {
                return Err(CompileError::Error("Too many strings in constant pool".to_string()));
            }

            Ok(idx)
        } else {
            // Constant pool is shared, we need to make a copy
            // This can happen with nested lambdas
            let pool_clone = (*self.function.constants).clone();
            self.function.constants = Rc::new(pool_clone);

            // Now we can get mutable access
            let pool = Rc::get_mut(&mut self.function.constants)
                .expect("Just created new Rc, should be unique");

            let idx = pool.add_string(s);

            if idx > u8::MAX as usize {
                return Err(CompileError::Error("Too many strings in constant pool".to_string()));
            }

            Ok(idx)
        }
    }

    /// Emit instruction
    pub(crate) fn emit(&mut self, instruction: u32) -> usize {
        self.function.add_instruction(instruction)
    }

    /// Emit LOAD_CONST instruction
    pub(crate) fn emit_load_const(&mut self, dst: u8, const_idx: usize) {
        self.emit(encode_abx(
            OpCode::LoadConst.as_u8(),
            dst,
            const_idx as u16,
        ));
    }

    /// Emit MOVE instruction
    pub(crate) fn emit_move(&mut self, dst: u8, src: u8) {
        self.emit(encode_abc(OpCode::Move.as_u8(), dst, src, 0));
    }

    /// Emit JUMP instruction and return position for patching
    pub(crate) fn emit_jump(&mut self, offset: i16) -> usize {
        self.emit(encode_abx(OpCode::Jump.as_u8(), 0, offset as u16))
    }

    /// Emit JUMP_IF_FALSE instruction
    pub(crate) fn emit_jump_if_false(&mut self, cond_reg: u8, offset: i16) -> usize {
        self.emit(encode_abx(
            OpCode::JumpIfFalse.as_u8(),
            cond_reg,
            offset as u16,
        ))
    }

    /// Emit JUMP_IF_TRUE instruction
    pub(crate) fn emit_jump_if_true(&mut self, cond_reg: u8, offset: i16) -> usize {
        self.emit(encode_abx(
            OpCode::JumpIfTrue.as_u8(),
            cond_reg,
            offset as u16,
        ))
    }

    /// Emit JUMP_IF_NULL instruction
    pub(crate) fn emit_jump_if_null(&mut self, value_reg: u8, offset: i16) -> usize {
        self.emit(encode_abx(
            OpCode::JumpIfNull.as_u8(),
            value_reg,
            offset as u16,
        ))
    }

    /// Emit RETURN_NULL instruction
    pub(crate) fn emit_return_null(&mut self) {
        self.emit(encode_abc(OpCode::ReturnNull.as_u8(), 0, 0, 0));
    }

    /// Get current code position
    pub(crate) fn current_position(&self) -> usize {
        self.function.code.len()
    }

    /// Patch jump instruction at position
    pub(crate) fn patch_jump(&mut self, pos: usize) {
        let offset = self.current_position() as i16 - pos as i16 - 1;
        let instruction = self.function.code[pos];
        let opcode = decode_opcode(instruction);
        let a = decode_a(instruction);

        let patched = encode_abx(opcode, a, offset as u16);
        self.function.patch_instruction(pos, patched);
    }

    /// Convert type annotation to string for type checking
    pub(crate) fn type_annotation_to_string(&self, type_ann: &achronyme_parser::TypeAnnotation) -> String {
        use achronyme_parser::TypeAnnotation;

        match type_ann {
            TypeAnnotation::Number => "Number".to_string(),
            TypeAnnotation::Boolean => "Boolean".to_string(),
            TypeAnnotation::String => "String".to_string(),
            TypeAnnotation::Complex => "Complex".to_string(),
            TypeAnnotation::Vector => "Vector".to_string(),
            TypeAnnotation::Tensor { .. } => "Tensor".to_string(),
            TypeAnnotation::Record { .. } => "Record".to_string(),
            TypeAnnotation::Function { .. } => "Function".to_string(),
            TypeAnnotation::Edge => "Edge".to_string(),
            TypeAnnotation::Generator => "Generator".to_string(),
            TypeAnnotation::Error => "Error".to_string(),
            TypeAnnotation::AnyFunction => "Function".to_string(),
            TypeAnnotation::Union { .. } => "Any".to_string(), // For now, union types are treated as Any
            TypeAnnotation::Null => "Null".to_string(),
            TypeAnnotation::Any => "Any".to_string(),
            TypeAnnotation::TypeReference(_) => "Any".to_string(), // Type aliases not yet implemented
        }
    }
}
