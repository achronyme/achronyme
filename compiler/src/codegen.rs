use crate::error::CompilerError;
use crate::interner::StringInterner;
use achronyme_parser::{parse_expression, Rule};
use memory::Value;
use pest::iterators::Pair;
use std::collections::HashMap;
use vm::opcode::{
    instruction::{encode_abc, encode_abx},
    OpCode,
};
use crate::expressions::ExpressionCompiler;
use crate::statements::StatementCompiler; 
use crate::control_flow::ControlFlowCompiler; 
use crate::functions::FunctionDefinitionCompiler;
use crate::scopes::ScopeCompiler;
use crate::statements::declarations::DeclarationCompiler;

// Types and FunctionCompiler imported from modules
use crate::types::{Local, UpvalueInfo, LoopContext};
use crate::function_compiler::FunctionCompiler;

// Helper trait imports
use crate::expressions::BinaryCompiler;
use crate::expressions::AtomCompiler;
use crate::expressions::PostfixCompiler;

/// The main compiler orchestrator
pub struct Compiler {
    pub compilers: Vec<FunctionCompiler>, // LIFO Stack of function compilers
    
    // FLAT list of ALL function prototypes (global indices)
    pub prototypes: Vec<memory::Function>,
    
    // Global Symbol Table (Name -> Index)
    pub global_symbols: HashMap<String, u16>,
    pub next_global_idx: u16,

    // String Interner (shared across all functions)
    pub interner: StringInterner,
}

use vm::specs::{NATIVE_TABLE, USER_GLOBAL_START};

impl Compiler {
    pub fn new() -> Self {
        let mut global_symbols = HashMap::new();

        // Pre-populate Natives from SSOT
        for (index, meta) in NATIVE_TABLE.iter().enumerate() {
            global_symbols.insert(meta.name.to_string(), index as u16);
        }

        let next_global_idx = USER_GLOBAL_START;
        
        // Start with a "main" function compiler (arity=0 for top-level script)
        let main_compiler = FunctionCompiler::new("main".to_string(), 0);

        Self {
            compilers: vec![main_compiler],
            prototypes: Vec::new(),
            global_symbols,
            next_global_idx,
            interner: StringInterner::new(),
        }
    }
    
    // Wrappers for FunctionCompiler
    pub fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        self.current().alloc_reg()
    }
    
    pub fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        self.current().alloc_contiguous(count)
    }
    
    pub fn free_reg(&mut self, reg: u8) {
        self.current().free_reg(reg)
    }
    
    pub fn add_constant(&mut self, val: Value) -> usize {
        self.current().add_constant(val)
    }
    
    pub fn add_upvalue(&mut self, is_local: bool, index: u8) -> u8 {
        self.current().add_upvalue(is_local, index)
    }
    
    pub fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.current().emit_abc(op, a, b, c)
    }
    
    pub fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.current().emit_abx(op, a, bx)
    }

    pub fn intern_string(&mut self, s: &str) -> u32 {
        self.interner.intern(s)
    }

    /// Returns a mutable reference to the current (top) function compiler
    pub fn current(&mut self) -> &mut FunctionCompiler {
        self.compilers.last_mut().expect("Compiler stack underflow")
    }
    
    /// Returns an immutable reference to the current function compiler
    pub fn current_ref(&self) -> &FunctionCompiler {
        self.compilers.last().expect("Compiler stack underflow")
    }

    pub fn append_debug_symbols(&self, buffer: &mut Vec<u8>) {
        // 1. Invert Name->Index to (Index, Name) for serialization
        let mut symbols: Vec<(&u16, &String)> = self
            .global_symbols
            .iter()
            .map(|(k, v)| (v, k))
            .collect();

        // 2. Sort by Index (Deterministic output is mandatory for build reproducibility)
        symbols.sort_by_key(|&(idx, _)| *idx);

        // 3. Write Section
        buffer.extend_from_slice(&[0xDB, 0x67]); // Magic "DBg"
        buffer.extend_from_slice(&(symbols.len() as u16).to_le_bytes());

        for (index, name) in symbols {
            let name_bytes = name.as_bytes();
            buffer.extend_from_slice(&index.to_le_bytes());
            buffer.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buffer.extend_from_slice(name_bytes);
        }
    }

    pub fn compile(&mut self, source: &str) -> Result<Vec<u32>, CompilerError> {
        let pairs =
            parse_expression(source).map_err(|e| CompilerError::ParseError(e.to_string()))?;

        for pair in pairs {
            if pair.as_rule() == Rule::EOI {
                continue;
            }
            match pair.as_rule() {
                Rule::stmt => self.compile_stmt(pair)?,
                Rule::expr => {
                    let reg = self.compile_expr(pair)?;
                    self.free_reg(reg);
                }
                _ => {
                    // Comments or whitespace
                }
            }
        }

        // Final return
        self.emit_abc(OpCode::Return, 0, 0, 0); // Return Nil/0

        Ok(self.current().bytecode.clone())
    }
}
