use crate::error::CompilerError;
use crate::types::{Local, LoopContext, RegType, UpvalueInfo};
use memory::Value;
use vm::opcode::instruction::{encode_abc, encode_abx};
use vm::opcode::OpCode;

/// State specific to ONE function being compiled
pub struct FunctionCompiler {
    pub name: String,
    pub arity: u8,
    pub locals: Vec<Local>,
    pub scope_depth: u32,
    pub bytecode: Vec<u32>,
    pub constants: Vec<Value>,
    pub upvalues: Vec<UpvalueInfo>,
    pub loop_stack: Vec<LoopContext>,

    // Register allocator state
    pub reg_top: u8,
    pub max_slots: u16,

    /// Best-effort compile-time type per register. Used to select specialized
    /// opcodes when operand types are statically known.
    pub reg_types: [RegType; 256],

    // Line tracking: one entry per bytecode instruction
    pub line_info: Vec<u32>,
    pub current_line: u32,
}

impl FunctionCompiler {
    /// Creates a new function compiler.
    /// CRITICAL: reg_top starts at arity to avoid argument/local collision.
    pub fn new(name: String, arity: u8) -> Self {
        Self {
            name,
            arity,
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
            constants: Vec::new(),
            upvalues: Vec::new(),
            loop_stack: Vec::new(),
            reg_top: arity, // Reserve R0..R(arity-1) for arguments
            max_slots: arity as u16,
            reg_types: [RegType::Unknown; 256],
            line_info: Vec::new(),
            current_line: 0,
        }
    }

    pub fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        let start = self.reg_top;
        if (start as usize) + (count as usize) > 255 {
            return Err(CompilerError::RegisterOverflow(None));
        }
        self.reg_top += count;

        if (self.reg_top as u16) > self.max_slots {
            self.max_slots = self.reg_top as u16;
        }
        Ok(start)
    }

    pub fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        let r = self.reg_top;
        if r == 255 {
            return Err(CompilerError::RegisterOverflow(None));
        }
        self.reg_top += 1;

        // Track High Water Mark
        if (self.reg_top as u16) > self.max_slots {
            self.max_slots = self.reg_top as u16;
        }

        Ok(r)
    }

    pub fn free_reg(&mut self, reg: u8) -> Result<(), CompilerError> {
        if self.reg_top == 0 || reg != self.reg_top - 1 {
            return Err(CompilerError::InternalError(format!(
                "register hygiene: expected to free r{}, but reg_top is {}",
                reg, self.reg_top
            )));
        }
        self.reg_top -= 1;
        Ok(())
    }

    pub fn add_constant(&mut self, val: Value) -> usize {
        if let Some(idx) = self.constants.iter().position(|c| c == &val) {
            return idx;
        }
        self.constants.push(val);
        self.constants.len() - 1
    }

    pub fn add_upvalue(&mut self, is_local: bool, index: u8) -> u8 {
        for (i, upval) in self.upvalues.iter().enumerate() {
            if upval.is_local == is_local && upval.index == index {
                return i as u8;
            }
        }
        self.upvalues.push(UpvalueInfo { is_local, index });
        (self.upvalues.len() - 1) as u8
    }

    pub fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.bytecode.push(encode_abc(op.as_u8(), a, b, c));
        self.line_info.push(self.current_line);
    }

    pub fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.bytecode.push(encode_abx(op.as_u8(), a, bx));
        self.line_info.push(self.current_line);
    }

    #[inline]
    pub fn get_reg_type(&self, reg: u8) -> RegType {
        self.reg_types[reg as usize]
    }

    #[inline]
    pub fn set_reg_type(&mut self, reg: u8, ty: RegType) {
        self.reg_types[reg as usize] = ty;
    }

    /// Snapshot the current register type state (for save/restore around control flow).
    pub fn save_reg_types(&self) -> [RegType; 256] {
        self.reg_types
    }

    /// Restore register type state from a snapshot.
    pub fn restore_reg_types(&mut self, saved: [RegType; 256]) {
        self.reg_types = saved;
    }

    pub fn resolve_local(&self, name: &str) -> Option<(usize, u8)> {
        for (i, local) in self.locals.iter().enumerate().rev() {
            if local.name == name {
                return Some((i, local.reg));
            }
        }
        None
    }
}
