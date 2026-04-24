//! Thin wrappers on `Compiler` that delegate to the top
//! `FunctionCompiler` on the stack, the constant interners, or the
//! compile-time circom handle/library registries. Also hosts
//! `append_debug_symbols`, which serializes the global-symbol table
//! into the bytecode's debug section.
//!
//! These methods carry no real logic — keeping them here keeps the
//! public surface of `Compiler` (register alloc, intern, emit) in one
//! readable block without crowding `compile` or the resolver-state
//! machinery.

use akron::opcode::OpCode;
use memory::Value;

use super::Compiler;
use crate::error::CompilerError;
use crate::function_compiler::FunctionCompiler;

impl Compiler {
    // Wrappers for FunctionCompiler
    pub fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        self.current()?.alloc_reg()
    }

    pub fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        self.current()?.alloc_contiguous(count)
    }

    pub fn free_reg(&mut self, reg: u8) -> Result<(), CompilerError> {
        self.current()?.free_reg(reg)
    }

    pub fn add_constant(&mut self, val: Value) -> Result<usize, CompilerError> {
        Ok(self.current()?.add_constant(val))
    }

    pub fn add_upvalue(&mut self, is_local: bool, index: u8) -> Result<u8, CompilerError> {
        Ok(self.current()?.add_upvalue(is_local, index))
    }

    pub fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) -> Result<(), CompilerError> {
        self.current()?.emit_abc(op, a, b, c);
        Ok(())
    }

    pub fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) -> Result<(), CompilerError> {
        self.current()?.emit_abx(op, a, bx);
        Ok(())
    }

    pub fn intern_string(&mut self, s: &str) -> u32 {
        self.interner.intern(s)
    }

    pub fn intern_field(&mut self, fe: memory::FieldElement) -> u32 {
        self.field_interner.intern(fe)
    }

    pub fn intern_bigint(&mut self, bi: memory::BigInt) -> u32 {
        self.bigint_interner.intern(bi)
    }

    pub fn intern_bytes(&mut self, data: Vec<u8>) -> u32 {
        self.bytes_interner.intern(data)
    }

    /// Register a circom handle descriptor and return the heap
    /// index the VM will resolve at program-run time.
    pub fn intern_circom_handle(&mut self, handle: memory::CircomHandle) -> u32 {
        self.circom_handle_interner.intern(handle)
    }

    /// Register a circom library in the compile-time registry and
    /// return its id. Called by the VM-mode codegen when it sees
    /// the first template call against a library.
    pub fn register_circom_library(&mut self, lib: std::sync::Arc<circom::CircomLibrary>) -> u32 {
        self.circom_library_registry.intern(lib)
    }

    /// Returns a mutable reference to the current (top) function compiler
    pub fn current(&mut self) -> Result<&mut FunctionCompiler, CompilerError> {
        self.compilers
            .last_mut()
            .ok_or_else(|| CompilerError::InternalError("compiler stack underflow".into()))
    }

    /// Returns an immutable reference to the current function compiler
    pub fn current_ref(&self) -> Result<&FunctionCompiler, CompilerError> {
        self.compilers
            .last()
            .ok_or_else(|| CompilerError::InternalError("compiler stack underflow".into()))
    }

    pub fn append_debug_symbols(&self, buffer: &mut Vec<u8>) {
        // 1. Invert Name->Index to (Index, Name) for serialization
        let mut symbols: Vec<(u16, &String)> = self
            .global_symbols
            .iter()
            .map(|(k, v)| (v.index, k))
            .collect();

        // 2. Sort by Index (Deterministic output is mandatory for build reproducibility)
        symbols.sort_by_key(|&(idx, _)| idx);

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
}
