//! Symbol table for variable bindings

use crate::error::CompileError;
use std::collections::HashMap;

/// Symbol table for variable bindings
#[derive(Debug)]
pub(crate) struct SymbolTable {
    /// Variable name → register mapping
    symbols: HashMap<String, u8>,

    /// Variable name → upvalue index mapping
    upvalues: HashMap<String, u8>,
}

impl SymbolTable {
    pub(crate) fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            upvalues: HashMap::new(),
        }
    }

    /// Define a new variable
    pub(crate) fn define(&mut self, name: String, register: u8) -> Result<(), CompileError> {
        self.symbols.insert(name, register);
        Ok(())
    }

    /// Define an upvalue
    pub(crate) fn define_upvalue(
        &mut self,
        name: String,
        upvalue_idx: u8,
    ) -> Result<(), CompileError> {
        self.upvalues.insert(name, upvalue_idx);
        Ok(())
    }

    /// Get register for variable
    pub(crate) fn get(&self, name: &str) -> Result<u8, CompileError> {
        self.symbols
            .get(name)
            .copied()
            .ok_or_else(|| CompileError::UndefinedVariable(name.to_string()))
    }

    /// Get upvalue index for variable
    pub(crate) fn get_upvalue(&self, name: &str) -> Option<u8> {
        self.upvalues.get(name).copied()
    }

    /// Check if variable exists (either local or upvalue)
    pub(crate) fn has(&self, name: &str) -> bool {
        self.symbols.contains_key(name) || self.upvalues.contains_key(name)
    }

    /// Check if a register is used by any variable
    #[allow(dead_code)]
    pub(crate) fn has_register(&self, reg: u8) -> bool {
        self.symbols.values().any(|&r| r == reg)
    }

    /// Remove a variable from the symbol table
    pub(crate) fn undefine(&mut self, name: &str) {
        self.symbols.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_table() {
        let mut symbols = SymbolTable::new();

        symbols.define("x".to_string(), 5).unwrap();
        symbols.define("y".to_string(), 10).unwrap();

        assert_eq!(symbols.get("x").unwrap(), 5);
        assert_eq!(symbols.get("y").unwrap(), 10);
        assert!(symbols.get("z").is_err());
    }
}
