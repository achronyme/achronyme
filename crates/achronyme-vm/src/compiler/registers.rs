//! Register allocation

use crate::error::CompileError;

/// Result of compiling an expression - tracks register ownership
#[derive(Debug, Clone, Copy)]
pub(crate) struct RegResult {
    /// Register index
    index: u8,
    /// True if this is a temporary register that can be freed
    is_temp: bool,
}

impl RegResult {
    /// Create a temporary register result (can be freed)
    pub(crate) fn temp(index: u8) -> Self {
        Self { index, is_temp: true }
    }

    /// Create a variable register result (should not be freed)
    pub(crate) fn var(index: u8) -> Self {
        Self { index, is_temp: false }
    }

    /// Get the register index
    pub(crate) fn reg(&self) -> u8 {
        self.index
    }

    /// Check if this is a temporary register
    pub(crate) fn is_temp(&self) -> bool {
        self.is_temp
    }
}

/// Register allocator for a function
#[derive(Debug)]
pub(crate) struct RegisterAllocator {
    /// Next available register
    next_free: u8,

    /// Maximum registers used
    max_used: u8,

    /// Free list for register reuse
    free_list: Vec<u8>,
}

impl RegisterAllocator {
    pub(crate) fn new() -> Self {
        Self {
            next_free: 0,
            max_used: 0,
            free_list: Vec::new(),
        }
    }

    /// Allocate a new register
    pub(crate) fn allocate(&mut self) -> Result<u8, CompileError> {
        if let Some(reg) = self.free_list.pop() {
            // Update max_used if this register is higher
            self.max_used = self.max_used.max(reg + 1);
            Ok(reg)
        } else if self.next_free < 255 {
            let reg = self.next_free;
            self.next_free += 1;
            self.max_used = self.max_used.max(self.next_free);
            Ok(reg)
        } else {
            Err(CompileError::TooManyRegisters)
        }
    }

    /// Allocate multiple consecutive registers
    /// Returns the first register in the sequence
    pub(crate) fn allocate_many(&mut self, count: usize) -> Result<u8, CompileError> {
        if count == 0 {
            return Err(CompileError::Error("Cannot allocate 0 registers".to_string()));
        }

        // For simplicity, always allocate from next_free (don't use free_list for consecutive allocations)
        // This ensures registers are consecutive
        let start_reg = self.next_free;

        // Check if we have enough space
        if start_reg as usize + count > 255 {
            return Err(CompileError::TooManyRegisters);
        }

        // Allocate all registers
        self.next_free = start_reg + count as u8;
        self.max_used = self.max_used.max(self.next_free);

        Ok(start_reg)
    }

    /// Free a register for reuse
    pub(crate) fn free(&mut self, reg: u8) {
        if !self.free_list.contains(&reg) {
            self.free_list.push(reg);
        }
    }

    /// Get maximum registers used
    pub(crate) fn max_used(&self) -> u8 {
        self.max_used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_allocator() {
        let mut alloc = RegisterAllocator::new();

        let r0 = alloc.allocate().unwrap();
        let r1 = alloc.allocate().unwrap();

        assert_eq!(r0, 0);
        assert_eq!(r1, 1);
        assert_eq!(alloc.max_used(), 2);

        alloc.free(r0);
        let r2 = alloc.allocate().unwrap();
        assert_eq!(r2, 0); // Reused
    }
}
