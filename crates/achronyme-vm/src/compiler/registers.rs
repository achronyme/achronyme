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
        Self {
            index,
            is_temp: true,
        }
    }

    /// Create a variable register result (should not be freed)
    pub(crate) fn var(index: u8) -> Self {
        Self {
            index,
            is_temp: false,
        }
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
            return Err(CompileError::Error(
                "Cannot allocate 0 registers".to_string(),
            ));
        }

        // Try to find consecutive registers in the free_list
        // Sort the free_list to make finding consecutive ranges easier
        if !self.free_list.is_empty() {
            self.free_list.sort_unstable();

            // Look for a consecutive sequence of 'count' registers
            for window_start in 0..self.free_list.len() {
                if window_start + count > self.free_list.len() {
                    break; // Not enough registers left to check
                }

                let start_reg = self.free_list[window_start];
                let mut is_consecutive = true;

                // Check if we have 'count' consecutive registers starting here
                for i in 0..count {
                    let expected = start_reg + (i as u8);
                    if window_start + i >= self.free_list.len()
                        || self.free_list[window_start + i] != expected
                    {
                        is_consecutive = false;
                        break;
                    }
                }

                if is_consecutive {
                    // Found a consecutive sequence! Remove these registers from free_list
                    // Remove in reverse order to avoid index shifting issues
                    for i in (0..count).rev() {
                        self.free_list.remove(window_start + i);
                    }

                    // Update max_used if needed
                    self.max_used = self.max_used.max(start_reg + (count as u8));

                    return Ok(start_reg);
                }
            }
        }

        // Couldn't find consecutive registers in free_list, allocate from next_free
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

    #[test]
    fn test_allocate_many_basic() {
        let mut alloc = RegisterAllocator::new();

        // Allocate 3 consecutive registers
        let r0 = alloc.allocate_many(3).unwrap();
        assert_eq!(r0, 0);
        assert_eq!(alloc.max_used(), 3);

        // Allocate 2 more
        let r3 = alloc.allocate_many(2).unwrap();
        assert_eq!(r3, 3);
        assert_eq!(alloc.max_used(), 5);
    }

    #[test]
    fn test_allocate_many_reuse() {
        let mut alloc = RegisterAllocator::new();

        // Allocate and free registers to create a consecutive free range
        let r0 = alloc.allocate_many(2).unwrap(); // R0, R1
        assert_eq!(r0, 0);

        alloc.free(0);
        alloc.free(1);

        // Should reuse R0-R1 instead of allocating R2-R3
        let r_reused = alloc.allocate_many(2).unwrap();
        assert_eq!(r_reused, 0);
        assert_eq!(alloc.max_used(), 2); // Should not increase
    }

    #[test]
    fn test_allocate_many_partial_reuse() {
        let mut alloc = RegisterAllocator::new();

        // Allocate R0-R4
        alloc.allocate_many(5).unwrap();

        // Free R0, R1, R2 (consecutive) and R4 (not consecutive with others)
        alloc.free(0);
        alloc.free(1);
        alloc.free(2);
        alloc.free(4);

        // Should reuse R0-R2 (3 consecutive registers)
        let r_reused = alloc.allocate_many(3).unwrap();
        assert_eq!(r_reused, 0);

        // R3 is still allocated, R4 is free, so next allocation goes to R5
        let r_new = alloc.allocate_many(2).unwrap();
        assert_eq!(r_new, 5);
    }

    #[test]
    fn test_allocate_many_no_consecutive_available() {
        let mut alloc = RegisterAllocator::new();

        // Allocate R0-R3
        alloc.allocate_many(4).unwrap();

        // Free R0 and R2 (not consecutive)
        alloc.free(0);
        alloc.free(2);

        // Need 2 consecutive, but only have R0 and R2 separately
        // Should allocate from next_free (R4-R5)
        let r_new = alloc.allocate_many(2).unwrap();
        assert_eq!(r_new, 4);
    }
}
