use crate::error::RuntimeError;
use memory::{Upvalue, Value};

/// Trait for upvalue capture and close operations
pub trait UpvalueOps {
    fn capture_upvalue(&mut self, stack_idx: usize) -> Result<u32, RuntimeError>;
    fn close_upvalues(&mut self, last: usize) -> Result<(), RuntimeError>;
}

impl UpvalueOps for super::vm::VM {
    /// Capture an upvalue for a local variable at `stack_idx` (absolute index).
    fn capture_upvalue(&mut self, stack_idx: usize) -> Result<u32, RuntimeError> {
        let mut prev_upval_idx: Option<u32> = None;
        let mut upval_idx = self.open_upvalues;

        while let Some(idx) = upval_idx {
            let upval = self
                .heap
                .get_upvalue(idx)
                .ok_or(RuntimeError::SystemError("stale upvalue handle".into()))?;

            // Open upvalue list is sorted by stack index (high → low).
            let loc = match upval.location {
                memory::UpvalueLocation::Open(si) => si,
                _ => break, // should not happen in open list
            };

            if loc == stack_idx {
                return Ok(idx); // already captured
            }

            if loc < stack_idx {
                break; // insertion point found
            }

            prev_upval_idx = Some(idx);
            upval_idx = upval.next_open;
        }

        // Not found — create new open upvalue
        let created_upval = Upvalue {
            location: memory::UpvalueLocation::Open(stack_idx),
            next_open: upval_idx, // link to next (lower index)
        };
        let new_idx = self.heap.alloc_upvalue(created_upval)?;

        if let Some(prev) = prev_upval_idx {
            let prev_obj = self
                .heap
                .get_upvalue_mut(prev)
                .ok_or(RuntimeError::SystemError("stale upvalue handle".into()))?;
            prev_obj.next_open = Some(new_idx);
        } else {
            self.open_upvalues = Some(new_idx);
        }

        Ok(new_idx)
    }

    /// Close all open upvalues pointing at stack index >= `last`.
    /// Copies the stack value into the upvalue and marks it Closed.
    fn close_upvalues(&mut self, last: usize) -> Result<(), RuntimeError> {
        while let Some(idx) = self.open_upvalues {
            let upval = self
                .heap
                .get_upvalue(idx)
                .ok_or(RuntimeError::SystemError("stale upvalue handle".into()))?;

            let stack_idx = match upval.location {
                memory::UpvalueLocation::Open(si) => si,
                _ => break,
            };

            if stack_idx >= last {
                // Capture value from stack
                let captured_val = self.stack.get(stack_idx).copied().unwrap_or(Value::nil());

                let upval_mut = self
                    .heap
                    .get_upvalue_mut(idx)
                    .ok_or(RuntimeError::SystemError("stale upvalue handle".into()))?;
                upval_mut.location = memory::UpvalueLocation::Closed(captured_val);

                let next = upval_mut.next_open;
                self.open_upvalues = next;
            } else {
                // List is sorted high → low; all remaining are < last.
                break;
            }
        }
        Ok(())
    }
}
