use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::stack::StackOps;

/// Trait for iterator instruction handlers (GetIter, ForIter)
pub trait IteratorOps {
    fn handle_iterator(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
        frame_idx: usize,
        max_slots: usize,
        chunk_len: usize,
    ) -> Result<(), RuntimeError>;
}

impl IteratorOps for super::vm::VM {
    fn handle_iterator(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
        frame_idx: usize,
        max_slots: usize,
        chunk_len: usize,
    ) -> Result<(), RuntimeError> {
        match op {
            OpCode::GetIter => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let val = self.get_reg(base, b)?;

                if val.is_iter() {
                    self.set_reg(base, a, val)?;
                } else {
                    let iter_obj = if val.is_list() {
                        // Snapshot: clone list contents so mutations during
                        // iteration don't cause stale reads or OOB access.
                        let l_handle = val
                            .as_handle()
                            .ok_or_else(|| RuntimeError::type_mismatch("Expected list handle"))?;
                        let snapshot = self
                            .heap
                            .get_list(l_handle)
                            .ok_or(RuntimeError::stale_heap("List", "GetIter"))?
                            .clone();
                        let snap_handle = self.heap.alloc_list(snapshot)?;
                        memory::IteratorObj {
                            source: Value::list(snap_handle),
                            index: 0,
                        }
                    } else if val.is_map() {
                        let handle = val
                            .as_handle()
                            .ok_or_else(|| RuntimeError::type_mismatch("Expected map handle"))?;
                        let map_keys: Vec<String> = {
                            let map = self
                                .heap
                                .get_map(handle)
                                .ok_or(RuntimeError::stale_heap("Map", "GetIter"))?;
                            map.keys().cloned().collect()
                        };

                        self.heap.lock_gc();
                        let mut val_keys = Vec::with_capacity(map_keys.len());
                        for s in map_keys {
                            let handle = if let Some(&h) = self.interner.get(&s) {
                                h
                            } else {
                                let h = self.heap.alloc_string(s.clone())?;
                                self.interner.insert(s, h);
                                h
                            };
                            val_keys.push(Value::string(handle));
                        }

                        let list_handle = self.heap.alloc_list(val_keys)?;
                        self.heap.unlock_gc();
                        memory::IteratorObj {
                            source: Value::list(list_handle),
                            index: 0,
                        }
                    } else {
                        return Err(RuntimeError::type_mismatch(format!(
                            "Value not iterable: {:?}",
                            val
                        )));
                    };

                    let handle = self.heap.alloc_iterator(iter_obj)?;
                    self.set_reg(base, a, Value::iterator(handle))?;
                }
            }

            OpCode::ForIter => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;

                if bx > chunk_len {
                    return Err(RuntimeError::out_of_bounds(format!(
                        "ForIter exit target {bx} exceeds chunk length {chunk_len}"
                    )));
                }
                if a + 1 >= max_slots {
                    return Err(RuntimeError::StackOverflow);
                }

                let iter_val = self.get_reg(base, a)?;
                if !iter_val.is_iter() {
                    return Err(RuntimeError::type_mismatch("Expected iterator for loop"));
                }
                let iter_handle = iter_val
                    .as_handle()
                    .ok_or_else(|| RuntimeError::type_mismatch("Expected iterator handle"))?;

                let (source, index) = {
                    let iter = self
                        .heap
                        .get_iterator(iter_handle)
                        .ok_or(RuntimeError::stale_heap("Iterator", "ForIter"))?;
                    (iter.source, iter.index)
                };

                let mut next_val = None;

                if source.is_list() {
                    let l_handle = source
                        .as_handle()
                        .ok_or_else(|| RuntimeError::type_mismatch("Expected list handle"))?;
                    if let Some(list) = self.heap.get_list(l_handle) {
                        if index < list.len() {
                            next_val = Some(list[index]);
                        }
                    }
                }

                if let Some(val) = next_val {
                    if let Some(iter) = self.heap.get_iterator_mut(iter_handle) {
                        iter.index += 1;
                    }
                    self.set_reg(base, a + 1, val)?;
                } else {
                    self.frames[frame_idx].ip = bx;
                }
            }

            _ => return Err(RuntimeError::InvalidOpcode(op as u8)),
        }

        Ok(())
    }
}
