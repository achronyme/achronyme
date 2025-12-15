use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::stack::StackOps;

/// Trait for global variable instruction handlers
pub trait GlobalOps {
    fn handle_globals(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
        closure_idx: u32,
    ) -> Result<(), RuntimeError>;
}

impl GlobalOps for super::vm::VM {
    fn handle_globals(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
        _closure_idx: u32,
    ) -> Result<(), RuntimeError> {
        // We no longer need 'func' to get constants, because Bx is a raw index
        let bx = decode_bx(instruction) as usize;

        match op {
            OpCode::DefGlobalVar | OpCode::DefGlobalLet => {
                let a = decode_a(instruction) as usize;
                let val = self.get_reg(base, a);
                let mutable = op == OpCode::DefGlobalVar;

                // Ensure capacity
                if bx >= self.globals.len() {
                    // Resize to fit. Since compiler emits sequential indices, this should be fine.
                    // Fill gaps with Nil if any (though logic suggests sequential)
                    self.globals.resize(
                        bx + 1,
                        GlobalEntry {
                            value: Value::nil(),
                            mutable: true, // safe default
                        },
                    );
                }

                self.globals[bx] = GlobalEntry {
                    value: val,
                    mutable,
                };
            }

            OpCode::GetGlobal => {
                let a = decode_a(instruction) as usize;
                if bx >= self.globals.len() {
                    let name = self
                        .debug_symbols
                        .as_ref()
                        .and_then(|map| map.get(&(bx as u16)))
                        .map(|s| format!("'{}'", s))
                        .unwrap_or_else(|| format!("Index {}", bx));

                    return Err(RuntimeError::Unknown(format!(
                        "Undefined global variable: {} (Index {})",
                        name, bx
                    )));
                }
                let entry = &self.globals[bx];
                self.set_reg(base, a, entry.value.clone());
            }

            OpCode::SetGlobal => {
                let a = decode_a(instruction) as usize;
                let val = self.get_reg(base, a);

                if bx >= self.globals.len() {
                     let name = self
                        .debug_symbols
                        .as_ref()
                        .and_then(|map| map.get(&(bx as u16)))
                        .map(|s| format!("'{}'", s))
                        .unwrap_or_else(|| format!("Index {}", bx));

                    return Err(RuntimeError::Unknown(format!(
                        "Undefined global variable: {} (Index {})",
                        name, bx
                    )));
                }

                let entry = &mut self.globals[bx];
                if entry.mutable {
                    entry.value = val;
                } else {
                     let name = self
                        .debug_symbols
                        .as_ref()
                        .and_then(|map| map.get(&(bx as u16)))
                        .map(|s| format!("'{}'", s))
                        .unwrap_or_else(|| format!("Index {}", bx));

                    return Err(RuntimeError::Unknown(format!(
                        "Cannot assign to immutable global: {} (Index {})",
                        name, bx
                    )));
                }
            }

            _ => unreachable!(),
        }

        Ok(())
    }
}
