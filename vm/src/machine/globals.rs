use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::opcode::{instruction::*, OpCode};

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
        closure_idx: u32,
    ) -> Result<(), RuntimeError> {
        // Get function from heap
        let func = self
            .heap
            .get_function(closure_idx)
            .ok_or(RuntimeError::FunctionNotFound)?;

        match op {
            OpCode::DefGlobalVar | OpCode::DefGlobalLet => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;
                let val = self.get_reg(base, a);

                let c = func.constants.get(bx).ok_or(RuntimeError::InvalidOperand)?;
                if !c.is_string() {
                    return Err(RuntimeError::TypeMismatch(
                        "Global name must be a string handle".into(),
                    ));
                }
                let name_handle = c.as_handle().unwrap();

                let mutable = op == OpCode::DefGlobalVar;
                self.globals.insert(
                    name_handle,
                    GlobalEntry {
                        value: val,
                        mutable,
                    },
                );
            }

            OpCode::GetGlobal => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;

                let c = func.constants.get(bx).ok_or(RuntimeError::InvalidOperand)?;
                if !c.is_string() {
                    return Err(RuntimeError::TypeMismatch(
                        "Global name must be a string handle".into(),
                    ));
                }
                let name_handle = c.as_handle().unwrap();

                if let Some(entry) = self.globals.get(&name_handle) {
                    self.set_reg(base, a, entry.value.clone());
                } else {
                    let name = self
                        .heap
                        .get_string(name_handle)
                        .cloned()
                        .unwrap_or("???".to_string());
                    return Err(RuntimeError::Unknown(format!(
                        "Undefined global variable: {}",
                        name
                    )));
                }
            }

            OpCode::SetGlobal => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;
                let val = self.get_reg(base, a);

                let c = func.constants.get(bx).ok_or(RuntimeError::InvalidOperand)?;
                if !c.is_string() {
                    return Err(RuntimeError::TypeMismatch(
                        "Global name must be a string handle".into(),
                    ));
                }
                let name_handle = c.as_handle().unwrap();

                if let Some(entry) = self.globals.get_mut(&name_handle) {
                    if entry.mutable {
                        entry.value = val;
                    } else {
                        let name = self
                            .heap
                            .get_string(name_handle)
                            .cloned()
                            .unwrap_or("???".to_string());
                        return Err(RuntimeError::Unknown(format!(
                            "Cannot assign to immutable global '{}'",
                            name
                        )));
                    }
                } else {
                    let name = self
                        .heap
                        .get_string(name_handle)
                        .cloned()
                        .unwrap_or("???".to_string());
                    return Err(RuntimeError::Unknown(format!(
                        "Undefined global variable: {}",
                        name
                    )));
                }
            }

            _ => unreachable!(),
        }

        Ok(())
    }
}
