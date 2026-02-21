use crate::error::RuntimeError;
use crate::opcode::instruction::{decode_a, decode_b, decode_c};
use crate::opcode::OpCode;
use memory::Value;
use std::collections::HashMap;

use super::stack::StackOps;

pub trait DataOps {
    fn handle_data(&mut self, op: OpCode, instruction: u32, base: usize) -> Result<(), RuntimeError>;
}

impl DataOps for super::vm::VM {
    fn handle_data(&mut self, op: OpCode, instruction: u32, base: usize) -> Result<(), RuntimeError> {
        let a = decode_a(instruction) as usize;
        let b = decode_b(instruction) as usize;
        let c = decode_c(instruction) as usize;

        match op {
            OpCode::BuildList => {
                // R[A] = [ R[B] ... R[B+C-1] ]
                let start = base + b;
                let count = c;
                
                // Security Sandwich: Bounds check
                if start + count > self.stack.len() {
                    return Err(RuntimeError::OutOfBounds(format!("Stack underflow in BUILD_LIST: need {} slots", count)));
                }

                // Clona los valores del stack al vector. 
                // Value es Copy-cheap (u64), así que es rápido.
                let mut list = Vec::with_capacity(count);
                for i in 0..count {
                    list.push(self.get_reg(base, b + i)?);
                }

                let handle = self.heap.alloc_list(list);
                self.set_reg(base, a, Value::list(handle))?;
            }

            OpCode::BuildMap => {
                // R[A] = { k1:v1, k2:v2 ... }
                // C es la cantidad de PARES. Consumimos 2*C registros.
                let start = base + b;
                let count = c;
                let total_regs = count * 2;

                if start + total_regs > self.stack.len() {
                     return Err(RuntimeError::OutOfBounds(format!("Stack underflow in BUILD_MAP: need {} slots", total_regs)));
                }

                let mut map = HashMap::with_capacity(count);
                for i in 0..count {
                    let key_idx = b + (i * 2);
                    let val_idx = key_idx + 1;
                    
                    let key = self.get_reg(base, key_idx)?;
                    let val = self.get_reg(base, val_idx)?;

                    // Validación Estricta: Las claves DEBEN ser strings.
                    // No hacemos magia de toString() implícito aquí. Sé estricto.
                    if !key.is_string() {
                         return Err(RuntimeError::TypeMismatch(
                             format!("Map keys must be strings, got {:?}", key)
                         ));
                    }

                    // Recuperar el string real del Heap
                    let s_handle = key.as_handle().unwrap();
                    let s = self.heap.get_string(s_handle)
                        .ok_or(RuntimeError::SystemError("String missing in heap".into()))?
                        .clone(); // Clone necesario porque HashMap es dueño de la clave

                    map.insert(s, val);
                }

                let handle = self.heap.alloc_map(map);
                self.set_reg(base, a, Value::map(handle))?;
            }

            OpCode::GetIndex => {
                // R[A] = R[B][R[C]]
                let target = self.get_reg(base, b)?;
                let key = self.get_reg(base, c)?;

                if target.is_list() {
                    let handle = target.as_handle().unwrap();
                    let list = self.heap.get_list(handle)
                        .ok_or(RuntimeError::SystemError("List missing".into()))?;

                    if let Some(idx_float) = key.as_number() {
                        // Truncamos a entero para indexar (0-based)
                        let idx = idx_float as usize;
                        if idx < list.len() {
                            let val = list[idx];
                            self.set_reg(base, a, val)?;
                        } else {
                            // Lua devuelve nil, Python lanza error. 
                            // En Achronyme, seamos seguros: Error.
                            return Err(RuntimeError::OutOfBounds(format!("Index {} out of bounds (len {})", idx, list.len())));
                        }
                    } else {
                        return Err(RuntimeError::TypeMismatch("List index must be a number".into()));
                    }

                } else if target.is_map() {
                    let handle = target.as_handle().unwrap();
                    let map = self.heap.get_map(handle)
                        .ok_or(RuntimeError::SystemError("Map missing".into()))?;

                    if key.is_string() {
                        let k_handle = key.as_handle().unwrap();
                        let k_str = self.heap.get_string(k_handle).unwrap();
                        
                        let val = map.get(k_str).cloned().unwrap_or(Value::nil());
                        self.set_reg(base, a, val)?;
                    } else {
                         return Err(RuntimeError::TypeMismatch("Map key must be a string".into()));
                    }
                } else {
                    return Err(RuntimeError::TypeMismatch("Can only index Lists or Maps".into()));
                }
            }

            OpCode::SetIndex => {
                // R[A][R[B]] = R[C]
                // OJO: SetIndex no modifica R[A], modifica el Objeto al que apunta R[A].
                let target = self.get_reg(base, a)?;
                let key = self.get_reg(base, b)?;
                let val = self.get_reg(base, c)?;

                if target.is_list() {
                    let handle = target.as_handle().unwrap();
                    // Necesitamos acceso mutable
                    let list = self.heap.get_list_mut(handle)
                        .ok_or(RuntimeError::SystemError("List missing".into()))?;

                    if let Some(idx_float) = key.as_number() {
                        let idx = idx_float as usize;
                        if idx < list.len() {
                            list[idx] = val;
                        } else {
                             // Strict bounds.
                             return Err(RuntimeError::OutOfBounds("List index out of bounds".into()));
                        }
                    } else {
                        return Err(RuntimeError::TypeMismatch("List index must be a number".into()));
                    }

                } else if target.is_map() {
                    let handle = target.as_handle().unwrap();

                    if key.is_string() {
                         let k_handle = key.as_handle().unwrap();
                         // Clone string first to avoid double borrow of heap
                         let k_str = self.heap.get_string(k_handle)
                             .ok_or(RuntimeError::SystemError("String missing in heap".into()))?
                             .clone();
                         
                         let map = self.heap.get_map_mut(handle)
                              .ok_or(RuntimeError::SystemError("Map missing".into()))?;
                         map.insert(k_str, val);
                    } else {
                         return Err(RuntimeError::TypeMismatch("Map key must be a string".into()));
                    }
                } else {
                    return Err(RuntimeError::TypeMismatch("Can only index Lists or Maps".into()));
                }
            }

            _ => unreachable!()
        }
        Ok(())
    }
}
