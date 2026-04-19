use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::stack::StackOps;
use super::upvalue::UpvalueOps;

/// Trait for closure and upvalue instruction handlers
pub trait ClosureOps {
    fn handle_closure(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
        frame_idx: usize,
    ) -> Result<(), RuntimeError>;
}

impl ClosureOps for super::vm::VM {
    fn handle_closure(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
        frame_idx: usize,
    ) -> Result<(), RuntimeError> {
        match op {
            OpCode::GetUpvalue => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;

                let closure_idx = self.frames[frame_idx].closure;
                let closure = self
                    .heap
                    .get_closure(closure_idx)
                    .ok_or(RuntimeError::FunctionNotFound)?;
                let upval_idx = *closure
                    .upvalues
                    .get(bx)
                    .ok_or(RuntimeError::out_of_bounds("Upvalue index"))?;
                let upval = self
                    .heap
                    .get_upvalue(upval_idx)
                    .ok_or(RuntimeError::StaleUpvalue)?;

                let val = match upval.location {
                    memory::UpvalueLocation::Open(stack_idx) => self.get_reg(0, stack_idx)?,
                    memory::UpvalueLocation::Closed(v) => v,
                };
                self.set_reg(base, a, val)?;
            }

            OpCode::SetUpvalue => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;
                let val = self.get_reg(base, a)?;

                let closure_idx = self.frames[frame_idx].closure;
                let closure = self
                    .heap
                    .get_closure(closure_idx)
                    .ok_or(RuntimeError::FunctionNotFound)?;
                let upval_idx = *closure
                    .upvalues
                    .get(bx)
                    .ok_or(RuntimeError::out_of_bounds("Upvalue index"))?;
                let upval = self
                    .heap
                    .get_upvalue(upval_idx)
                    .ok_or(RuntimeError::StaleUpvalue)?;

                match upval.location {
                    memory::UpvalueLocation::Open(stack_idx) => {
                        self.set_reg(0, stack_idx, val)?;
                    }
                    memory::UpvalueLocation::Closed(_) => {
                        let upval_mut = self
                            .heap
                            .get_upvalue_mut(upval_idx)
                            .ok_or(RuntimeError::StaleUpvalue)?;
                        upval_mut.location = memory::UpvalueLocation::Closed(val);
                    }
                }
            }

            OpCode::CloseUpvalue => {
                let a = decode_a(instruction) as usize;
                let stack_idx = base + a;
                self.close_upvalues(stack_idx)?;
            }

            OpCode::Closure => {
                let a = decode_a(instruction) as usize;
                let bx = decode_bx(instruction) as usize;

                let proto_idx = *self
                    .prototypes
                    .get(bx)
                    .ok_or(RuntimeError::FunctionNotFound)?;

                let upval_count = {
                    let proto = self
                        .heap
                        .get_function(proto_idx)
                        .ok_or(RuntimeError::FunctionNotFound)?;
                    let len = proto.upvalue_info.len();
                    if len % 2 != 0 {
                        return Err(RuntimeError::out_of_bounds(format!(
                            "upvalue_info length {len} is not even"
                        )));
                    }
                    len
                };

                self.heap.lock_gc();
                let mut captured = Vec::with_capacity(upval_count / 2);
                let mut i = 0;
                let capture_result: Result<(), RuntimeError> = (|| {
                    while i < upval_count {
                        let (is_local, index) = {
                            let proto = self
                                .heap
                                .get_function(proto_idx)
                                .ok_or(RuntimeError::FunctionNotFound)?;
                            (
                                proto.upvalue_info[i] == 1,
                                proto.upvalue_info[i + 1] as usize,
                            )
                        };
                        i += 2;

                        if is_local {
                            let stack_idx = base + index;
                            let upval_idx = self.capture_upvalue(stack_idx)?;
                            captured.push(upval_idx);
                        } else {
                            let current_closure_idx = self.frames[frame_idx].closure;
                            let current_closure = self
                                .heap
                                .get_closure(current_closure_idx)
                                .ok_or(RuntimeError::FunctionNotFound)?;
                            let upval_idx = *current_closure
                                .upvalues
                                .get(index)
                                .ok_or(RuntimeError::out_of_bounds("Upvalue capture"))?;
                            captured.push(upval_idx);
                        }
                    }
                    Ok(())
                })();
                if let Err(e) = capture_result {
                    self.heap.unlock_gc();
                    return Err(e);
                }

                let closure = memory::Closure {
                    function: proto_idx,
                    upvalues: captured,
                };
                let closure_idx = self.heap.alloc_closure(closure)?;
                self.heap.unlock_gc();
                self.set_reg(base, a, Value::closure(closure_idx))?;
            }

            _ => return Err(RuntimeError::InvalidOpcode(op as u8)),
        }

        Ok(())
    }
}
