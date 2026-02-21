use crate::error::RuntimeError;
use crate::opcode::{instruction::*, OpCode};
use memory::Value;

use super::stack::StackOps;

/// Trait for control flow instruction handlers
pub trait ControlFlowOps {
    fn handle_control(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError>;

    fn call_native(
        &mut self,
        func_val: Value,
        args_start: usize,
        args_count: usize,
        base: usize,
        result_reg: usize,
    ) -> Result<(), RuntimeError>;
}

impl ControlFlowOps for super::vm::VM {
    fn handle_control(
        &mut self,
        op: OpCode,
        instruction: u32,
        base: usize,
    ) -> Result<(), RuntimeError> {
        match op {
            OpCode::Call => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize;
                let c = decode_c(instruction) as usize;

                let func_val = self.get_reg(base, b)?;
                let args_start = base + b + 1;
                let args_count = c;

                if args_start + args_count > self.stack.len() {
                    return Err(RuntimeError::StackUnderflow);
                }

                if func_val.is_native() {
                    self.call_native(func_val, args_start, args_count, base, a)?;
                } else if func_val.is_closure() {
                    let handle = func_val.as_handle()
                        .ok_or_else(|| RuntimeError::TypeMismatch("Expected closure handle".into()))?;
                        
                    let closure = self.heap.get_closure(handle).ok_or(RuntimeError::FunctionNotFound)?;
                    let func = self.heap.get_function(closure.function).ok_or(RuntimeError::FunctionNotFound)?;
                    
                    // 1. Check arity (optional but good)
                    if func.arity as usize != args_count {
                         return Err(RuntimeError::ArityMismatch(format!("Expected {} args, got {}", func.arity, args_count)));
                    }

                    // 2. Calculate New Base Pointer
                    // BP = args_start (The arguments become the locals R0..Rn of the new frame)
                    let new_bp = args_start;

                    // 3. THE GOLDEN CHECK
                    // Check if stack has space for this function's PEAK requirement
                    if new_bp + (func.max_slots as usize) >= crate::machine::vm::STACK_MAX {
                         return Err(RuntimeError::StackOverflow);
                    }

                    // 4. Push Frame with dest_reg = caller's base + A (where result goes)
                    let dest_reg = base + a;
                    self.frames.push(crate::machine::frame::CallFrame {
                        closure: handle, // Points to Closure
                        ip: 0,
                        base: new_bp,
                        dest_reg,
                    });
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "Call target must be Closure or Native".into(),
                    ));
                }
            }

            OpCode::Return => {
                let a = decode_a(instruction) as usize;
                let b = decode_b(instruction) as usize; // 1 if has value, 0 if nil
                
                // Get return value

                let ret_val = if b == 1 {
                    self.get_reg(base, a)?
                } else {
                    Value::nil()
                };
                
                // Close Upvalues for current frame
                // "base" is the start of the current frame (R0)
                // Any upvalue pointing to base or higher is now invalid/closed
                let ptr = self.get_reg_ptr(base, 0)?;
                self.close_upvalues(ptr);
                
                // Pop current frame and get its dest_reg
                if let Some(frame) = self.frames.pop() {
                    // Write return value to dest_reg (absolute stack index)
                    // Only if there's still a caller (not the top-level script)
                    if !self.frames.is_empty() {
                        self.set_reg(0, frame.dest_reg, ret_val)?;
                    }
                }
            }

            _ => unreachable!(),
        }

        Ok(())
    }

    fn call_native(
        &mut self,
        func_val: Value,
        args_start: usize,
        args_count: usize,
        base: usize,
        result_reg: usize,
    ) -> Result<(), RuntimeError> {
        let handle = func_val.as_handle().unwrap();
        let (func, arity) = {
            let n = self
                .natives
                .get(handle as usize)
                .ok_or(RuntimeError::FunctionNotFound)?;
            (n.func, n.arity)
        };

        if arity != -1 && arity as usize != args_count {
            return Err(RuntimeError::ArityMismatch(format!(
                "Expected {} args, got {}",
                arity, args_count
            )));
        }

        let args: Vec<Value> = self.stack[args_start..args_start + args_count].to_vec();
        let res = func(self, &args)?;
        self.set_reg(base, result_reg, res)?;

        Ok(())
    }
}
