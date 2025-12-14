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

                let func_val = self.get_reg(base, b);
                let args_start = base + b + 1;
                let args_count = c;

                if args_start + args_count > self.stack.len() {
                    return Err(RuntimeError::StackUnderflow);
                }

                if func_val.is_native() {
                    self.call_native(func_val, args_start, args_count, base, a)?;
                } else if func_val.is_function() {
                    return Err(RuntimeError::Unknown(
                        "Script function calls not implemented yet".into(),
                    ));
                } else {
                    return Err(RuntimeError::TypeMismatch(
                        "Call target must be Function or Native".into(),
                    ));
                }
            }

            OpCode::Return => {
                let a = decode_a(instruction) as usize;
                let _ret_val = self.get_reg(base, a);
                self.frames.pop();
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
        self.set_reg(base, result_reg, res);

        Ok(())
    }
}
