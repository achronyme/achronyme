use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::error::CompilerError;
use crate::function_compiler::FunctionCompiler;
use crate::types::Local;
use achronyme_parser::ast::*;
use memory::Function;
use vm::opcode::OpCode;

pub trait FunctionDefinitionCompiler {
    fn compile_fn_core(
        &mut self,
        name: Option<&str>,
        params: &[TypedParam],
        body: &Block,
    ) -> Result<u8, CompilerError>;
}

impl FunctionDefinitionCompiler for Compiler {
    fn compile_fn_core(
        &mut self,
        name: Option<&str>,
        params: &[TypedParam],
        body: &Block,
    ) -> Result<u8, CompilerError> {
        let fn_name = name.unwrap_or("lambda").to_string();
        if params.len() > 255 {
            return Err(CompilerError::CompilerLimitation(format!(
                "function `{fn_name}` has {} parameters (maximum is 255)",
                params.len()
            )));
        }
        let arity = params.len() as u8;

        let global_idx = if name.is_some() {
            if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants);
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;
            self.global_symbols.insert(fn_name.clone(), idx);
            Some(idx)
        } else {
            None
        };

        self.compilers
            .push(FunctionCompiler::new(fn_name.clone(), arity));

        for (i, param) in params.iter().enumerate() {
            self.current().locals.push(Local {
                name: param.name.clone(),
                depth: 0,
                is_captured: false,
                reg: i as u8,
            });
        }

        let body_reg = self.alloc_reg()?;
        self.compile_block(body, body_reg)?;

        self.emit_abc(OpCode::Return, body_reg, 1, 0);

        let mut compiled_func = self.compilers.pop().expect("Compiler stack underflow");
        compiled_func.max_slots = compiled_func.max_slots.max(compiled_func.reg_top as u16);

        let func = Function {
            name: compiled_func.name,
            arity: compiled_func.arity,
            max_slots: compiled_func.max_slots,
            chunk: compiled_func.bytecode,
            constants: compiled_func.constants,
            upvalue_info: compiled_func
                .upvalues
                .iter()
                .flat_map(|u| vec![u.is_local as u8, u.index])
                .collect(),
        };

        let global_func_idx = self.prototypes.len();
        self.prototypes.push(func);

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::Closure, target_reg, global_func_idx as u16);

        if let Some(idx) = global_idx {
            self.emit_abx(OpCode::DefGlobalLet, target_reg, idx);
        }

        Ok(target_reg)
    }
}
