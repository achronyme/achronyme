//! Literal expression compilation

use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_parser::ast::AstNode;

impl Compiler {
    /// Compile literal expressions
    pub(crate) fn compile_literal(
        &mut self,
        node: &AstNode,
    ) -> Result<RegResult, CompileError> {
        match node {
            AstNode::Number(n) => {
                let reg = self.registers.allocate()?;
                let const_idx = self.add_constant(Value::Number(*n))?;
                self.emit_load_const(reg, const_idx);
                Ok(RegResult::temp(reg))
            }

            AstNode::Boolean(b) => {
                let reg = self.registers.allocate()?;
                if *b {
                    self.emit(encode_abc(OpCode::LoadTrue.as_u8(), reg, 0, 0));
                } else {
                    self.emit(encode_abc(OpCode::LoadFalse.as_u8(), reg, 0, 0));
                }
                Ok(RegResult::temp(reg))
            }

            AstNode::Null => {
                let reg = self.registers.allocate()?;
                self.emit(encode_abc(OpCode::LoadNull.as_u8(), reg, 0, 0));
                Ok(RegResult::temp(reg))
            }

            _ => unreachable!("Non-literal node in literal compiler"),
        }
    }
}
