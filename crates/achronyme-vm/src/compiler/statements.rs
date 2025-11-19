//! Statement compilation

use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;

impl Compiler {
    /// Compile a statement
    pub(crate) fn compile_statement(&mut self, node: &AstNode) -> Result<(), CompileError> {
        match node {
            AstNode::VariableDecl {
                name,
                initializer,
                ..
            }
            | AstNode::MutableDecl {
                name,
                initializer,
                ..
            } => {
                let value_res = self.compile_expression(initializer)?;
                let var_reg = self.registers.allocate()?;

                // Move value to variable register
                self.emit_move(var_reg, value_res.reg());

                // Free value ONLY if temporary
                if value_res.is_temp() {
                    self.registers.free(value_res.reg());
                }

                // Define in symbol table
                self.symbols.define(name.clone(), var_reg)?;

                Ok(())
            }

            AstNode::Assignment { target, value } => {
                let value_res = self.compile_expression(value)?;

                match target.as_ref() {
                    AstNode::VariableRef(name) => {
                        // Check if it's a local variable or an upvalue
                        if let Ok(var_reg) = self.symbols.get(name) {
                            // Local variable
                            self.emit_move(var_reg, value_res.reg());
                        } else if let Some(upvalue_idx) = self.symbols.get_upvalue(name) {
                            // Upvalue (captured variable)
                            self.emit(encode_abc(OpCode::SetUpvalue.as_u8(), upvalue_idx, value_res.reg(), 0));
                        } else {
                            return Err(CompileError::UndefinedVariable(name.clone()));
                        }
                    }
                    _ => {
                        return Err(CompileError::InvalidAssignmentTarget);
                    }
                }

                // Free value ONLY if temporary
                if value_res.is_temp() {
                    self.registers.free(value_res.reg());
                }
                Ok(())
            }

            // Expression statement (evaluate and discard result)
            _ => {
                let res = self.compile_expression(node)?;
                // Free ONLY if temporary
                if res.is_temp() {
                    self.registers.free(res.reg());
                }
                Ok(())
            }
        }
    }
}
