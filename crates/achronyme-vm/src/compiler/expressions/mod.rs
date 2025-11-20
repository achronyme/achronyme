//! Expression compilation

use crate::compiler::registers::RegResult;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;

mod access;
mod control;
mod functions;
mod generators;
mod literals;
mod operators;
mod variables;

impl Compiler {
    /// Compile an expression (returns register holding result)
    pub(crate) fn compile_expression(&mut self, node: &AstNode) -> Result<RegResult, CompileError> {
        match node {
            // Literals
            AstNode::Number(_) | AstNode::Boolean(_) | AstNode::Null | AstNode::StringLiteral(_) => {
                self.compile_literal(node)
            }

            // Variables
            AstNode::VariableRef(name) => {
                self.compile_variable_ref(name)
            }

            AstNode::RecReference => {
                self.compile_rec_reference()
            }

            // Operators
            AstNode::BinaryOp { op, left, right } => {
                self.compile_binary_op(op, left, right)
            }

            AstNode::UnaryOp { op, operand } => {
                self.compile_unary_op(op, operand)
            }

            // Control flow
            AstNode::If {
                condition,
                then_expr,
                else_expr,
            } => self.compile_if(condition, then_expr, Some(else_expr.as_ref())),

            AstNode::WhileLoop { condition, body } => {
                self.compile_while(condition, body)
            }

            AstNode::ForInLoop { variable, iterable, body } => {
                self.compile_for_in(variable, iterable, body)
            }

            AstNode::Match { value, arms } => {
                self.compile_match(value, arms)
            }

            // Exception handling
            AstNode::TryCatch {
                try_block,
                error_param,
                catch_block,
            } => self.compile_try_catch(try_block, error_param, catch_block),

            AstNode::Throw { value } => {
                self.compile_throw(value)
            }

            // Functions
            AstNode::Lambda {
                params,
                return_type: _,
                body,
            } => {
                self.compile_lambda(params, body)
            }

            AstNode::FunctionCall { name, args } => {
                self.compile_function_call(name, args)
            }

            AstNode::CallExpression { callee, args } => {
                self.compile_call_expression(callee, args)
            }

            // Array and Record literals
            AstNode::ArrayLiteral(elements) => {
                self.compile_array_literal(elements)
            }

            AstNode::RecordLiteral(fields) => {
                self.compile_record_literal(fields)
            }

            // Access expressions
            AstNode::IndexAccess { object, indices } => {
                self.compile_index_access(object, indices)
            }

            AstNode::FieldAccess { record, field } => {
                self.compile_field_access(record, field)
            }

            // Generators
            AstNode::GenerateBlock { statements } => {
                self.compile_generate_block(statements)
            }

            // Sequences
            AstNode::Break { value } => {
                self.compile_break(value.as_deref())
            }

            AstNode::Continue => {
                self.compile_continue()
            }

            AstNode::Sequence { statements } | AstNode::DoBlock { statements } => {
                let mut last_res: Option<RegResult> = None;
                for stmt in statements {
                    // Check if statement is an expression
                    let is_expression = !matches!(
                        stmt,
                        AstNode::VariableDecl { .. }
                            | AstNode::MutableDecl { .. }
                            | AstNode::LetDestructuring { .. }
                            | AstNode::MutableDestructuring { .. }
                            | AstNode::Assignment { .. }
                            | AstNode::Import { .. }
                            | AstNode::Export { .. }
                    );

                    if is_expression {
                        if let Some(old_res) = last_res {
                            // Free old result ONLY if temporary
                            if old_res.is_temp() {
                                self.registers.free(old_res.reg());
                            }
                        }
                        last_res = Some(self.compile_expression(stmt)?);
                    } else {
                        self.compile_statement(stmt)?;
                    }
                }

                // Return last value or null
                if let Some(res) = last_res {
                    Ok(res)
                } else {
                    let reg = self.registers.allocate()?;
                    self.emit(encode_abc(OpCode::LoadNull.as_u8(), reg, 0, 0));
                    Ok(RegResult::temp(reg))
                }
            }

            _ => Err(CompileError::Error(format!(
                "Expression compilation not yet implemented for {:?}",
                node
            ))),
        }
    }
}
