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
        // Default: not in tail position
        self.compile_expression_with_tail(node, false)
    }

    /// Compile an expression with tail position awareness
    pub(crate) fn compile_expression_with_tail(&mut self, node: &AstNode, is_tail: bool) -> Result<RegResult, CompileError> {
        match node {
            // Literals
            AstNode::Number(_) | AstNode::Boolean(_) | AstNode::Null | AstNode::StringLiteral(_) | AstNode::ComplexLiteral { .. } => {
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
            } => self.compile_if_with_tail(condition, then_expr, Some(else_expr.as_ref()), is_tail),

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
                self.compile_function_call(name, args, is_tail)
            }

            AstNode::CallExpression { callee, args } => {
                self.compile_call_expression(callee, args, is_tail)
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

            AstNode::Yield { value } => {
                self.compile_yield_expr(value)
            }

            // Ranges
            AstNode::RangeExpr { start, end, inclusive } => {
                self.compile_range(start, end, *inclusive)
            }

            // Interpolated strings
            AstNode::InterpolatedString { parts } => {
                self.compile_interpolated_string(parts)
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
                let num_statements = statements.len();

                for (idx, stmt) in statements.iter().enumerate() {
                    // Check if statement is an expression
                    // Note: Yield can be both statement and expression, but we treat it as expression here
                    let is_expression = !matches!(
                        stmt,
                        AstNode::VariableDecl { .. }
                            | AstNode::MutableDecl { .. }
                            | AstNode::LetDestructuring { .. }
                            | AstNode::MutableDestructuring { .. }
                            | AstNode::Assignment { .. }
                            | AstNode::Import { .. }
                            | AstNode::Export { .. }
                            | AstNode::TypeAlias { .. }
                            | AstNode::Return { .. }
                    );

                    if is_expression {
                        if let Some(old_res) = last_res {
                            // Free old result ONLY if temporary
                            if old_res.is_temp() {
                                self.registers.free(old_res.reg());
                            }
                        }
                        // Last expression inherits tail position from parent
                        let is_last = idx == num_statements - 1;
                        let expr_is_tail = is_tail && is_last;
                        last_res = Some(self.compile_expression_with_tail(stmt, expr_is_tail)?);
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
