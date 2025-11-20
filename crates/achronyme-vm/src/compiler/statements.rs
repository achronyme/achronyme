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
                type_annotation,
                initializer,
            }
            | AstNode::MutableDecl {
                name,
                type_annotation,
                initializer,
            } => {
                let value_res = self.compile_expression(initializer)?;
                let var_reg = self.registers.allocate()?;

                // Move value to variable register
                self.emit_move(var_reg, value_res.reg());

                // If type annotation exists, emit TYPE_ASSERT
                if let Some(ref type_ann) = type_annotation {
                    let type_name = self.type_annotation_to_string(type_ann);
                    let type_idx = self.add_string(type_name)?;

                    // TYPE_ASSERT R[var_reg], K[type_idx]
                    // Uses ABx format: A = value register, Bx = type constant index
                    self.emit(encode_abx(OpCode::TypeAssert.as_u8(), var_reg, type_idx as u16));
                }

                // Free value ONLY if temporary
                if value_res.is_temp() {
                    self.registers.free(value_res.reg());
                }

                // Define in symbol table
                self.symbols.define(name.clone(), var_reg)?;

                Ok(())
            }

            AstNode::LetDestructuring {
                pattern,
                initializer,
                ..
            }
            | AstNode::MutableDestructuring {
                pattern,
                initializer,
                ..
            } => {
                use crate::compiler::patterns::PatternMode;

                // Compile the initializer expression
                let value_res = self.compile_expression(initializer)?;

                // Compile the pattern in irrefutable mode (let binding)
                self.compile_pattern(pattern, value_res.reg(), PatternMode::Irrefutable)?;

                // Free value ONLY if temporary
                if value_res.is_temp() {
                    self.registers.free(value_res.reg());
                }

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

                    AstNode::IndexAccess { object, indices } => {
                        use achronyme_parser::ast::IndexArg;

                        // For Phase 3, only support single index access
                        if indices.len() != 1 {
                            return Err(CompileError::Error(
                                "Multi-dimensional indexing not yet supported".to_string(),
                            ));
                        }

                        // Extract the single index
                        let index_node = match &indices[0] {
                            IndexArg::Single(node) => node,
                            IndexArg::Range { .. } => {
                                return Err(CompileError::Error(
                                    "Range slicing not yet supported".to_string(),
                                ));
                            }
                        };

                        // Vector/array element assignment: arr[idx] = value
                        let obj_res = self.compile_expression(object)?;
                        let idx_res = self.compile_expression(index_node)?;

                        // Emit VecSet: obj[idx] = value
                        self.emit(encode_abc(
                            OpCode::VecSet.as_u8(),
                            obj_res.reg(),
                            idx_res.reg(),
                            value_res.reg(),
                        ));

                        // Free temporaries
                        if obj_res.is_temp() {
                            self.registers.free(obj_res.reg());
                        }
                        if idx_res.is_temp() {
                            self.registers.free(idx_res.reg());
                        }
                    }

                    AstNode::FieldAccess { record, field } => {
                        // Record field assignment: rec.field = value
                        let rec_res = self.compile_expression(record)?;

                        // Add field name to constant pool
                        let field_idx = self.add_string(field.clone())?;

                        // Emit SetField: rec[field] = value
                        self.emit(encode_abc(
                            OpCode::SetField.as_u8(),
                            rec_res.reg(),
                            field_idx as u8,
                            value_res.reg(),
                        ));

                        // Free temporary
                        if rec_res.is_temp() {
                            self.registers.free(rec_res.reg());
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

            // Yield statement
            AstNode::Yield { value } => {
                self.compile_yield(value)
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
