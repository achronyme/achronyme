//! Statement compilation

use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
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

            // Compound assignment (+=, -=, *=, /=, %=, ^=)
            AstNode::CompoundAssignment { target, operator, value } => {
                use achronyme_parser::ast::CompoundOp;

                // 1. Read the current value of the target
                let current_res = self.compile_expression(target)?;

                // 2. Compile the RHS value
                let rhs_res = self.compile_expression(value)?;

                // 3. Apply the binary operation
                let result_reg = self.registers.allocate()?;
                let opcode = match operator {
                    CompoundOp::AddAssign => OpCode::Add,
                    CompoundOp::SubAssign => OpCode::Sub,
                    CompoundOp::MulAssign => OpCode::Mul,
                    CompoundOp::DivAssign => OpCode::Div,
                    CompoundOp::ModAssign => OpCode::Mod,
                    CompoundOp::PowAssign => OpCode::Pow,
                };

                self.emit(encode_abc(
                    opcode.as_u8(),
                    result_reg,
                    current_res.reg(),
                    rhs_res.reg(),
                ));

                // Free temporary registers
                if current_res.is_temp() {
                    self.registers.free(current_res.reg());
                }
                if rhs_res.is_temp() {
                    self.registers.free(rhs_res.reg());
                }

                // 4. Assign the result back to the target
                match target.as_ref() {
                    AstNode::VariableRef(name) => {
                        // Check if it's a local variable or an upvalue
                        if let Ok(var_reg) = self.symbols.get(name) {
                            // Local variable
                            self.emit_move(var_reg, result_reg);
                        } else if let Some(upvalue_idx) = self.symbols.get_upvalue(name) {
                            // Upvalue (captured variable)
                            self.emit(encode_abc(OpCode::SetUpvalue.as_u8(), upvalue_idx, result_reg, 0));
                        } else {
                            return Err(CompileError::UndefinedVariable(name.clone()));
                        }
                    }

                    AstNode::FieldAccess { record, field } => {
                        // Compile record expression
                        let rec_res = self.compile_expression(record)?;

                        // Get field name index
                        let field_idx = self.add_string(field.clone())?;

                        // Emit SetField instruction
                        self.emit(encode_abc(
                            OpCode::SetField.as_u8(),
                            rec_res.reg(),
                            field_idx as u8,
                            result_reg,
                        ));

                        // Free temporary
                        if rec_res.is_temp() {
                            self.registers.free(rec_res.reg());
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

                        // Compile object and index
                        let obj_res = self.compile_expression(object)?;
                        let idx_res = self.compile_expression(index_node)?;

                        // Emit VecSet instruction: R[A][R[B]] = R[C]
                        self.emit(encode_abc(
                            OpCode::VecSet.as_u8(),
                            obj_res.reg(),
                            idx_res.reg(),
                            result_reg,
                        ));

                        // Free temporaries
                        if obj_res.is_temp() {
                            self.registers.free(obj_res.reg());
                        }
                        if idx_res.is_temp() {
                            self.registers.free(idx_res.reg());
                        }
                    }

                    _ => {
                        return Err(CompileError::InvalidAssignmentTarget);
                    }
                }

                // Free result register
                self.registers.free(result_reg);
                Ok(())
            }

            // Yield statement
            AstNode::Yield { value } => {
                self.compile_yield(value)
            }

            // Return statement
            AstNode::Return { value } => {
                let value_res = self.compile_expression(value)?;
                self.emit(encode_abc(OpCode::Return.as_u8(), value_res.reg(), 0, 0));
                if value_res.is_temp() {
                    self.registers.free(value_res.reg());
                }
                Ok(())
            }

            // Type alias - register in type registry (no code generation)
            AstNode::TypeAlias { name, type_definition } => {
                // Store the type alias in the compiler's type registry
                self.type_registry.insert(name.clone(), type_definition.clone());
                // Type aliases don't generate any bytecode
                Ok(())
            }

            // Export - mark values/types for export
            AstNode::Export { items } => {
                // Check if we're in a module (has exports_reg)
                let exports_reg = self.exports_reg.ok_or_else(|| {
                    CompileError::Error("Export statements can only be used in modules".to_string())
                })?;

                for item in items {
                    let name = &item.name;
                    let export_name = if let Some(alias) = &item.alias {
                        alias.clone()
                    } else {
                        name.clone()
                    };

                    // Check if it's a value in the symbol table
                    if let Ok(value_reg) = self.symbols.get(name) {
                        // Add field name to constant pool
                        let field_idx = self.add_string(export_name.clone())?;

                        // Emit SetField: exports_rec[field_name] = value
                        self.emit(encode_abc(
                            OpCode::SetField.as_u8(),
                            exports_reg,
                            field_idx as u8,
                            value_reg,
                        ));

                        // Track the exported value's register for reference
                        self.exported_values.insert(export_name, value_reg);
                    } else if self.type_registry.contains_key(name) {
                        // It's a type alias - export from type registry (no bytecode)
                        let type_def = self.type_registry.get(name).unwrap().clone();
                        self.exported_types.insert(export_name, type_def);
                    } else {
                        return Err(CompileError::Error(format!(
                            "Cannot export '{}': not found in current scope (neither value nor type)",
                            name
                        )));
                    }
                }
                Ok(())
            }

            // Import - load module and import exported values/types
            AstNode::Import { items, module_path } => {
                self.compile_import(items, module_path)
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

    /// Compile an import statement
    ///
    /// This generates bytecode that calls the builtin 'import' function
    /// at runtime to load and execute a module, then extracts the requested exports
    fn compile_import(
        &mut self,
        items: &[achronyme_parser::ast::ImportItem],
        module_path: &str,
    ) -> Result<(), CompileError> {
        // 1. Call builtin import(module_path) to get the module's exports Record
        // Add module path as a string constant
        let mod_name_value = Value::String(module_path.to_string());
        let mod_name_idx = self.add_constant(mod_name_value)?;

        // Allocate dest + args registers consecutively
        // We need 2 registers: dest (result) + 1 arg
        let module_res_reg = self.registers.allocate_many(2)?;
        let arg_reg = module_res_reg + 1;

        // Load module path string constant into arg register
        self.emit_load_const(arg_reg, mod_name_idx);

        // CallBuiltin import(arg_reg) -> module_res_reg
        let import_idx = self.builtins.get_id("import")
            .ok_or_else(|| CompileError::Error("Builtin 'import' not found".to_string()))?;

        self.emit(encode_abc(
            OpCode::CallBuiltin.as_u8(),
            module_res_reg,  // A = dest
            1,               // B = argc (1 argument)
            import_idx as u8 // C = builtin_idx
        ));

        // 2. Extract each requested export from the module Record
        for item in items {
            let original_name = &item.name;
            let local_name = item.alias.as_ref().unwrap_or(original_name);

            // Check for name collision
            if self.symbols.get(local_name).is_ok() {
                return Err(CompileError::Error(format!(
                    "Variable '{}' already defined", local_name
                )));
            }

            // Add field name to constant pool
            let field_idx = self.add_string(original_name.clone())?;

            // Allocate register for the imported value
            let var_reg = self.registers.allocate()?;

            // Emit GetField: var_reg = module_res_reg[original_name]
            self.emit(encode_abc(
                OpCode::GetField.as_u8(),
                var_reg,
                module_res_reg,
                field_idx as u8
            ));

            // Define in symbol table
            self.symbols.define(local_name.clone(), var_reg)?;
        }

        // The arg_reg and module_res_reg are now part of the bytecode and shouldn't be freed
        // They will be managed by the VM's register allocation during execution

        Ok(())
    }
}
