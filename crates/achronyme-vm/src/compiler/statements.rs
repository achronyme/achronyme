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
                for item in items {
                    let name = &item.name;
                    let export_name = if let Some(alias) = &item.alias {
                        alias.clone()
                    } else {
                        name.clone()
                    };

                    // Check if it's a value in the symbol table
                    if let Ok(reg) = self.symbols.get(name) {
                        // Export the value: store it as a global with a special prefix
                        // This ensures the value is preserved after module execution
                        let global_name = format!("__export__{}", export_name);
                        let global_idx = self.add_string(global_name)?;

                        // Emit SET_GLOBAL instruction to save the value
                        self.emit(encode_abx(OpCode::SetGlobal.as_u8(), reg, global_idx as u16));

                        // Track the exported value's register for reference
                        self.exported_values.insert(export_name, reg);
                    } else if self.type_registry.contains_key(name) {
                        // It's a type alias - export from type registry
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
    /// This loads a user module from a file, compiles it, executes it,
    /// and imports the exported values/types into the current scope
    fn compile_import(
        &mut self,
        items: &[achronyme_parser::ast::ImportItem],
        module_path: &str,
    ) -> Result<(), CompileError> {
        use std::fs;

        // Resolve module path relative to current working directory
        // Convert "src/funcion1" to "src/funcion1.soc"
        let file_path = if module_path.ends_with(".soc") {
            module_path.to_string()
        } else {
            format!("{}.soc", module_path)
        };

        // Read the module file
        let source = fs::read_to_string(&file_path)
            .map_err(|e| CompileError::Error(format!("Failed to read module '{}': {}", file_path, e)))?;

        // Parse the module
        let ast = achronyme_parser::parse(&source)
            .map_err(|e| CompileError::Error(format!("Failed to parse module '{}': {:?}", file_path, e)))?;

        // Compile the module
        let mut module_compiler = Compiler::new(file_path.clone());
        let module_bytecode = module_compiler.compile(&ast)
            .map_err(|e| CompileError::Error(format!("Failed to compile module '{}': {:?}", file_path, e)))?;

        // Execute the module to get exported values
        let mut vm = crate::vm::VM::new();
        let _result = vm.execute(module_bytecode.clone())
            .map_err(|e| CompileError::Error(format!("Failed to execute module '{}': {:?}", file_path, e)))?;

        // Get the module's exported values and types
        let value_exports = &module_compiler.exported_values;
        let type_exports = &module_compiler.exported_types;

        // Extract runtime values from VM's globals
        // Exported values are stored as globals with __export__ prefix
        let mut runtime_exports = std::collections::HashMap::new();

        for (name, _) in value_exports.iter() {
            let global_name = format!("__export__{}", name);
            if let Some(value) = vm.get_global(&global_name) {
                eprintln!("DEBUG: Importing '{}' from global '{}': {:?}", name, global_name, value);
                runtime_exports.insert(name.clone(), value.clone());
            } else {
                eprintln!("DEBUG: Global '{}' not found for export '{}'", global_name, name);
            }
        }

        // Import each requested item
        for item in items {
            let original_name = &item.name;
            let local_name = if let Some(alias) = &item.alias {
                alias.clone()
            } else {
                original_name.clone()
            };

            // Check if it's a value export
            if let Some(value) = runtime_exports.get(original_name) {
                // Add the value as a constant
                let const_idx = self.add_constant(value.clone())?;

                // Allocate a register and load the constant
                let reg = self.registers.allocate()?;
                self.emit_load_const(reg, const_idx);

                // Define in symbol table
                self.symbols.define(local_name, reg)?;
            } else if let Some(type_def) = type_exports.get(original_name) {
                // Import the type into the current compiler's type registry
                self.type_registry.insert(local_name, type_def.clone());
            } else {
                return Err(CompileError::Error(format!(
                    "'{}' is not exported from module '{}' (neither as value nor type)",
                    original_name, file_path
                )));
            }
        }

        Ok(())
    }
}
