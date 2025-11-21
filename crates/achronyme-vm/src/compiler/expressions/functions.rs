//! Function and lambda expression compilation

use crate::bytecode::{FunctionPrototype, UpvalueDescriptor};
use crate::compiler::registers::{RegResult, RegisterAllocator};
use crate::compiler::symbols::SymbolTable;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;
use std::collections::HashSet;

impl Compiler {
    /// Compile lambda expression
    pub(crate) fn compile_lambda(
        &mut self,
        params: &[(String, Option<achronyme_parser::TypeAnnotation>, Option<Box<AstNode>>)],
        body: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Create a nested function compiler
        let lambda_name = format!("<lambda@{}>", self.current_position());
        let mut child_compiler = Compiler {
            module_name: self.module_name.clone(),  // Inherit module name from parent
            function: FunctionPrototype::new(lambda_name, self.function.constants.clone()),
            registers: RegisterAllocator::new(),
            symbols: SymbolTable::new(),
            loops: Vec::new(),
            parent: None,  // We don't need parent for simple compilation
            builtins: self.builtins.clone(),  // Share the built-ins registry
            type_registry: self.type_registry.clone(),  // Share the type registry
            exported_values: std::collections::HashMap::new(),
            exported_types: std::collections::HashMap::new(),
            exports_reg: None,  // Lambdas don't have exports
        };

        // Set parameter count
        child_compiler.function.param_count = params.len() as u8;
        if params.len() > 255 {
            return Err(CompileError::TooManyParameters);
        }

        // Define parameters in symbol table
        for (i, (param_name, _, _)) in params.iter().enumerate() {
            let reg = child_compiler.registers.allocate()?;
            if reg != i as u8 {
                // Parameters must be in registers 0..param_count
                return Err(CompileError::Error(
                    "Parameter register mismatch".to_string()
                ));
            }
            child_compiler.symbols.define(param_name.clone(), reg)?;
        }

        // Emit default value handling and type assertions for each parameter
        // This must happen BEFORE analyzing upvalues, because we might reference parent variables
        for (i, (param_name, type_ann, default_expr)) in params.iter().enumerate() {
            let param_reg = i as u8;

            // If parameter has default value, emit code to check if it's Null and fill it
            if let Some(default_expr) = default_expr {
                // Emit: if R[param] != null then skip default assignment
                // Logic: JumpIfNull jumps if null, so we need the opposite - skip if NOT null
                // We'll use: if param is null, don't jump (fall through to default), else jump over default

                // Actually, we need to use a different approach:
                // Check if null, and if so, fill with default
                // Use JumpIfNull: if null, don't jump (execute default code), else jump over it

                // Emit JumpIfNull - if param is null, jump to the default code; if not null, skip it
                // Wait, JumpIfNull jumps if the value IS null. So:
                // - If param is NOT null (value was provided), jump over the default assignment
                // - If param IS null (no value provided), fall through to execute default assignment

                // We need a "JumpIfNotNull" which doesn't exist. So we do:
                // 1. Check if null
                // 2. If null, don't jump (fall through to compute default)
                // 3. If not null, jump over default code

                // Since JumpIfNull jumps when value IS null, we need to:
                // - First check if NOT null and jump over default
                // But we don't have JumpIfNotNull. Workaround:
                // - Load null into a temp register
                // - Compare with Ne (not equal)
                // - JumpIfTrue if they're not equal (i.e., param is not null)

                let temp_reg = child_compiler.registers.allocate()?;
                child_compiler.emit(encode_abc(OpCode::LoadNull.as_u8(), temp_reg, 0, 0));

                let cmp_reg = child_compiler.registers.allocate()?;
                child_compiler.emit(encode_abc(OpCode::Ne.as_u8(), cmp_reg, param_reg, temp_reg));
                child_compiler.registers.free(temp_reg);

                // Jump over default code if param is not null (i.e., if cmp_reg is true)
                let jump_pos = child_compiler.emit_jump_if_true(cmp_reg, 0);

                // Compile default expression
                let default_res = child_compiler.compile_expression(default_expr)?;

                // Move default value to parameter register if needed
                if default_res.reg() != param_reg {
                    child_compiler.emit_move(param_reg, default_res.reg());
                }
                if default_res.is_temp() {
                    child_compiler.registers.free(default_res.reg());
                }
                child_compiler.registers.free(cmp_reg);

                // Patch the jump - jump over the default code if value was provided
                let current_pos = child_compiler.function.code.len();
                let offset = (current_pos - jump_pos - 1) as i16;
                child_compiler.function.patch_instruction(
                    jump_pos,
                    encode_abx(OpCode::JumpIfTrue.as_u8(), cmp_reg, offset as u16)
                );

                // Mark that this parameter has a default (for metadata)
                child_compiler.function.param_defaults.push(Some(0)); // 0 is placeholder
            } else {
                child_compiler.function.param_defaults.push(None);
            }

            // Emit type assertion if parameter has type annotation
            if let Some(type_ann) = type_ann {
                let type_name = child_compiler.type_annotation_to_string(type_ann);
                let type_idx = child_compiler.add_string(type_name)?;
                child_compiler.emit(encode_abx(OpCode::TypeAssert.as_u8(), param_reg, type_idx as u16));
            }
        }

        // Analyze upvalues by finding variables used but not defined in lambda
        let used_vars = self.find_used_variables(body)?;
        let mut upvalues = Vec::new();

        // IMPORTANT: Reserve upvalue index 0 for 'rec' (self-reference)
        // This is a special upvalue that will be filled at closure creation time
        // with the closure itself, enabling recursive calls
        upvalues.push(UpvalueDescriptor {
            depth: 0,  // Will be filled at closure creation
            register: 0,  // Placeholder - will be set to the closure itself at runtime
            is_mutable: false,  // The function reference itself is immutable
        });
        child_compiler.symbols.define_upvalue("rec".to_string(), 0)?;

        for var in used_vars {
            if !child_compiler.symbols.has(&var) && var != "rec" {
                // This variable is captured from parent scope
                // Skip 'rec' since it's already handled above
                if let Ok(parent_reg) = self.symbols.get(&var) {
                    let upvalue_idx = upvalues.len();
                    if upvalue_idx >= 256 {
                        return Err(CompileError::TooManyUpvalues);
                    }

                    upvalues.push(UpvalueDescriptor {
                        depth: 0,  // Immediate parent
                        register: parent_reg,
                        is_mutable: true,  // Assume mutable for now
                    });

                    // Map variable to upvalue in child's symbol table
                    child_compiler.symbols.define_upvalue(var.clone(), upvalue_idx as u8)?;
                }
            }
        }

        child_compiler.function.upvalues = upvalues;

        // Compile lambda body (always in tail position within the lambda)
        let body_res = child_compiler.compile_expression_with_tail(body, true)?;
        child_compiler.emit(encode_abc(OpCode::Return.as_u8(), body_res.reg(), 0, 0));

        // Set register count based on actual usage
        child_compiler.function.register_count = child_compiler.registers.max_used();

        // Add nested function to parent's function list
        let func_idx = self.function.functions.len();
        self.function.functions.push(child_compiler.function);

        // Emit CLOSURE opcode
        let closure_reg = self.registers.allocate()?;
        self.emit(encode_abx(
            OpCode::Closure.as_u8(),
            closure_reg,
            func_idx as u16,
        ));

        Ok(RegResult::temp(closure_reg))
    }

    /// Compile function call (named function)
    pub(crate) fn compile_function_call(
        &mut self,
        name: &str,
        args: &[AstNode],
        is_tail: bool,
    ) -> Result<RegResult, CompileError> {
        // Check if this is a built-in function call
        if let Some(builtin_idx) = self.builtins.get_id(name) {
            return self.compile_builtin_call(builtin_idx, args);
        }

        // For FunctionCall, lookup the function by name and copy to a fresh register
        // This ensures the function value won't be overwritten when compiling arguments
        let func_reg = if let Ok(source_reg) = self.symbols.get(name) {
            // Variable in current scope (local or parameter)
            let func_reg = self.registers.allocate()?;
            self.emit_move(func_reg, source_reg);
            func_reg
        } else if let Some(upvalue_idx) = self.symbols.get_upvalue(name) {
            // Variable from parent scope (including 'rec' which is always upvalue 0)
            let reg = self.registers.allocate()?;
            self.emit(encode_abc(OpCode::GetUpvalue.as_u8(), reg, upvalue_idx, 0));
            reg
        } else {
            return Err(CompileError::UndefinedVariable(name.to_string()));
        };

        // Allocate temporary registers for arguments (consecutive)
        let mut arg_results = Vec::new();
        for arg in args {
            let arg_res = self.compile_expression(arg)?;
            arg_results.push(arg_res);
        }

        // Arguments must be in consecutive registers starting from func_reg + 1
        // Move them if necessary BEFORE allocating result register
        // IMPORTANT: Move in reverse order to avoid overwriting source registers
        // that are needed for later moves
        for i in (0..arg_results.len()).rev() {
            let arg_reg = arg_results[i].reg();
            // Calculate target register, checking for overflow
            let target_offset = 1u16 + i as u16;
            let target_calc = func_reg as u16 + target_offset;
            if target_calc > 255 {
                return Err(CompileError::TooManyRegisters);
            }
            let target_reg = target_calc as u8;
            if arg_reg != target_reg {
                self.emit_move(target_reg, arg_reg);
            }
        }

        // Check argument count
        if args.len() > 255 {
            return Err(CompileError::Error("Too many arguments".to_string()));
        }

        // Emit CALL or TAIL_CALL depending on tail position
        if is_tail {
            // TAIL_CALL: Replace current frame with callee
            // TailCall doesn't use a result register - it acts as an implicit return
            self.emit(encode_abc(
                OpCode::TailCall.as_u8(),
                0,  // unused
                func_reg,
                args.len() as u8,
            ));

            // Free temporary registers ONLY if they are temps
            for arg_res in arg_results {
                if arg_res.is_temp() {
                    self.registers.free(arg_res.reg());
                }
            }
            self.registers.free(func_reg);

            // Tail call acts as return, but we need to return a register for type checking
            // Use a dummy register (caller won't use it)
            let dummy_reg = self.registers.allocate()?;
            Ok(RegResult::temp(dummy_reg))
        } else {
            // Regular CALL: Allocate result register
            let result_reg = self.registers.allocate()?;

            self.emit(encode_abc(
                OpCode::Call.as_u8(),
                result_reg,
                func_reg,
                args.len() as u8,
            ));

            // Free temporary registers ONLY if they are temps
            for arg_res in arg_results {
                if arg_res.is_temp() {
                    self.registers.free(arg_res.reg());
                }
            }
            self.registers.free(func_reg);

            Ok(RegResult::temp(result_reg))
        }
    }

    /// Compile call expression (arbitrary callee)
    pub(crate) fn compile_call_expression(
        &mut self,
        callee: &AstNode,
        args: &[AstNode],
        is_tail: bool,
    ) -> Result<RegResult, CompileError> {
        // Check if this is a built-in function call FIRST
        // (before trying to compile callee as variable)
        if let AstNode::VariableRef(name) = callee {
            if let Some(builtin_idx) = self.builtins.get_id(name) {
                // This is a built-in function call - use specialized compilation
                return self.compile_builtin_call(builtin_idx, args);
            }
        }

        // Compile the callee expression (can be any expression returning a function)
        let func_res = self.compile_expression(callee)?;
        let mut func_reg = func_res.reg();

        // Check if there's enough space for arguments after func_reg
        // If func_reg + 1 + args.len() > 256, we need to move func_reg to a lower register
        if (func_reg as usize) + 1 + args.len() > 256 {
            let new_func_reg = self.registers.allocate()?;
            self.emit_move(new_func_reg, func_reg);
            if func_res.is_temp() {
                self.registers.free(func_reg);
            }
            func_reg = new_func_reg;
        }

        // Allocate temporary registers for arguments (consecutive)
        let mut arg_results = Vec::new();
        for arg in args {
            let arg_res = self.compile_expression(arg)?;
            arg_results.push(arg_res);
        }

        // Arguments must be in consecutive registers starting from func_reg + 1
        // Move them if necessary BEFORE allocating result register
        // IMPORTANT: Move in reverse order to avoid overwriting source registers
        // that are needed for later moves
        for i in (0..arg_results.len()).rev() {
            let arg_reg = arg_results[i].reg();
            // Calculate target register, checking for overflow
            let target_offset = 1u16 + i as u16;
            let target_calc = func_reg as u16 + target_offset;
            if target_calc > 255 {
                return Err(CompileError::TooManyRegisters);
            }
            let target_reg = target_calc as u8;
            if arg_reg != target_reg {
                self.emit_move(target_reg, arg_reg);
            }
        }

        // Check argument count
        if args.len() > 255 {
            return Err(CompileError::Error("Too many arguments".to_string()));
        }

        // Emit CALL or TAIL_CALL depending on tail position
        if is_tail {
            // TAIL_CALL: Replace current frame with callee
            // TailCall doesn't use a result register - it acts as an implicit return
            self.emit(encode_abc(
                OpCode::TailCall.as_u8(),
                0,  // unused
                func_reg,
                args.len() as u8,
            ));

            // Free temporary registers ONLY if they are temps
            for arg_res in arg_results {
                if arg_res.is_temp() {
                    self.registers.free(arg_res.reg());
                }
            }
            if func_res.is_temp() {
                self.registers.free(func_res.reg());
            }

            // Tail call acts as return, but we need to return a register for type checking
            // Use a dummy register (caller won't use it)
            let dummy_reg = self.registers.allocate()?;
            Ok(RegResult::temp(dummy_reg))
        } else {
            // Regular CALL: Allocate result register
            let result_reg = self.registers.allocate()?;

            self.emit(encode_abc(
                OpCode::Call.as_u8(),
                result_reg,
                func_reg,
                args.len() as u8,
            ));

            // Free temporary registers ONLY if they are temps
            for arg_res in arg_results {
                if arg_res.is_temp() {
                    self.registers.free(arg_res.reg());
                }
            }
            if func_res.is_temp() {
                self.registers.free(func_res.reg());
            }

            Ok(RegResult::temp(result_reg))
        }
    }

    /// Find all variable references in an AST subtree
    pub(crate) fn find_used_variables(&self, node: &AstNode) -> Result<HashSet<String>, CompileError> {
        let mut vars = HashSet::new();
        self.collect_variable_refs(node, &mut vars)?;
        Ok(vars)
    }

    /// Recursively collect variable references
    pub(crate) fn collect_variable_refs(
        &self,
        node: &AstNode,
        vars: &mut HashSet<String>,
    ) -> Result<(), CompileError> {
        match node {
            AstNode::VariableRef(name) => {
                vars.insert(name.clone());
            }
            AstNode::BinaryOp { left, right, .. } => {
                self.collect_variable_refs(left, vars)?;
                self.collect_variable_refs(right, vars)?;
            }
            AstNode::UnaryOp { operand, .. } => {
                self.collect_variable_refs(operand, vars)?;
            }
            AstNode::If {
                condition,
                then_expr,
                else_expr,
            } => {
                self.collect_variable_refs(condition, vars)?;
                self.collect_variable_refs(then_expr, vars)?;
                self.collect_variable_refs(else_expr, vars)?;
            }
            AstNode::WhileLoop { condition, body } => {
                self.collect_variable_refs(condition, vars)?;
                self.collect_variable_refs(body, vars)?;
            }
            AstNode::Lambda { body, .. } => {
                // Don't traverse into nested lambdas
                // They will analyze their own variables
                self.collect_variable_refs(body, vars)?;
            }
            AstNode::Sequence { statements } | AstNode::DoBlock { statements } => {
                for stmt in statements {
                    self.collect_variable_refs(stmt, vars)?;
                }
            }
            AstNode::VariableDecl { initializer, .. }
            | AstNode::MutableDecl { initializer, .. } => {
                self.collect_variable_refs(initializer, vars)?;
            }
            AstNode::Assignment { target, value } => {
                self.collect_variable_refs(target, vars)?;
                self.collect_variable_refs(value, vars)?;
            }
            AstNode::CompoundAssignment { target, value, .. } => {
                self.collect_variable_refs(target, vars)?;
                self.collect_variable_refs(value, vars)?;
            }
            AstNode::FunctionCall { name, args } => {
                vars.insert(name.clone());
                for arg in args {
                    self.collect_variable_refs(arg, vars)?;
                }
            }
            AstNode::CallExpression { callee, args } => {
                self.collect_variable_refs(callee, vars)?;
                for arg in args {
                    self.collect_variable_refs(arg, vars)?;
                }
            }
            AstNode::FieldAccess { record, .. } => {
                self.collect_variable_refs(record, vars)?;
            }
            AstNode::IndexAccess { object, indices } => {
                self.collect_variable_refs(object, vars)?;
                for index_arg in indices {
                    match index_arg {
                        achronyme_parser::ast::IndexArg::Single(node) => {
                            self.collect_variable_refs(node, vars)?;
                        }
                        achronyme_parser::ast::IndexArg::Range { start, end } => {
                            if let Some(start_node) = start {
                                self.collect_variable_refs(start_node, vars)?;
                            }
                            if let Some(end_node) = end {
                                self.collect_variable_refs(end_node, vars)?;
                            }
                        }
                    }
                }
            }
            AstNode::RecordLiteral(fields) => {
                use achronyme_parser::ast::RecordFieldOrSpread;
                for field in fields {
                    match field {
                        RecordFieldOrSpread::Field { value, .. } |
                        RecordFieldOrSpread::MutableField { value, .. } => {
                            self.collect_variable_refs(value, vars)?;
                        }
                        RecordFieldOrSpread::Spread(expr) => {
                            self.collect_variable_refs(expr, vars)?;
                        }
                    }
                }
            }
            AstNode::ArrayLiteral(elements) => {
                use achronyme_parser::ast::ArrayElement;
                for element in elements {
                    match element {
                        ArrayElement::Single(node) => {
                            self.collect_variable_refs(node, vars)?;
                        }
                        ArrayElement::Spread(node) => {
                            self.collect_variable_refs(node, vars)?;
                        }
                    }
                }
            }
            AstNode::Return { value } => {
                self.collect_variable_refs(value, vars)?;
            }
            AstNode::Yield { value } => {
                self.collect_variable_refs(value, vars)?;
            }
            AstNode::TryCatch { try_block, catch_block, .. } => {
                self.collect_variable_refs(try_block, vars)?;
                self.collect_variable_refs(catch_block, vars)?;
            }
            AstNode::Throw { value } => {
                self.collect_variable_refs(value, vars)?;
            }
            AstNode::Match { value, arms } => {
                self.collect_variable_refs(value, vars)?;
                for arm in arms {
                    if let Some(guard) = &arm.guard {
                        self.collect_variable_refs(guard, vars)?;
                    }
                    self.collect_variable_refs(&arm.body, vars)?;
                }
            }
            AstNode::ForInLoop { iterable, body, .. } => {
                self.collect_variable_refs(iterable, vars)?;
                self.collect_variable_refs(body, vars)?;
            }
            AstNode::RangeExpr { start, end, .. } => {
                self.collect_variable_refs(start, vars)?;
                self.collect_variable_refs(end, vars)?;
            }
            AstNode::InterpolatedString { parts } => {
                use achronyme_parser::ast::StringPart;
                for part in parts {
                    match part {
                        StringPart::Literal(_) => {}
                        StringPart::Expression(expr) => {
                            self.collect_variable_refs(expr, vars)?;
                        }
                    }
                }
            }
            AstNode::Break { value } => {
                if let Some(val) = value {
                    self.collect_variable_refs(val, vars)?;
                }
            }
            AstNode::Continue => {}
            AstNode::SelfReference => {
                vars.insert("self".to_string());
            }
            AstNode::GenerateBlock { statements } => {
                for stmt in statements {
                    self.collect_variable_refs(stmt, vars)?;
                }
            }
            AstNode::LetDestructuring { initializer, .. } |
            AstNode::MutableDestructuring { initializer, .. } => {
                self.collect_variable_refs(initializer, vars)?;
            }
            AstNode::ComplexLiteral { .. } => {}
            // Literals don't reference variables
            AstNode::Number(_)
            | AstNode::Boolean(_)
            | AstNode::Null
            | AstNode::StringLiteral(_) => {}
            // Skip other node types
            _ => {}
        }
        Ok(())
    }

    /// Compile built-in function call
    ///
    /// Emits a CallBuiltin opcode with arguments in consecutive registers
    pub(crate) fn compile_builtin_call(
        &mut self,
        builtin_idx: u16,
        args: &[AstNode],
    ) -> Result<RegResult, CompileError> {
        // Allocate consecutive registers: result_reg + arg registers
        // This ensures all needed registers exist in the call frame
        let result_reg = if args.is_empty() {
            // No arguments, just need result register
            self.registers.allocate()?
        } else {
            // Need result + arg count registers
            let base = self.registers.allocate_many(1 + args.len())?;
            base
        };

        // Compile arguments into consecutive registers starting at result_reg + 1
        let mut arg_results = Vec::new();
        for arg in args {
            let arg_res = self.compile_expression(arg)?;
            arg_results.push(arg_res);
        }

        // Move arguments to consecutive registers if needed
        // IMPORTANT: Move in reverse order to avoid overwriting
        for i in (0..arg_results.len()).rev() {
            let arg_reg = arg_results[i].reg();
            let target_reg = result_reg.wrapping_add(1).wrapping_add(i as u8);
            if arg_reg != target_reg {
                self.emit_move(target_reg, arg_reg);
            }
        }

        // Check argument count
        if args.len() > 255 {
            return Err(CompileError::Error("Too many arguments for built-in function".to_string()));
        }

        // Check builtin_idx fits in u8 (we support max 256 built-ins)
        if builtin_idx > 255 {
            return Err(CompileError::Error(
                format!("Built-in function index {} exceeds maximum of 255", builtin_idx)
            ));
        }

        // Emit CallBuiltin opcode using ABC format:
        // A = result_reg (destination)
        // B = argc (argument count)
        // C = builtin_idx (function index, limited to 256)
        self.emit(encode_abc(
            OpCode::CallBuiltin.as_u8(),
            result_reg,
            args.len() as u8,
            builtin_idx as u8,
        ));

        // Free temporary argument registers
        for arg_res in arg_results {
            if arg_res.is_temp() {
                self.registers.free(arg_res.reg());
            }
        }

        Ok(RegResult::temp(result_reg))
    }
}
