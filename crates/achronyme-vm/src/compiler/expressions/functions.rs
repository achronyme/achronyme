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
            function: FunctionPrototype::new(lambda_name, self.function.constants.clone()),
            registers: RegisterAllocator::new(),
            symbols: SymbolTable::new(),
            loops: Vec::new(),
            parent: None,  // We don't need parent for simple compilation
            builtins: self.builtins.clone(),  // Share the built-ins registry
            type_registry: self.type_registry.clone(),  // Share the type registry
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

        // Analyze upvalues by finding variables used but not defined in lambda
        let used_vars = self.find_used_variables(body)?;
        let mut upvalues = Vec::new();

        for var in used_vars {
            if !child_compiler.symbols.has(&var) {
                // This variable is captured from parent scope
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

        // Set register count (need to allocate enough for rec register 255)
        // Since we use register 255 for recursion, we need at least 256 registers (0-255)
        // But register_count is u8, so the max is 255, meaning 0-254
        // We'll use a workaround: always allocate all 256 registers for functions
        child_compiler.function.register_count = 255;

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
        let func_reg = if name == "rec" {
            // Special case: 'rec' refers to register 255 (current function for recursion)
            let func_reg = self.registers.allocate()?;
            self.emit_move(func_reg, 255);
            func_reg
        } else if let Ok(source_reg) = self.symbols.get(name) {
            let func_reg = self.registers.allocate()?;
            self.emit_move(func_reg, source_reg);
            func_reg
        } else if let Some(upvalue_idx) = self.symbols.get_upvalue(name) {
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
            // Use wrapping arithmetic to handle func_reg + 1 + i safely
            let target_reg = func_reg.wrapping_add(1).wrapping_add(i as u8);
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

        // CRITICAL FIX: R255 is reserved for recursion and cannot be used as func_reg
        // in CALL instructions because arguments would wrap to R0, overwriting parameters.
        // Always copy the function value to a fresh register before calling.
        let func_reg = if func_res.reg() == 255 {
            let reg = self.registers.allocate()?;
            self.emit_move(reg, 255);
            reg
        } else {
            func_res.reg()
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
            // Use wrapping arithmetic to handle func_reg + 1 + i safely
            let target_reg = func_reg.wrapping_add(1).wrapping_add(i as u8);
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
            // Also free the copied func_reg if we allocated it
            if func_res.reg() == 255 {
                self.registers.free(func_reg);
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
            // Also free the copied func_reg if we allocated it
            if func_res.reg() == 255 {
                self.registers.free(func_reg);
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
    fn collect_variable_refs(
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
