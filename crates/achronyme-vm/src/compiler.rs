//! Bytecode compiler (AST to bytecode)

use crate::bytecode::{BytecodeModule, ConstantPool, FunctionPrototype, UpvalueDescriptor};
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use crate::value::Value;
use achronyme_parser::ast::{AstNode, BinaryOp, UnaryOp};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Result of compiling an expression - tracks register ownership
#[derive(Debug, Clone, Copy)]
struct RegResult {
    /// Register index
    index: u8,
    /// True if this is a temporary register that can be freed
    is_temp: bool,
}

impl RegResult {
    /// Create a temporary register result (can be freed)
    fn temp(index: u8) -> Self {
        Self { index, is_temp: true }
    }

    /// Create a variable register result (should not be freed)
    fn var(index: u8) -> Self {
        Self { index, is_temp: false }
    }

    /// Get the register index
    fn reg(&self) -> u8 {
        self.index
    }
}

/// Register allocator for a function
#[derive(Debug)]
struct RegisterAllocator {
    /// Next available register
    next_free: u8,

    /// Maximum registers used
    max_used: u8,

    /// Free list for register reuse
    free_list: Vec<u8>,
}

impl RegisterAllocator {
    fn new() -> Self {
        Self {
            next_free: 0,
            max_used: 0,
            free_list: Vec::new(),
        }
    }

    /// Allocate a new register
    fn allocate(&mut self) -> Result<u8, CompileError> {
        if let Some(reg) = self.free_list.pop() {
            // Make sure we never allocate R255 (reserved for recursion)
            if reg == 255 {
                return Err(CompileError::TooManyRegisters);
            }
            Ok(reg)
        } else if self.next_free < 255 {
            let reg = self.next_free;
            self.next_free += 1;
            self.max_used = self.max_used.max(self.next_free);
            Ok(reg)
        } else {
            Err(CompileError::TooManyRegisters)
        }
    }

    /// Free a register for reuse
    fn free(&mut self, reg: u8) {
        // Never free R255 (reserved for recursion)
        if reg != 255 && !self.free_list.contains(&reg) {
            self.free_list.push(reg);
        }
    }

    /// Get maximum registers used
    fn max_used(&self) -> u8 {
        self.max_used
    }
}

/// Symbol table for variable bindings
#[derive(Debug)]
struct SymbolTable {
    /// Variable name → register mapping
    symbols: HashMap<String, u8>,

    /// Variable name → upvalue index mapping
    upvalues: HashMap<String, u8>,
}

impl SymbolTable {
    fn new() -> Self {
        Self {
            symbols: HashMap::new(),
            upvalues: HashMap::new(),
        }
    }

    /// Define a new variable
    fn define(&mut self, name: String, register: u8) -> Result<(), CompileError> {
        self.symbols.insert(name, register);
        Ok(())
    }

    /// Define an upvalue
    fn define_upvalue(&mut self, name: String, upvalue_idx: u8) -> Result<(), CompileError> {
        self.upvalues.insert(name, upvalue_idx);
        Ok(())
    }

    /// Get register for variable
    fn get(&self, name: &str) -> Result<u8, CompileError> {
        self.symbols
            .get(name)
            .copied()
            .ok_or_else(|| CompileError::UndefinedVariable(name.to_string()))
    }

    /// Get upvalue index for variable
    fn get_upvalue(&self, name: &str) -> Option<u8> {
        self.upvalues.get(name).copied()
    }

    /// Check if variable exists (either local or upvalue)
    fn has(&self, name: &str) -> bool {
        self.symbols.contains_key(name) || self.upvalues.contains_key(name)
    }

    /// Check if a register is used by any variable
    fn has_register(&self, reg: u8) -> bool {
        self.symbols.values().any(|&r| r == reg)
    }
}

/// Loop context for break/continue
#[derive(Debug)]
struct LoopContext {
    /// Start of loop (for continue)
    start: usize,

    /// Break jump targets (to be patched)
    breaks: Vec<usize>,
}

/// Bytecode compiler
pub struct Compiler {
    /// Current function being compiled
    function: FunctionPrototype,

    /// Register allocator
    registers: RegisterAllocator,

    /// Symbol table
    symbols: SymbolTable,

    /// Loop context stack
    loops: Vec<LoopContext>,

    /// Parent compiler (for nested functions)
    parent: Option<Box<Compiler>>,
}

impl Compiler {
    /// Create a new compiler for a module
    pub fn new(module_name: String) -> Self {
        let constants = Rc::new(ConstantPool::new());
        let function = FunctionPrototype::new("<main>".to_string(), constants);

        Self {
            function,
            registers: RegisterAllocator::new(),
            symbols: SymbolTable::new(),
            loops: Vec::new(),
            parent: None,
        }
    }

    /// Compile AST nodes to bytecode module
    pub fn compile(&mut self, nodes: &[AstNode]) -> Result<BytecodeModule, CompileError> {
        // Compile all nodes (usually just one Sequence node)
        let mut last_res: Option<RegResult> = None;
        for node in nodes {
            // Check if it's the last statement that returns a value
            let is_expression = !matches!(
                node,
                AstNode::VariableDecl { .. }
                    | AstNode::MutableDecl { .. }
                    | AstNode::Assignment { .. }
                    | AstNode::Import { .. }
                    | AstNode::Export { .. }
            );

            if is_expression {
                let res = self.compile_expression(node)?;
                last_res = Some(res);
            } else {
                self.compile_statement(node)?;
            }
        }

        // Emit return with last value or null
        if let Some(res) = last_res {
            self.emit(encode_abc(OpCode::Return.as_u8(), res.reg(), 0, 0));
        } else {
            self.emit_return_null();
        }

        // Update register count
        self.function.register_count = self.registers.max_used();

        // Create module
        let module = BytecodeModule {
            name: "<main>".to_string(),
            main: self.function.clone(),
            constants: self.function.constants.clone(),
        };

        Ok(module)
    }

    /// Compile a statement
    fn compile_statement(&mut self, node: &AstNode) -> Result<(), CompileError> {
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
                if value_res.is_temp {
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
                if value_res.is_temp {
                    self.registers.free(value_res.reg());
                }
                Ok(())
            }

            // Expression statement (evaluate and discard result)
            _ => {
                let res = self.compile_expression(node)?;
                // Free ONLY if temporary
                if res.is_temp {
                    self.registers.free(res.reg());
                }
                Ok(())
            }
        }
    }

    /// Compile an expression (returns register holding result)
    fn compile_expression(&mut self, node: &AstNode) -> Result<RegResult, CompileError> {
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

            AstNode::VariableRef(name) => {
                // Check if this is an upvalue first
                if let Some(upvalue_idx) = self.symbols.get_upvalue(name) {
                    // Emit GET_UPVALUE instruction (this creates a copy, so it's temp)
                    let dst = self.registers.allocate()?;
                    self.emit(encode_abc(OpCode::GetUpvalue.as_u8(), dst, upvalue_idx, 0));
                    Ok(RegResult::temp(dst))
                } else {
                    // Regular local variable (not a temp, it's the variable itself)
                    let var_reg = self.symbols.get(name)?;
                    Ok(RegResult::var(var_reg))
                }
            }

            AstNode::BinaryOp { op, left, right } => {
                self.compile_binary_op(op, left, right)
            }

            AstNode::UnaryOp { op, operand } => self.compile_unary_op(op, operand),

            AstNode::If {
                condition,
                then_expr,
                else_expr,
            } => self.compile_if(condition, then_expr, Some(else_expr.as_ref())),

            AstNode::WhileLoop { condition, body } => self.compile_while(condition, body),

            AstNode::Lambda {
                params,
                return_type: _,
                body,
            } => {
                // Create a nested function compiler
                let lambda_name = format!("<lambda@{}>", self.current_position());
                let mut child_compiler = Compiler {
                    function: FunctionPrototype::new(lambda_name, self.function.constants.clone()),
                    registers: RegisterAllocator::new(),
                    symbols: SymbolTable::new(),
                    loops: Vec::new(),
                    parent: None,  // We don't need parent for simple compilation
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

                // Compile lambda body
                let body_res = child_compiler.compile_expression(body)?;
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

            AstNode::Sequence { statements } | AstNode::DoBlock { statements } => {
                let mut last_res: Option<RegResult> = None;
                for stmt in statements {
                    // Check if statement is an expression
                    let is_expression = !matches!(
                        stmt,
                        AstNode::VariableDecl { .. }
                            | AstNode::MutableDecl { .. }
                            | AstNode::Assignment { .. }
                            | AstNode::Import { .. }
                            | AstNode::Export { .. }
                    );

                    if is_expression {
                        if let Some(old_res) = last_res {
                            // Free old result ONLY if temporary
                            if old_res.is_temp {
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

            AstNode::FunctionCall { name, args } => {
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
                    return Err(CompileError::UndefinedVariable(name.clone()));
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

                // Now allocate result register - this must happen AFTER args are positioned
                // to avoid allocating a register that conflicts with argument positions
                let result_reg = self.registers.allocate()?;

                #[cfg(debug_assertions)]
                eprintln!("COMPILE CALL: func_reg={}, argc={}, result_reg={}, args at {:?}",
                          func_reg, args.len(), result_reg,
                          arg_results.iter().map(|r| r.reg()).collect::<Vec<_>>());

                // Emit CALL opcode
                if args.len() > 255 {
                    return Err(CompileError::Error("Too many arguments".to_string()));
                }
                self.emit(encode_abc(
                    OpCode::Call.as_u8(),
                    result_reg,
                    func_reg,
                    args.len() as u8,
                ));

                // Free temporary registers ONLY if they are temps
                for arg_res in arg_results {
                    if arg_res.is_temp {
                        self.registers.free(arg_res.reg());
                    }
                }
                self.registers.free(func_reg);

                Ok(RegResult::temp(result_reg))
            }

            AstNode::CallExpression { callee, args } => {
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

                // Now allocate result register - this must happen AFTER args are positioned
                // to avoid allocating a register that conflicts with argument positions
                let result_reg = self.registers.allocate()?;

                // Emit CALL opcode
                if args.len() > 255 {
                    return Err(CompileError::Error("Too many arguments".to_string()));
                }
                self.emit(encode_abc(
                    OpCode::Call.as_u8(),
                    result_reg,
                    func_reg,
                    args.len() as u8,
                ));

                // Free temporary registers ONLY if they are temps
                for arg_res in arg_results {
                    if arg_res.is_temp {
                        self.registers.free(arg_res.reg());
                    }
                }
                if func_res.is_temp {
                    self.registers.free(func_res.reg());
                }
                // Also free the copied func_reg if we allocated it
                if func_res.reg() == 255 {
                    self.registers.free(func_reg);
                }

                Ok(RegResult::temp(result_reg))
            }

            AstNode::RecReference => {
                // 'rec' refers to the current function being defined
                // Register 255 is reserved for this purpose
                // This is a special variable, not a temp
                Ok(RegResult::var(255))
            }

            _ => Err(CompileError::Error(format!(
                "Expression compilation not yet implemented for {:?}",
                node
            ))),
        }
    }

    /// Compile binary operation
    fn compile_binary_op(
        &mut self,
        op: &BinaryOp,
        left: &AstNode,
        right: &AstNode,
    ) -> Result<RegResult, CompileError> {
        let left_res = self.compile_expression(left)?;
        let right_res = self.compile_expression(right)?;
        let result_reg = self.registers.allocate()?;

        let opcode = match op {
            BinaryOp::Add => OpCode::Add,
            BinaryOp::Subtract => OpCode::Sub,
            BinaryOp::Multiply => OpCode::Mul,
            BinaryOp::Divide => OpCode::Div,
            BinaryOp::Modulo => OpCode::Mod,
            BinaryOp::Power => OpCode::Pow,
            BinaryOp::Eq => OpCode::Eq,
            BinaryOp::Neq => OpCode::Ne,
            BinaryOp::Lt => OpCode::Lt,
            BinaryOp::Lte => OpCode::Le,
            BinaryOp::Gt => OpCode::Gt,
            BinaryOp::Gte => OpCode::Ge,
            BinaryOp::And | BinaryOp::Or => {
                return Err(CompileError::Error(format!(
                    "Binary operation {:?} requires short-circuit evaluation",
                    op
                )))
            }
        };

        self.emit(encode_abc(
            opcode.as_u8(),
            result_reg,
            left_res.reg(),
            right_res.reg(),
        ));

        // Free ONLY if temporary
        if left_res.is_temp {
            self.registers.free(left_res.reg());
        }
        if right_res.is_temp {
            self.registers.free(right_res.reg());
        }

        Ok(RegResult::temp(result_reg))
    }

    /// Compile unary operation
    fn compile_unary_op(
        &mut self,
        op: &UnaryOp,
        operand: &AstNode,
    ) -> Result<RegResult, CompileError> {
        let operand_res = self.compile_expression(operand)?;
        let result_reg = self.registers.allocate()?;

        let opcode = match op {
            UnaryOp::Negate => OpCode::Neg,
            UnaryOp::Not => OpCode::Not,
        };

        self.emit(encode_abc(opcode.as_u8(), result_reg, operand_res.reg(), 0));

        // Free ONLY if temporary
        if operand_res.is_temp {
            self.registers.free(operand_res.reg());
        }

        Ok(RegResult::temp(result_reg))
    }

    /// Compile if expression
    fn compile_if(
        &mut self,
        condition: &AstNode,
        then_expr: &AstNode,
        else_expr: Option<&AstNode>,
    ) -> Result<RegResult, CompileError> {
        // Compile condition
        let cond_res = self.compile_expression(condition)?;

        // Jump to else if false
        let else_jump = self.emit_jump_if_false(cond_res.reg(), 0);

        // Free condition ONLY if temporary
        if cond_res.is_temp {
            self.registers.free(cond_res.reg());
        }

        // Compile then branch
        let then_res = self.compile_expression(then_expr)?;
        let result_reg = self.registers.allocate()?;
        self.emit_move(result_reg, then_res.reg());

        // Free then result ONLY if temporary
        if then_res.is_temp {
            self.registers.free(then_res.reg());
        }

        // Jump over else
        let end_jump = self.emit_jump(0);

        // Patch else jump
        self.patch_jump(else_jump);

        // Compile else branch
        if let Some(else_node) = else_expr {
            let else_res = self.compile_expression(else_node)?;
            self.emit_move(result_reg, else_res.reg());

            // Free else result ONLY if temporary
            if else_res.is_temp {
                self.registers.free(else_res.reg());
            }
        } else {
            // No else branch, result is null
            self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));
        }

        // Patch end jump
        self.patch_jump(end_jump);

        Ok(RegResult::temp(result_reg))
    }

    /// Compile while loop
    fn compile_while(&mut self, condition: &AstNode, body: &AstNode) -> Result<RegResult, CompileError> {
        let loop_start = self.current_position();

        // Compile condition
        let cond_res = self.compile_expression(condition)?;

        // Jump to end if false
        let end_jump = self.emit_jump_if_false(cond_res.reg(), 0);

        // Free condition ONLY if temporary
        if cond_res.is_temp {
            self.registers.free(cond_res.reg());
        }

        // Push loop context
        self.loops.push(LoopContext {
            start: loop_start,
            breaks: Vec::new(),
        });

        // Compile body
        let body_res = self.compile_expression(body)?;

        // Free body ONLY if temporary
        if body_res.is_temp {
            self.registers.free(body_res.reg());
        }

        // Jump back to start
        let offset = -(self.current_position() as i16 - loop_start as i16);
        self.emit_jump(offset);

        // Patch end jump
        self.patch_jump(end_jump);

        // Pop loop context and patch breaks
        let loop_ctx = self.loops.pop().unwrap();
        for break_pos in loop_ctx.breaks {
            self.patch_jump(break_pos);
        }

        // While loop returns null
        let result_reg = self.registers.allocate()?;
        self.emit(encode_abc(OpCode::LoadNull.as_u8(), result_reg, 0, 0));

        Ok(RegResult::temp(result_reg))
    }

    // ===== Helper methods =====

    /// Add constant to pool
    fn add_constant(&mut self, value: Value) -> Result<usize, CompileError> {
        // Try to get mutable access to the constant pool
        if let Some(pool) = Rc::get_mut(&mut self.function.constants) {
            let idx = pool.add_constant(value);

            if idx > u16::MAX as usize {
                return Err(CompileError::TooManyConstants);
            }

            Ok(idx)
        } else {
            // Constant pool is shared, we need to make a copy
            // This can happen with nested lambdas
            let pool_clone = (*self.function.constants).clone();
            self.function.constants = Rc::new(pool_clone);

            // Now we can get mutable access
            let pool = Rc::get_mut(&mut self.function.constants)
                .expect("Just created new Rc, should be unique");

            let idx = pool.add_constant(value);

            if idx > u16::MAX as usize {
                return Err(CompileError::TooManyConstants);
            }

            Ok(idx)
        }
    }

    /// Emit instruction
    fn emit(&mut self, instruction: u32) -> usize {
        self.function.add_instruction(instruction)
    }

    /// Emit LOAD_CONST instruction
    fn emit_load_const(&mut self, dst: u8, const_idx: usize) {
        self.emit(encode_abx(
            OpCode::LoadConst.as_u8(),
            dst,
            const_idx as u16,
        ));
    }

    /// Emit MOVE instruction
    fn emit_move(&mut self, dst: u8, src: u8) {
        self.emit(encode_abc(OpCode::Move.as_u8(), dst, src, 0));
    }

    /// Emit JUMP instruction and return position for patching
    fn emit_jump(&mut self, offset: i16) -> usize {
        self.emit(encode_abx(OpCode::Jump.as_u8(), 0, offset as u16))
    }

    /// Emit JUMP_IF_FALSE instruction
    fn emit_jump_if_false(&mut self, cond_reg: u8, offset: i16) -> usize {
        self.emit(encode_abx(
            OpCode::JumpIfFalse.as_u8(),
            cond_reg,
            offset as u16,
        ))
    }

    /// Emit RETURN_NULL instruction
    fn emit_return_null(&mut self) {
        self.emit(encode_abc(OpCode::ReturnNull.as_u8(), 0, 0, 0));
    }

    /// Get current code position
    fn current_position(&self) -> usize {
        self.function.code.len()
    }

    /// Patch jump instruction at position
    fn patch_jump(&mut self, pos: usize) {
        let offset = self.current_position() as i16 - pos as i16 - 1;
        let instruction = self.function.code[pos];
        let opcode = decode_opcode(instruction);
        let a = decode_a(instruction);

        let patched = encode_abx(opcode, a, offset as u16);
        self.function.patch_instruction(pos, patched);
    }

    /// Find all variable references in an AST subtree
    fn find_used_variables(&self, node: &AstNode) -> Result<HashSet<String>, CompileError> {
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
            // Literals don't reference variables
            AstNode::Number(_)
            | AstNode::Boolean(_)
            | AstNode::Null
            | AstNode::StringLiteral(_) => {}
            // Skip other node types for now
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_allocator() {
        let mut alloc = RegisterAllocator::new();

        let r0 = alloc.allocate().unwrap();
        let r1 = alloc.allocate().unwrap();

        assert_eq!(r0, 0);
        assert_eq!(r1, 1);
        assert_eq!(alloc.max_used(), 2);

        alloc.free(r0);
        let r2 = alloc.allocate().unwrap();
        assert_eq!(r2, 0); // Reused
    }

    #[test]
    fn test_symbol_table() {
        let mut symbols = SymbolTable::new();

        symbols.define("x".to_string(), 5).unwrap();
        symbols.define("y".to_string(), 10).unwrap();

        assert_eq!(symbols.get("x").unwrap(), 5);
        assert_eq!(symbols.get("y").unwrap(), 10);
        assert!(symbols.get("z").is_err());
    }
}
