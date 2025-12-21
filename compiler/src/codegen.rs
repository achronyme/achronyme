use crate::error::CompilerError;
use crate::interner::StringInterner;
use achronyme_parser::{parse_expression, Rule};
use memory::{Value, Complex64};
use pest::iterators::Pair;
use std::collections::HashMap;
use vm::opcode::{
    instruction::{encode_abc, encode_abx},
    OpCode,
};

pub struct Local {
    pub name: String,
    pub depth: u32,
    pub is_captured: bool,
    pub reg: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpvalueInfo {
    pub is_local: bool,
    pub index: u8,
}

#[derive(Debug, Clone)]
pub struct LoopContext {
    pub scope_depth: u32,
    pub start_label: usize,
    pub break_jumps: Vec<usize>,
}

/// State specific to ONE function being compiled
pub struct FunctionCompiler {
    pub name: String,
    pub arity: u8,
    pub locals: Vec<Local>,
    pub scope_depth: u32,
    pub bytecode: Vec<u32>,
    pub constants: Vec<Value>,
    pub upvalues: Vec<UpvalueInfo>,
    pub loop_stack: Vec<LoopContext>,
    
    // Register allocator state
    pub reg_top: u8,
    pub max_slots: u16,
}

impl FunctionCompiler {
    /// Creates a new function compiler. 
    /// CRITICAL: reg_top starts at arity to avoid argument/local collision.
    pub fn new(name: String, arity: u8) -> Self {
        Self {
            name,
            arity,
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
            constants: Vec::new(),
            upvalues: Vec::new(),
            loop_stack: Vec::new(),
            reg_top: arity,        // Reserve R0..R(arity-1) for arguments
            max_slots: arity as u16,
        }
    }
    
    fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        let start = self.reg_top;
        if (start as usize) + (count as usize) > 255 {
             return Err(CompilerError::RegisterOverflow);
        }
        self.reg_top += count;
        
        if (self.reg_top as u16) > self.max_slots {
            self.max_slots = self.reg_top as u16;
        }
        Ok(start)
    }

    fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        let r = self.reg_top;
        if r == 255 {
            return Err(CompilerError::RegisterOverflow);
        }
        self.reg_top += 1;
        
        // Track High Water Mark
        if (self.reg_top as u16) > self.max_slots {
            self.max_slots = self.reg_top as u16;
        }

        Ok(r)
    }

    fn free_reg(&mut self, reg: u8) {
        assert_eq!(
            reg,
            self.reg_top - 1,
            "Register Hygiene Error: Tried to free {} but top is {}",
            reg,
            self.reg_top
        );
        self.reg_top -= 1;
    }


    fn add_constant(&mut self, val: Value) -> usize {
        if let Some(idx) = self.constants.iter().position(|c| c == &val) {
            return idx;
        }
        self.constants.push(val);
        self.constants.len() - 1
    }

    fn add_upvalue(&mut self, is_local: bool, index: u8) -> u8 {
        for (i, upval) in self.upvalues.iter().enumerate() {
            if upval.is_local == is_local && upval.index == index {
                return i as u8;
            }
        }
        self.upvalues.push(UpvalueInfo { is_local, index });
        (self.upvalues.len() - 1) as u8
    }

    fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.bytecode.push(encode_abc(op.as_u8(), a, b, c));
    }

    fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.bytecode.push(encode_abx(op.as_u8(), a, bx));
    }

    fn resolve_local(&self, name: &str) -> Option<(usize, u8)> {
        for (i, local) in self.locals.iter().enumerate().rev() {
            if local.name == name {
                return Some((i, local.reg));
            }
        }
        None
    }
}

/// The main compiler orchestrator
pub struct Compiler {
    pub compilers: Vec<FunctionCompiler>, // LIFO Stack of function compilers
    
    // FLAT list of ALL function prototypes (global indices)
    pub prototypes: Vec<memory::Function>,
    
    // Global Symbol Table (Name -> Index)
    pub global_symbols: HashMap<String, u16>,
    pub next_global_idx: u16,

    // String Interner (shared across all functions)
    pub interner: StringInterner,

    // Complex Number Arena (shared)
    pub complexes: Vec<Complex64>,
}

use vm::specs::{NATIVE_TABLE, USER_GLOBAL_START};

impl Compiler {
    pub fn new() -> Self {
        let mut global_symbols = HashMap::new();

        // Pre-populate Natives from SSOT
        for (index, meta) in NATIVE_TABLE.iter().enumerate() {
            global_symbols.insert(meta.name.to_string(), index as u16);
        }

        let next_global_idx = USER_GLOBAL_START;
        
        // Start with a "main" function compiler (arity=0 for top-level script)
        let main_compiler = FunctionCompiler::new("main".to_string(), 0);

        Self {
            compilers: vec![main_compiler],
            prototypes: Vec::new(),
            global_symbols,
            next_global_idx,
            interner: StringInterner::new(),
            complexes: Vec::new(),
        }
    }
    
    /// Returns a mutable reference to the current (top) function compiler
    fn current(&mut self) -> &mut FunctionCompiler {
        self.compilers.last_mut().expect("Compiler stack underflow")
    }
    
    /// Returns an immutable reference to the current function compiler
    fn current_ref(&self) -> &FunctionCompiler {
        self.compilers.last().expect("Compiler stack underflow")
    }

    pub fn append_debug_symbols(&self, buffer: &mut Vec<u8>) {
        // 1. Invert Name->Index to (Index, Name) for serialization
        let mut symbols: Vec<(&u16, &String)> = self
            .global_symbols
            .iter()
            .map(|(k, v)| (v, k))
            .collect();

        // 2. Sort by Index (Deterministic output is mandatory for build reproducibility)
        symbols.sort_by_key(|&(idx, _)| *idx);

        // 3. Write Section
        buffer.extend_from_slice(&[0xDB, 0x67]); // Magic "DBg"
        buffer.extend_from_slice(&(symbols.len() as u16).to_le_bytes());

        for (index, name) in symbols {
            let name_bytes = name.as_bytes();
            buffer.extend_from_slice(&index.to_le_bytes());
            buffer.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            buffer.extend_from_slice(name_bytes);
        }
    }

    pub fn compile(&mut self, source: &str) -> Result<Vec<u32>, CompilerError> {
        let pairs =
            parse_expression(source).map_err(|e| CompilerError::ParseError(e.to_string()))?;

        for pair in pairs {
            if pair.as_rule() == Rule::EOI {
                continue;
            }
            // Now the top level is (stmt ~ ";"?)*
            // The grammar calls it 'program', but parse_expression likely infers rule from 'Grammar::program'?
            // Wait, parse_expression name is misleading if it parses 'program'.
            // Assuming the trait or helper uses Rule::program as entry.
            // If pair is 'stmt', compile it.
            // If input is "stmt stmt", pest returns multiple pairs if rule is (stmt)*.
            // Let's assume pair is 'stmt'.
            match pair.as_rule() {
                Rule::stmt => self.compile_stmt(pair)?,
                Rule::expr => {
                    // Fallback if grammar allows expr at top (it does via expr_stmt)
                    let reg = self.compile_expr(pair)?;
                    // IMPORTANT: Free the "zombie" register to prevent bloat
                    self.free_reg(reg);
                }
                _ => {
                    // Maybe whitespace or comments if not silent?
                }
            }
        }

        // Final return
        self.emit_abc(OpCode::Return, 0, 0, 0); // Return Nil/0

        Ok(self.current().bytecode.clone())
    }

    fn compile_stmt(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::let_decl => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;

                if self.current().scope_depth > 0 {
                    let depth = self.current().scope_depth;
                    self.current().locals.push(Local {
                        name,
                        depth,
                        is_captured: false,
                        reg: val_reg,
                    });
                } else {
                    if self.next_global_idx == u16::MAX {
                        return Err(CompilerError::TooManyConstants);
                    }
                    let idx = self.next_global_idx;
                    self.next_global_idx += 1;
                    self.global_symbols.insert(name, idx);
                    self.emit_abx(OpCode::DefGlobalLet, val_reg, idx);
                    self.free_reg(val_reg);
                }
            }
            Rule::mut_decl => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;

                if self.current().scope_depth > 0 {
                    let depth = self.current().scope_depth;
                    self.current().locals.push(Local {
                        name,
                        depth,
                        is_captured: false,
                        reg: val_reg,
                    });
                } else {
                    if self.next_global_idx == u16::MAX {
                        return Err(CompilerError::TooManyConstants);
                    }
                    let idx = self.next_global_idx;
                    self.next_global_idx += 1;
                    self.global_symbols.insert(name, idx);
                    self.emit_abx(OpCode::DefGlobalVar, val_reg, idx);
                    self.free_reg(val_reg);
                }

            }
            Rule::assignment => {
                let mut p = inner.into_inner();
                let lhs_pair = p.next().unwrap(); // postfix_expr
                let rhs_pair = p.next().unwrap();

                let mut lhs_inner = lhs_pair.into_inner();
                let atom = lhs_inner.next().unwrap();
                let mut suffixes: Vec<Pair<Rule>> = lhs_inner.collect();

                if suffixes.is_empty() {
                    // Simple Identifier Assignment
                    let atom_inner = atom.into_inner().next().unwrap();
                    if atom_inner.as_rule() != Rule::identifier {
                         return Err(CompilerError::UnexpectedRule("LHS atom must be identifier".into()));
                    }
                    let name = atom_inner.as_str().to_string();

                    let val_reg = self.compile_expr(rhs_pair)?;

                    if let Some(local_reg) = self.resolve_local(&name) {
                         self.emit_abc(OpCode::Move, local_reg, val_reg, 0);
                    } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, &name) {
                         self.emit_abx(OpCode::SetUpvalue, val_reg, upval_idx as u16);
                    } else {
                         let idx = *self.global_symbols.get(&name).ok_or_else(|| {
                              CompilerError::UnknownOperator(format!("Undefined global variable: {}", name))
                         })?;
                         self.emit_abx(OpCode::SetGlobal, val_reg, idx);
                    }
                    self.free_reg(val_reg);
                } else {
                    // Complex Assignment (Index)
                    let last_op = suffixes.pop().unwrap();
                    if last_op.as_rule() != Rule::index_op {
                        return Err(CompilerError::UnexpectedRule("Cannot assign to function call".into()));
                    }

                    // 1. Compile Target
                    let target_reg = self.compile_expr(atom)?;
                    for op in suffixes {
                        self.compile_postfix_op(target_reg, op)?;
                    }

                    // 2. Compile Key
                    let inner_op = last_op.into_inner().next().unwrap();
                    let key_reg = match inner_op.as_rule() {
                        Rule::expr => self.compile_expr(inner_op)?,
                        Rule::identifier => self.compile_dot_key(inner_op.as_str())?,
                         _ => return Err(CompilerError::UnexpectedRule(format!("{:?}", inner_op.as_rule())))
                    };

                    // 3. Compile Value
                    let val_reg = self.compile_expr(rhs_pair)?;

                    // 4. Emit SetIndex
                    self.emit_abc(OpCode::SetIndex, target_reg, key_reg, val_reg);

                    // 5. Hygiene
                    self.free_reg(val_reg);
                    self.free_reg(key_reg);
                    self.free_reg(target_reg);
                }
            }
            Rule::print_stmt => {
                let expr = inner.into_inner().next().unwrap();

                // 1. Prepare Call Frame: Func Reg, Arg Reg
                let func_reg = self.alloc_reg()?;
                let arg_reg = self.alloc_reg()?; // Must be func_reg + 1

                // 2. Load "print" (Pre-defined at index 0)
                let print_idx = *self
                    .global_symbols
                    .get("print")
                    .expect("Natives not initialized");
                self.emit_abx(OpCode::GetGlobal, func_reg, print_idx);

                // 3. Compile Argument
                self.compile_expr_into(expr, arg_reg)?;

                // 4. Call
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1);
                
                // Hygiene: Free args AND func_reg? 
                // Call result replaces func_reg. 
                // arg_reg is func_reg+1.
                // We should free `arg_reg` from compiler tracking perspective.
                self.free_reg(arg_reg);
                self.free_reg(func_reg); // Result is discarded in print_stmt

            }
            Rule::break_stmt => self.compile_break()?,
            Rule::continue_stmt => self.compile_continue()?,
            Rule::return_stmt => {
                // return expr?
                let mut inner_iter = inner.into_inner();
                if let Some(expr) = inner_iter.next() {
                    // Compile expression and return its value
                    let reg = self.compile_expr(expr)?;
                    self.emit_abc(OpCode::Return, reg, 1, 0); // 1 = has value
                } else {
                    // Return nil
                    self.emit_abc(OpCode::Return, 0, 0, 0); // 0 = no value (nil)
                }
            }
            Rule::expr => {
                let reg = self.compile_expr(inner)?;
                // IMPORTANT: Free the "zombie" register to prevent bloat
                self.free_reg(reg);
            }
            _ => {
                return Err(CompilerError::UnexpectedRule(format!(
                    "{:?}",
                    inner.as_rule()
                )))
            }
        }
        Ok(())
    }

    fn compile_expr(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        match pair.as_rule() {
            Rule::expr => self.compile_expr(pair.into_inner().next().unwrap()),
            Rule::cmp_expr => self.compile_comparison(pair),
            Rule::add_expr => self.compile_binary(pair, OpCode::Add, OpCode::Sub, false),
            Rule::mul_expr => self.compile_binary(pair, OpCode::Mul, OpCode::Div, false),
            Rule::pow_expr => self.compile_binary(pair, OpCode::Pow, OpCode::Nop, true),
            Rule::prefix_expr => self.compile_prefix(pair),
            Rule::postfix_expr => self.compile_postfix(pair),
            Rule::for_expr => self.compile_for(pair),
            Rule::forever_expr => self.compile_forever(pair),
            Rule::atom => self.compile_atom(pair),
            _ => {
                let rule = pair.as_rule();
                let mut inner = pair.into_inner();
                if let Some(first) = inner.next() {
                    self.compile_expr(first)
                } else {
                    Err(CompilerError::UnexpectedRule(format!(
                        "Empty rule: {:?}",
                        rule
                    )))
                }
            }
        }
    }

    // Handles logic for add_expr, mul_expr, pow_expr
    fn compile_binary(
        &mut self,
        pair: Pair<Rule>,
        op1: OpCode,
        op2: OpCode,
        is_right_associative: bool,
    ) -> Result<u8, CompilerError> {
        if is_right_associative {
            // Right-associative (e.g., Power: 2^3^2 = 2^(3^2))
            let mut pairs = pair.into_inner();
            let first_pair = pairs.next().unwrap();

            // 1. Collect all operands (registers)
            let mut regs = vec![self.compile_expr(first_pair)?];
            let mut ops = Vec::new();

            // 2. Collect all operators and subsequent operands
            while let Some(op_pair) = pairs.next() {
                let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;

                let opcode = match op_pair.as_str() {
                    "+" | "*" | "^" => op1,
                    "-" | "/" => op2,
                    _ => return Err(CompilerError::UnknownOperator(op_pair.as_str().to_string())),
                };

                ops.push(opcode);
                regs.push(self.compile_expr(right_pair)?);
            }

            // 3. Fold Right-to-Left
            if ops.is_empty() {
                return Ok(regs[0]);
            }

            let mut right_reg = regs.pop().unwrap(); // Start with the last operand

            // Iterate backwards through operators
            while let Some(op) = ops.pop() {
                let left_reg = regs.pop().unwrap();
                // Reuse left_reg as result
                self.emit_abc(op, left_reg, left_reg, right_reg);
                self.free_reg(right_reg); // Hygiene
                right_reg = left_reg; // Result becomes the right operand for the next op
            }

            Ok(right_reg)
        } else {
            // Left-associative (Standard: 1-2-3 = (1-2)-3)
            let mut pairs = pair.into_inner();
            let left_reg = self.compile_expr(pairs.next().unwrap())?;

            while let Some(op_pair) = pairs.next() {
                let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;
                let right_reg = self.compile_expr(right_pair)?;

                let opcode = match op_pair.as_str() {
                    "+" | "*" | "^" => op1,
                    "-" | "/" => op2,
                    _ => return Err(CompilerError::UnknownOperator(op_pair.as_str().to_string())),
                };

                // REUSE left_reg as target (Accumulator pattern)
                self.emit_abc(opcode, left_reg, left_reg, right_reg);
                self.free_reg(right_reg); // Hygiene: Free the right operand (since it was just on top)
            }
            Ok(left_reg)
        }
    }

    // --- Control Flow Helpers ---

    fn emit_jump(&mut self, op: OpCode, a: u8) -> usize {
        self.emit_abx(op, a, 0xFFFF);
        self.current().bytecode.len() - 1
    }

    fn patch_jump(&mut self, idx: usize) {
        let bytecode = &mut self.current().bytecode;
        let jump_target = bytecode.len() as u16;
        let instr = bytecode[idx];
        // Re-encode with new Bx
        let opcode = (instr >> 24) as u8;
        let a = ((instr >> 16) & 0xFF) as u8;
        bytecode[idx] = encode_abx(opcode, a, jump_target);
    }

    fn enter_loop(&mut self, start_label: usize) {
        let depth = self.current().scope_depth;
        self.current().loop_stack.push(LoopContext {
            scope_depth: depth,
            start_label,
            break_jumps: Vec::new(),
        });
    }

    fn exit_loop(&mut self) {
        let loop_ctx = self.current().loop_stack.pop().expect("Loop stack underflow");
        for jump_idx in loop_ctx.break_jumps {
             self.patch_jump(jump_idx);
        }
    }

    fn compile_block(&mut self, pair: Pair<Rule>, target_reg: u8) -> Result<(), CompilerError> {
        let initial_reg_top = self.current().reg_top; // Snapshot
        self.begin_scope();
        let stmts = pair.into_inner();
        let mut last_processed = false;

        // Collect all stmts to handle 'last one' logic
        let stmt_list: Vec<Pair<Rule>> = stmts.collect();
        let len = stmt_list.len();

        for (i, stmt) in stmt_list.into_iter().enumerate() {
            let is_last = i == len - 1;

            if is_last {
                // If specific rules, treat as expr?
                // stmt is { let | mut | assign | print | expr }
                // We peek inside
                let inner = stmt.clone().into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::expr => {
                        // Directly compile into target
                        let _ = self.compile_expr_into(inner, target_reg)?;
                    }
                    _ => {
                        // Statement: compile then load nil
                        self.compile_stmt(stmt)?;
                        self.emit_abx(OpCode::LoadNil, target_reg, 0);
                    }
                }
                last_processed = true;
            } else {
                // Not last, just execute side effects
                self.compile_stmt(stmt)?;
            }
        }

        if !last_processed {
             // Empty block?
             self.emit_abx(OpCode::LoadNil, target_reg, 0);
        }

        self.end_scope();
        self.current().reg_top = initial_reg_top; // Restore (Hygiene)
        Ok(())
    }

    fn compile_if(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // if expr block (else block_or_if)?
        let mut inner = pair.into_inner();
        let cond_expr = inner.next().unwrap();
        let then_block = inner.next().unwrap();
        let else_part = inner.next(); // Optional

        let target_reg = self.alloc_reg()?;

        // 1. Compile Condition
        let cond_reg = self.compile_expr(cond_expr)?;

        // 2. Jump if False -> Else
        let jump_else = self.emit_jump(OpCode::JumpIfFalse, cond_reg);
        self.free_reg(cond_reg); // Hygiene: Condition not needed in body

        // 3. Then Block
        self.compile_block(then_block, target_reg)?;

        // 4. Jump -> End
        let jump_end = self.emit_jump(OpCode::Jump, 0);

        // 5. Else Start
        self.patch_jump(jump_else);

        if let Some(else_pair) = else_part {
             match else_pair.as_rule() {
                 Rule::block => self.compile_block(else_pair, target_reg)?,
                 Rule::if_expr => {
                     // Recurse: write result to target_reg
                     let res = self.compile_if(else_pair)?;
                     self.emit_abc(OpCode::Move, target_reg, res, 0);
                 },
                 _ => return Err(CompilerError::UnexpectedRule(format!("Else: {:?}", else_pair.as_rule())))
             }
        } else {
             // Implicit else -> Nil
             self.emit_abx(OpCode::LoadNil, target_reg, 0);
        }

        // 6. End
        self.patch_jump(jump_end);

        Ok(target_reg)
    }

    fn compile_break(&mut self) -> Result<(), CompilerError> {
        
        let loop_ctx = self.current_ref().loop_stack.last()
            .ok_or(CompilerError::CompileError("break outside of loop".into()))?;
        
        let target_depth = loop_ctx.scope_depth;
        
        // emits OP_CLOSE_UPVALUE for locals that are captured and going out of scope
        // We find the *lowest* register index among variables that need closing.
        // In Lua/Achronyme (assumption), CLOSE(A) closes all upvalues >= R[A].
        
        // Scan locals from current scope down to loop scope
        let mut close_threshold = None;
        
        for (i, local) in self.current().locals.iter().enumerate().rev() {
            if local.depth <= target_depth {
                break; 
            }
            if local.is_captured {
                close_threshold = Some(i as u8);
            }
        }
        
        if let Some(reg) = close_threshold {
            self.emit_abx(OpCode::CloseUpvalue, reg, 0); 
            // Bx usually unused for CloseUpvalue? Or maybe just A?
            // OpCode::CloseUpvalue def: CloseUpvalue = 36.
            // Using implicit encoding.
        }
        
        // Emit Jump (placeholder)
        let jump = self.emit_jump(OpCode::Jump, 0);
        
        // Add to break_jumps
        self.current().loop_stack.last_mut().unwrap().break_jumps.push(jump);
        
        Ok(())
    }

    fn compile_continue(&mut self) -> Result<(), CompilerError> {
        
        let loop_ctx = self.current_ref().loop_stack.last()
            .ok_or(CompilerError::CompileError("continue outside of loop".into()))?;
            
        let target_depth = loop_ctx.scope_depth;
        let start_label = loop_ctx.start_label;
        
        // Hygiene: Close upvalues
        let mut close_threshold = None;
        for (i, local) in self.current().locals.iter().enumerate().rev() {
            if local.depth <= target_depth {
                break;
            }
            if local.is_captured {
                close_threshold = Some(i as u8);
            }
        }
        if let Some(reg) = close_threshold {
            self.emit_abx(OpCode::CloseUpvalue, reg, 0);
        }
        
        // Jump to start
        self.emit_abx(OpCode::Jump, 0, start_label as u16);
        
        Ok(())
    }

    fn compile_for(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // for identifier in expr block
        let mut inner = pair.into_inner();
        let var_name = inner.next().unwrap().as_str().to_string();

        let iterable_expr = inner.next().unwrap();
        let body_block = inner.next().unwrap();

        // 1. Compile Iterable
        let iter_src_reg = self.compile_expr(iterable_expr)?;
        
        // 2. Allocate Iterator Register (holds the iterator STATE) + Value Register
        // We need 2 contiguous registers: R[iter] and R[iter+1] (value)
        let iter_reg = self.alloc_contiguous(2)?;
        let val_reg = iter_reg + 1;
        
        // 3. Emit GetIter R[iter_reg] = Iter(R[iter_src_reg])
        // We use A=iter_reg, B=iter_src_reg
        self.emit_abc(OpCode::GetIter, iter_reg, iter_src_reg, 0); 
                                     // Actually usually GetIter might consume or borrow.
                                     // Let's assume hygiene allows freeing source if GetIter creates a new object
                                     // or moves it.
        
        // 4. Start Label
        let start_label = self.current().bytecode.len();
        self.enter_loop(start_label);
        
        // 5. Emit ForIter
        // R[iter_reg] points to iterator.
        // We need a jump target if finished.
        let jump_exit_idx = self.emit_jump(OpCode::ForIter, iter_reg);
        
        // 6. Extract Value
        // Assumption: ForIter pushed value to R[iter_reg + 1]?
        // Or ForIter *is* the assignment? 
        // Logic: ForIter A, Bx. 
        // If has next: R[A+1] = val. PC++.
        // If done: Jump Bx.
        
        // We need to define the loop variable in the scope.
        // We need to define the loop variable in the scope.
        self.begin_scope();
        
        // Local variable 'var_name' maps to R[iter_reg + 1] (already allocated via alloc_contiguous)
        
        // Register local
        // Register local
        // Register local
        let depth = self.current().scope_depth;
        self.current().locals.push(Local {
            name: var_name,
            depth,
            is_captured: false,
            reg: val_reg,
        });

        // 7. Compile Body (result ignored usually)
        // We pass a dummy target, but careful: compile_block creates its own scope?
        // compile_block logic: "self.begin_scope(); ... self.end_scope();"
        // We already opened a scope for the loop variable, so the body block should probably 
        // be compiled *inside* this scope?
        // compile_block calls begin_scope. So we have:
        // Scope(ForVar) -> Scope(Block).
        // That's fine.
        
        let body_target = self.alloc_reg()?;
        self.compile_block(body_block, body_target)?;
        self.free_reg(body_target);
        
        // 8. Loop Back
        self.emit_abx(OpCode::Jump, 0, start_label as u16);
        
        // 9. Patch Exit
        self.patch_jump(jump_exit_idx);
        
        // 10. Exit Loop Scope
        self.end_scope(); // Pops 'var_name' local
        
        // Hygiene: free val_reg and iter_reg (2 slots)
        self.free_reg(val_reg);
        
        self.exit_loop();

        self.free_reg(iter_reg);
        self.free_reg(iter_src_reg);
        
        // Return Nil
        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);
        Ok(target_reg)
    }

    fn compile_forever(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // forever block
        let block = pair.into_inner().next().unwrap();
        
        let start_label = self.current().bytecode.len();
        self.enter_loop(start_label);
        
        let body_reg = self.alloc_reg()?;
        self.compile_block(block, body_reg)?;
        self.free_reg(body_reg);
        
        self.emit_abx(OpCode::Jump, 0, start_label as u16);
        
        self.exit_loop();
        
        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);
        Ok(target_reg)
    }



    fn compile_while(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // while expr block
        let mut inner = pair.into_inner();
        let cond_expr = inner.next().unwrap();
        let body_block = inner.next().unwrap();

        let start_label = self.current().bytecode.len();

        // 1. Compile Condition
        let cond_reg = self.compile_expr(cond_expr)?;

        // 2. Jump if False -> End
        let jump_end = self.emit_jump(OpCode::JumpIfFalse, cond_reg);
        
        self.free_reg(cond_reg); // Hygiene

        // 3. Body
        
        // Enter Loop context
        self.enter_loop(start_label);
        
        let body_reg = self.alloc_reg()?;
        self.compile_block(body_block, body_reg)?;
        self.free_reg(body_reg); // Hygiene

        // 4. Jump -> Start
        self.emit_abx(OpCode::Jump, 0, start_label as u16);

        // 5. Patch End
        self.patch_jump(jump_end);
        
        // Exit Loop context (backpatch breaks)
        self.exit_loop();

        // 6. Return Nil
        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);

        Ok(target_reg)
    }

    /// Compile function expression: fn name?(params) block
    fn compile_fn_expr(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // ROBUST PARSING: Iterate and match rules, don't assume positions
        let mut name = "lambda".to_string();
        let mut params: Vec<String> = vec![];
        let mut block_pair = None;
        
        for item in pair.into_inner() {
            match item.as_rule() {
                Rule::identifier => name = item.as_str().to_string(),
                Rule::param_list => {
                    params = item.into_inner().map(|id| id.as_str().to_string()).collect();
                }
                Rule::block => block_pair = Some(item),
                _ => {} // Ignore unexpected rules
            }
        }
        
        let block = block_pair.ok_or_else(|| {
            CompilerError::UnexpectedRule("Function must have a block".to_string())
        })?;
        
        let arity = params.len() as u8;
        
        // 2. CRITICAL FIX: Reserve global slot BEFORE compiling body
        //    This enables recursion: fn fib(n) { ... fib(n-1) ... }
        let global_idx = if name != "lambda" {
            if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants);
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;
            self.global_symbols.insert(name.clone(), idx);
            Some(idx)
        } else {
            None
        };
        
        // 3. PUSH: Create new FunctionCompiler for this function
        self.compilers.push(FunctionCompiler::new(name.clone(), arity));
        
        // 4. Register parameters as locals (they're already in R0..R(arity-1))
        for (i, param) in params.iter().enumerate() {
            self.current().locals.push(Local {
                name: param.clone(),
                depth: 0,
                is_captured: false,
                reg: i as u8,
            });
        }
        
        // 5. Compile the block
        let body_reg = self.alloc_reg()?;
        self.compile_block(block, body_reg)?;
        
        // 6. Implicit return (if no explicit return was hit)
        self.emit_abc(OpCode::Return, body_reg, 1, 0);
        
        // 7. POP: Finalize the function
        let mut compiled_func = self.compilers.pop().expect("Compiler stack underflow");
        compiled_func.max_slots = compiled_func.max_slots.max(compiled_func.reg_top as u16);
        
        // 8. Create Function object 
        let func = memory::Function {
            name: compiled_func.name,
            arity: compiled_func.arity,
            max_slots: compiled_func.max_slots,
            chunk: compiled_func.bytecode,

            constants: compiled_func.constants,
            // Convert UpvalueInfo struct to raw bytes [is_local, index, ...]
            upvalue_info: compiled_func.upvalues.iter().flat_map(|u| vec![u.is_local as u8, u.index]).collect(),
        };
        
        // 9. Store function in GLOBAL prototypes list (flat architecture)
        let global_func_idx = self.prototypes.len();
        self.prototypes.push(func);
        
        // 10. Emit Closure instruction with GLOBAL function index
        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::Closure, target_reg, global_func_idx as u16);
        
        // 11. Define global using pre-reserved slot
        if let Some(idx) = global_idx {
            self.emit_abx(OpCode::DefGlobalLet, target_reg, idx);
        }
        
        Ok(target_reg)
    }

    // Specialized compile_expr that targets a register
    fn compile_expr_into(&mut self, pair: Pair<Rule>, target: u8) -> Result<(), CompilerError> {
        let reg = self.compile_expr(pair)?;
        if reg != target {
            self.emit_abc(OpCode::Move, target, reg, 0);
            self.free_reg(reg); // Hygiene: Free the temp register
        }
        Ok(())
    }

    fn compile_comparison(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let mut pairs = pair.into_inner();
        let left_reg = self.compile_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right_pair = pairs.next().ok_or(CompilerError::MissingOperand)?;
            let right_reg = self.compile_expr(right_pair)?;

            let opcode = match op_pair.as_str() {
                "==" => OpCode::Eq,
                "<" => OpCode::Lt,
                ">" => OpCode::Gt,
                _ => return Err(CompilerError::UnknownOperator(op_pair.as_str().to_string())),
            };

            // Reuse left_reg
            self.emit_abc(opcode, left_reg, left_reg, right_reg);
            self.free_reg(right_reg); // Hygiene
        }

        Ok(left_reg)
    }

    fn compile_prefix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // prefix_expr = { unary_op* ~ postfix_expr }
        let mut inner = pair.into_inner();

        // We might have multiple unary ops: - - - 5
        // Or zero.
        // Strategy: Recursively apply? Or strictly unary_op then expr?
        // Grammar: unary_op* ~ postfix_expr
        // Pest iterates them in order.

        // We collect unary ops first
        let mut ops = Vec::new();
        let mut next = inner.next().unwrap();

        while next.as_rule() == Rule::unary_op {
            ops.push(next);
            next = inner.next().unwrap();
        }

        // 'next' is now postfix_expr (the term)
        let reg = self.compile_expr(next)?;

        // Apply ops in reverse (right-to-left associativty essentially for prefixes?
        // Actually - - 5 is -(-5). So inner-most first.
        // But we have the value in 'reg'. We just wrap it.
        // If we have [- , -], we do neg(neg(val)).
        for _op in ops {
            // Check op type if we have more than one (e.g. ! or -)
            // currently only "-"
            self.emit_abc(OpCode::Neg, reg, reg, 0); // In-place Negation
        }

        Ok(reg)
    }

    fn compile_postfix_op(&mut self, reg: u8, op: Pair<Rule>) -> Result<(), CompilerError> {
        match op.as_rule() {
             Rule::call_op => {
                let mut arg_count = 0;
                for arg in op.into_inner() {
                    let _arg_reg = self.compile_expr(arg)?;
                    arg_count += 1;
                }
                if arg_count > 255 { return Err(CompilerError::TooManyConstants); }
                self.emit_abc(OpCode::Call, reg, reg, arg_count as u8);
                for _ in 0..arg_count {
                     let top = self.current().reg_top - 1;
                     self.free_reg(top);
                }
             }
             Rule::index_op => {
                 let inner_op = op.into_inner().next().unwrap();
                 let key_reg = match inner_op.as_rule() {
                      Rule::expr => self.compile_expr(inner_op)?,
                      Rule::identifier => self.compile_dot_key(inner_op.as_str())?,
                       _ => return Err(CompilerError::UnexpectedRule(format!("{:?}", inner_op.as_rule())))
                 };
                 self.emit_abc(OpCode::GetIndex, reg, reg, key_reg);
                 self.free_reg(key_reg);
             }
             _ => return Err(CompilerError::UnexpectedRule(format!("Postfix: {:?}", op.as_rule())))
        }
        Ok(())
    }

    fn compile_postfix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // postfix_expr = { atom ~ (postfix_op)* }
        let mut inner = pair.into_inner();
        let atom_pair = inner.next().unwrap();
        let reg = self.compile_expr(atom_pair)?; // Compile the atom

        // Handle suffixes (calls, index)
        while let Some(op) = inner.next() {
            self.compile_postfix_op(reg, op)?;
        }

        Ok(reg)
    }

    fn compile_atom(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::number => self.compile_number(inner),
            Rule::string => self.compile_string(inner),
            Rule::complex => self.compile_complex(inner),
            Rule::true_lit => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadTrue, reg, 0);
                Ok(reg)
            }
            Rule::false_lit => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadFalse, reg, 0);
                Ok(reg)
            }
            Rule::nil_lit => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadNil, reg, 0);
                Ok(reg)
            }
            Rule::list_literal => self.compile_list(inner),
            Rule::map_literal => self.compile_map(inner),
            Rule::block => {
                let reg = self.alloc_reg()?;
                self.compile_block(inner, reg)?;
                Ok(reg)
            }
            Rule::if_expr => self.compile_if(inner),
            Rule::while_expr => self.compile_while(inner),
            Rule::fn_expr => self.compile_fn_expr(inner),
            Rule::for_expr => self.compile_for(inner),
            Rule::forever_expr => self.compile_forever(inner),
            Rule::identifier => {
                let name = inner.as_str().to_string();
                let reg = self.alloc_reg()?;

                // 1. First check locals (including function parameters)
                if let Some(local_reg) = self.resolve_local(&name) {
                    // Local variable - just MOVE from its register
                    self.emit_abc(OpCode::Move, reg, local_reg, 0);

                    Ok(reg)
                } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, &name) {
                    // 2. Upvalue lookup
                    self.emit_abx(OpCode::GetUpvalue, reg, upval_idx as u16);
                    Ok(reg)
                } else {
                    // 3. Fall back to global lookup
                    let idx = *self.global_symbols.get(&name).ok_or_else(|| {
                        CompilerError::UnknownOperator(format!("Undefined variable: {}", name))
                    })?;

                    // GetGlobal R[reg], Slot[idx]
                    self.emit_abx(OpCode::GetGlobal, reg, idx);
                    Ok(reg)
                }
            }
            Rule::expr => self.compile_expr(inner),
            _ => Err(CompilerError::UnexpectedRule(format!(
                "{:?}",
                inner.as_rule()
            ))),
        }
    }

    fn compile_list(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let inside = pair.into_inner();
        let target_reg = self.alloc_reg()?;

        let mut count = 0;
        let start_reg = self.current().reg_top;

        for expr in inside {
            let reg = self.compile_expr(expr)?;
            // Verify contiguity (sanity check)
            if reg != start_reg + count {
                return Err(CompilerError::CompilerLimitation("Register allocation fragmentation in list literal".into()));
            }
            count += 1;
        }
        
        if count > 255 {
            return Err(CompilerError::TooManyConstants); // Reuse for size limit
        }

        // R[A] = List(R[B]...R[B+C-1])
        // If count == 0, B is irrelevant, we pass 0
        self.emit_abc(OpCode::BuildList, target_reg, start_reg, count);

        // Cleanup: Free all element registers
        for _ in 0..count {
            let top = self.current().reg_top - 1;
            self.free_reg(top);
        }

        Ok(target_reg)
    }

    fn compile_map(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let inside = pair.into_inner(); // map_pairs
        
        // 1. Collect pairs to count them and pre-allocate registers
        let pairs: Vec<_> = inside.collect();
        let count = pairs.len();
        
        if count > 127 { // 255 / 2 approx
             return Err(CompilerError::TooManyConstants); // Reuse error
        }

        let target_reg = self.alloc_reg()?;
        
        // 2. Allocate contiguous block for keys and values (2 * count)
        // If count is 0, we simply build map from start_reg (which will be target_reg+1 effectively, but size 0)
        let start_reg = if count > 0 {
             self.alloc_contiguous((count * 2) as u8)?
        } else {
             self.current().reg_top 
        };

        for (i, map_pair) in pairs.into_iter().enumerate() {
            let mut pair_inner = map_pair.into_inner();
            let key_node = pair_inner.next().unwrap();
            let value_node = pair_inner.next().unwrap();
            
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            // 1. Compile Key (Must be String)
            let raw_s = key_node.as_str();
            let key_slice = match key_node.as_rule() {
                Rule::identifier => raw_s,
                Rule::string => &raw_s[1..raw_s.len()-1], // Strip quotes
                _ => return Err(CompilerError::UnexpectedRule("Map key must be identifier or string".into()))
            };

            // Intern and LoadConst
            let key_handle = self.intern_string(key_slice);
            let key_val = Value::string(key_handle);
            let const_idx = self.add_constant(key_val);

            if const_idx > 0xFFFF { return Err(CompilerError::TooManyConstants); }
            self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16);

            // 2. Compile Value
            self.compile_expr_into(value_node, val_reg)?;
        }

        self.emit_abc(OpCode::BuildMap, target_reg, start_reg, count as u8);

        // Cleanup: Free 2*count regs
        if count > 0 {
             // We need to free backwards
             // Top is start_reg + 2*count
             for _ in 0..(count * 2) {
                 let top = self.current().reg_top - 1;
                 self.free_reg(top);
             }
        }

        Ok(target_reg)
    }

    fn compile_number(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let s = pair.as_str();
        let val = s.parse::<f64>().map_err(|_| CompilerError::InvalidNumber)?;

        let reg = self.alloc_reg()?;
        let const_idx = self.add_constant(Value::number(val));

        if const_idx <= 0xFFFF {
            self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        } else {
            return Err(CompilerError::TooManyConstants);
        }

        Ok(reg)
    }

    fn compile_complex(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let s = pair.as_str();
        let num_str = &s[..s.len() - 1]; // Remove 'i'
        let val = num_str
            .parse::<f64>()
            .map_err(|_| CompilerError::InvalidComplex)?;

        // Construct the complex number (0 + val*i)
        let c = Complex64::new(0.0, val);
        
        // Deduplicate/Intern in the compiler's list
        let complex_handle = if let Some(idx) = self.complexes.iter().position(|&existing| existing == c) {
            idx as u32
        } else {
            let idx = self.complexes.len() as u32;
            self.complexes.push(c);
            idx
        };

        let val = Value::complex(complex_handle);
        let const_idx = self.add_constant(val);

        let reg = self.alloc_reg()?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants);
        }
        self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);

        Ok(reg)
    }

    fn compile_string(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let raw = pair.as_str(); 
        // grammar: string = ${ "\"" ~ inner ~ "\"" }
        // The raw string includes the surrounding quotes
        let inner_content = &raw[1..raw.len() - 1]; 
        
        let processed = Self::unescape_string(inner_content);
        
        let handle = self.intern_string(&processed);
        // Value::string creates a tagged value with payload = handle
        let val = Value::string(handle);
        let const_idx = self.add_constant(val);
        
        let reg = self.alloc_reg()?;
        if const_idx <= 0xFFFF {
            self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        } else {
            return Err(CompilerError::TooManyConstants);
        }
        
        Ok(reg)
    }


    fn unescape_string(raw: &str) -> String {
        let mut result = String::with_capacity(raw.len());
        let mut chars = raw.chars();

        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    // If we find an unknown escape (e.g., \a), 
                    // we treat it as literal or ignore it. 
                    // Safe standard: keep the backslash.
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => {
                        // Backslash at the end of string with nothing else (rare checking grammar)
                        result.push('\\');
                    }
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    fn compile_dot_key(&mut self, name: &str) -> Result<u8, CompilerError> {
        let handle = self.intern_string(name);
        let val = Value::string(handle);
        let const_idx = self.add_constant(val);
        let r = self.alloc_reg()?;
        if const_idx > 0xFFFF { 
            return Err(CompilerError::TooManyConstants); 
        }
        self.emit_abx(OpCode::LoadConst, r, const_idx as u16);
        Ok(r)
    }

    // --- Helpers (Delegate to Current FunctionCompiler) ---

    fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        self.current().alloc_reg()
    }

    fn alloc_contiguous(&mut self, count: u8) -> Result<u8, CompilerError> {
        self.current().alloc_contiguous(count)
    }

    fn free_reg(&mut self, reg: u8) {
        self.current().free_reg(reg)
    }

    fn add_constant(&mut self, val: Value) -> usize {
        self.current().add_constant(val)
    }

    fn intern_string(&mut self, s: &str) -> u32 {
        self.interner.intern(s)
    }

    fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.current().emit_abc(op, a, b, c)
    }

    fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.current().emit_abx(op, a, bx)
    }
    
    /// Resolve a local variable by name. Returns Some(register_index) if found, None otherwise.
    fn resolve_local(&self, name: &str) -> Option<u8> {
        self.current_ref().resolve_local(name).map(|(_, r)| r)
    }

    fn resolve_upvalue(&mut self, compiler_idx: usize, name: &str) -> Option<u8> {
        if compiler_idx == 0 {
            return None;
        }

        let parent_idx = compiler_idx - 1;

        // 1. Resolve in Parent Local
        // Use a block to limit borrow scope
        let local_res = self.compilers[parent_idx].resolve_local(name);
        
        if let Some((idx, reg)) = local_res {
            // Mark captured
            self.compilers[parent_idx].locals[idx].is_captured = true;
            return Some(self.compilers[compiler_idx].add_upvalue(true, reg));
        }

        // 2. Resolve in Parent Upvalue (Recursive)
        if let Some(upval_idx) = self.resolve_upvalue(parent_idx, name) {
            return Some(self.compilers[compiler_idx].add_upvalue(false, upval_idx));
        }

        None
    }
    
    // --- Scope Helpers (Delegate) ---
    
    fn begin_scope(&mut self) {
        self.current().scope_depth += 1;
    }

    fn end_scope(&mut self) {
        let func = self.current();
        func.scope_depth -= 1;
        let current_depth = func.scope_depth;

        while let Some(local) = func.locals.last() {
            if local.depth > current_depth {
                func.locals.pop();
            } else {
                break;
            }
        }
    }
}
