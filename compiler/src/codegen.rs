use crate::error::CompilerError;
use crate::interner::StringInterner;
use achronyme_parser::{parse_expression, Rule};
use memory::Value;
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
}

pub struct Compiler {
    pub locals: Vec<Local>,
    pub scope_depth: u32,
    pub bytecode: Vec<u32>, // Using u32 for 4-byte instructions
    pub constants: Vec<Value>,

    // Global Symbol Table (Name -> Index)
    pub global_symbols: HashMap<String, u16>,
    pub next_global_idx: u16,

    // Simple register allocator state
    pub reg_top: u8,

    // String Interner
    pub interner: StringInterner,
}

use vm::specs::{NATIVE_TABLE, USER_GLOBAL_START};

impl Compiler {
    pub fn new() -> Self {
        let mut global_symbols = HashMap::new();

        // Phase 1: Pre-populate Natives (Must align with VM)
        // Dynamic Population from SSOT
        for (index, meta) in NATIVE_TABLE.iter().enumerate() {
            global_symbols.insert(meta.name.to_string(), index as u16);
        }

        let next_global_idx = USER_GLOBAL_START; // Start user globals after natives

        Self {
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
            constants: Vec::new(),
            global_symbols,
            next_global_idx,
            reg_top: 0,
            interner: StringInterner::new(),
        }
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
                    // Implicit print/return? No, statement does 'Print'.
                    // For pure expr stmt, we discard result unless REPL.
                    // But simpler: just compile it.
                }
                _ => {
                    // Maybe whitespace or comments if not silent?
                }
            }
        }

        // Final return
        self.emit_abc(OpCode::Return, 0, 0, 0); // Return Nil/0

        Ok(self.bytecode.clone())
    }

    fn compile_stmt(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::let_decl => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;

                // Allocate slot or use existing?
                // For now: Always allocate new slot.
                // Note: This simple approach leaks slots if you re-declare 'x' in REPL
                // but keeps implementation simple for O(1).

                if self.next_global_idx == u16::MAX {
                    return Err(CompilerError::TooManyConstants); // Reuse error or make new one
                }

                let idx = self.next_global_idx;
                self.next_global_idx += 1;
                self.global_symbols.insert(name, idx);

                // DefGlobalLet R[val_reg], Slot[idx]
                // Bx is now raw index, NOT constant pool index
                self.emit_abx(OpCode::DefGlobalLet, val_reg, idx);
                self.free_reg(val_reg); // Statement consumes
            }
            Rule::mut_decl => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;

                if self.next_global_idx == u16::MAX {
                    return Err(CompilerError::TooManyConstants);
                }

                let idx = self.next_global_idx;
                self.next_global_idx += 1;
                self.global_symbols.insert(name, idx);

                // DefGlobalVar
                self.emit_abx(OpCode::DefGlobalVar, val_reg, idx);
                self.free_reg(val_reg); // Statement consumes the reg

            }
            Rule::assignment => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;

                // Lookup global index
                let idx = *self.global_symbols.get(&name).ok_or_else(|| {
                    // This is now a COMPILER ERROR, not runtime!
                    CompilerError::UnknownOperator(format!("Undefined global variable: {}", name))
                })?;

                // SetGlobal
                self.emit_abx(OpCode::SetGlobal, val_reg, idx);
                self.free_reg(val_reg); // Statement consumes
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
            Rule::print_stmt => {
                let expr = inner.into_inner().next().unwrap();
                let _ = self.compile_expr(expr)?;
                // Print in stdlib usually? 
                // Ah, previous implementation emited Call "print". 
                // Keep it consistent.
            }
            // Rule::expr_stmt => ... removed
            Rule::expr => {
                 let _ = self.compile_expr(inner)?;
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
            let mut left_reg = self.compile_expr(pairs.next().unwrap())?;

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

    fn begin_scope(&mut self) {
        self.scope_depth += 1;
    }

    fn end_scope(&mut self) {
        self.scope_depth -= 1;
        // Simple pop locals (future: reuse regs)
        // self.locals.retain(|l| l.depth <= self.scope_depth);
    }

    fn emit_jump(&mut self, op: OpCode, a: u8) -> usize {
        self.emit_abx(op, a, 0xFFFF);
        self.bytecode.len() - 1
    }

    fn patch_jump(&mut self, idx: usize) {
        let jump_target = self.bytecode.len() as u16;
        let instr = self.bytecode[idx];
        // Re-encode with new Bx
        let opcode = (instr >> 24) as u8;
        let a = ((instr >> 16) & 0xFF) as u8;
        self.bytecode[idx] = encode_abx(opcode, a, jump_target);
    }

    fn compile_block(&mut self, pair: Pair<Rule>, target_reg: u8) -> Result<(), CompilerError> {
        let initial_reg_top = self.reg_top; // Snapshot
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
        self.reg_top = initial_reg_top; // Restore (Hygiene)
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
             // else_pair rule is implicit in grammar?
             // ("else" ~ (block | if_expr))?
             // Pest often flattens this if not atomic?
             // inner.next() gave the block or if_expr directly?
             // Let's check logic.
             // If implicit: `else_part` is the block or if_expr.
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

    fn compile_while(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // while expr block
        let mut inner = pair.into_inner();
        let cond_expr = inner.next().unwrap();
        let body_block = inner.next().unwrap();

        let start_label = self.bytecode.len();

        // 1. Compile Condition
        let cond_reg = self.compile_expr(cond_expr)?;

        // 2. Jump if False -> End
        let jump_end = self.emit_jump(OpCode::JumpIfFalse, cond_reg);
        
        self.free_reg(cond_reg); // Hygiene

        // 3. Body
        // While loops technically return Nil usually? Or last value?
        // Common pattern: return Nil.
        // We allocate a dummy register for body result (discarded for now)
        let body_reg = self.alloc_reg()?;
        self.compile_block(body_block, body_reg)?;
        self.free_reg(body_reg); // Hygiene

        // 4. Jump -> Start
        let jump_idx = self.bytecode.len() as u16;
        self.emit_abx(OpCode::Jump, 0, start_label as u16);

        // 5. Patch End
        self.patch_jump(jump_end);

        // 6. Return Nil
        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);

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
        let mut left_reg = self.compile_expr(pairs.next().unwrap())?;

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

    fn compile_postfix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // postfix_expr = { atom ~ (postfix_op)* }
        let mut inner = pair.into_inner();
        let atom_pair = inner.next().unwrap();
        let mut reg = self.compile_expr(atom_pair)?; // Compile the atom

        // Handle suffixes (calls, index)
        // Handle suffixes (calls)
        // Note: Grammar defines `postfix_op*`, so we iterate
        while let Some(op) = inner.next() {
            match op.as_rule() {
                Rule::call_op => {
                    let mut arg_count = 0;
                    for arg in op.into_inner() {
                        // Compile argument, it lands in the next register (reg + 1 + i)
                        let _arg_reg = self.compile_expr(arg)?;
                        arg_count += 1;
                    }

                    if arg_count > 255 {
                        return Err(CompilerError::TooManyConstants); // Limitation of ABC format
                    }

                    // Call R[reg], ReturnTo R[reg], ArgCount
                    self.emit_abc(OpCode::Call, reg, reg, arg_count as u8);

                    // Hygiene: Free arguments (Stack LIFO)
                    // We allocated `arg_count` registers on top of `reg`.
                    for _ in 0..arg_count {
                         // Verify we are freeing the top
                         self.free_reg(self.reg_top - 1);
                    }
                }
                _ => {
                    return Err(CompilerError::UnexpectedRule(format!(
                        "Postfix: {:?}",
                        op.as_rule()
                    )))
                }
            }
        }

        Ok(reg)
    }

    fn compile_atom(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::number => self.compile_number(inner),
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
            Rule::block => {
                let reg = self.alloc_reg()?;
                self.compile_block(inner, reg)?;
                Ok(reg)
            }
            Rule::if_expr => self.compile_if(inner),
            Rule::while_expr => self.compile_while(inner),
            Rule::identifier => {
                let name = inner.as_str().to_string();
                let reg = self.alloc_reg()?;

                // Lookup global index
                let idx = *self.global_symbols.get(&name).ok_or_else(|| {
                    CompilerError::UnknownOperator(format!("Undefined global variable: {}", name))
                })?;

                // GetGlobal R[reg], Slot[idx]
                self.emit_abx(OpCode::GetGlobal, reg, idx);
                Ok(reg)
            }
            Rule::expr => self.compile_expr(inner),
            _ => Err(CompilerError::UnexpectedRule(format!(
                "{:?}",
                inner.as_rule()
            ))),
        }
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

        let reg = self.alloc_reg()?;
        let zero_reg = self.alloc_reg()?;
        let val_reg = self.alloc_reg()?;

        let z_idx = self.add_constant(Value::number(0.0));
        self.emit_abx(OpCode::LoadConst, zero_reg, z_idx as u16);

        let v_idx = self.add_constant(Value::number(val));
        self.emit_abx(OpCode::LoadConst, val_reg, v_idx as u16);

        self.emit_abc(OpCode::NewComplex, reg, zero_reg, val_reg);
        
        // Hygiene
        self.free_reg(val_reg);
        self.free_reg(zero_reg);

        Ok(reg)
    }

    // --- Helpers ---

    fn alloc_reg(&mut self) -> Result<u8, CompilerError> {
        let r = self.reg_top;
        if r == 255 {
            return Err(CompilerError::RegisterOverflow);
        }
        self.reg_top += 1;
        Ok(r)
    }

    fn free_reg(&mut self, reg: u8) {
        // Register Hygiene: Ensure we are freeing the most recently allocated register.
        assert_eq!(
            reg,
            self.reg_top - 1,
            "Register Hygiene Error: Tried to free {} but top is {}",
            reg,
            self.reg_top
        );
        self.reg_top -= 1;
    }

    // Rudimentary reset for expression boundaries needed usually

    fn add_constant(&mut self, val: Value) -> usize {
        if let Some(idx) = self.constants.iter().position(|c| c == &val) {
            return idx;
        }

        // Add new constant
        self.constants.push(val);
        self.constants.len() - 1
    }

    fn intern_string(&mut self, s: &str) -> u32 {
        self.interner.intern(s)
    }

    fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.bytecode.push(encode_abc(op.as_u8(), a, b, c));
    }

    fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.bytecode.push(encode_abx(op.as_u8(), a, bx));
    }
}
