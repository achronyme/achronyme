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

    // Simple register allocator state
    reg_top: u8,

    // String Interner
    pub interner: StringInterner,
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
            constants: Vec::new(),
            reg_top: 0,
            interner: StringInterner::new(),
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

                let handle = self.intern_string(&name);
                let name_idx = self.add_constant(Value::string(handle));

                // DefGlobalLet R[val_reg], Name[name_idx]
                self.emit_abx(OpCode::DefGlobalLet, val_reg, name_idx as u16);
            }
            Rule::mut_decl => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;
                let handle = self.intern_string(&name);
                let name_idx = self.add_constant(Value::string(handle));

                // DefGlobalVar
                self.emit_abx(OpCode::DefGlobalVar, val_reg, name_idx as u16);
            }
            Rule::assignment => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();

                let val_reg = self.compile_expr(expr)?;
                let handle = self.intern_string(&name);
                let name_idx = self.add_constant(Value::string(handle));

                // SetGlobal
                self.emit_abx(OpCode::SetGlobal, val_reg, name_idx as u16);
            }
            Rule::print_stmt => {
                let expr = inner.into_inner().next().unwrap();

                // 1. Prepare Call Frame: Func Reg, Arg Reg
                let func_reg = self.alloc_reg()?;
                let arg_reg = self.alloc_reg()?; // Must be func_reg + 1

                // 2. Load "print"
                let handle = self.intern_string("print");
                let name_idx = self.add_constant(Value::string(handle));
                self.emit_abx(OpCode::GetGlobal, func_reg, name_idx as u16);

                // 3. Compile Argument
                let expr_reg = self.compile_expr(expr)?;

                // 4. Move result to Arg position
                self.emit_abc(OpCode::Move, arg_reg, expr_reg, 0);

                // 5. Call
                // Call(Dest=func_reg, Func=func_reg, ArgCount=1)
                // Args start at B+1 (arg_reg)
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1);
            }
            Rule::expr_stmt => {
                let expr = inner.into_inner().next().unwrap();
                let _ = self.compile_expr(expr)?;
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
            Rule::add_expr => self.compile_binary(pair, OpCode::Add, OpCode::Sub),
            Rule::mul_expr => self.compile_binary(pair, OpCode::Mul, OpCode::Div),
            Rule::pow_expr => self.compile_binary(pair, OpCode::Pow, OpCode::Nop),
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
    ) -> Result<u8, CompilerError> {
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

            let res_reg = self.alloc_reg()?;
            self.emit_abc(opcode, res_reg, left_reg, right_reg);
            left_reg = res_reg;
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
        let mut reg = self.compile_expr(next)?;

        // Apply ops in reverse (right-to-left associativty essentially for prefixes?
        // Actually - - 5 is -(-5). So inner-most first.
        // But we have the value in 'reg'. We just wrap it.
        // If we have [- , -], we do neg(neg(val)).
        for _op in ops {
            // Check op type if we have more than one (e.g. !)
            // currently only "-"
            let new_reg = self.alloc_reg()?;
            self.emit_abc(OpCode::Neg, new_reg, reg, 0); // Neg uses B reg
            reg = new_reg;
        }

        Ok(reg)
    }

    fn compile_postfix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // postfix_expr = { atom ~ (postfix_op)* }
        let mut inner = pair.into_inner();
        let atom_pair = inner.next().unwrap();
        let mut reg = self.compile_expr(atom_pair)?; // Compile the atom

        // Handle suffixes (calls, index)
        // Handle suffixes (calls, index)
        if let Some(op) = inner.next() {
            match op.as_rule() {
                // Rule::call_op => { ... }
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
            Rule::identifier => {
                let name = inner.as_str().to_string();
                let reg = self.alloc_reg()?;
                let handle = self.intern_string(&name);
                let name_idx = self.add_constant(Value::string(handle));
                self.emit_abx(OpCode::GetGlobal, reg, name_idx as u16);
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
