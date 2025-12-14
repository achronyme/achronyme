use crate::error::CompilerError;
use memory::Value;
use achronyme_parser::{parse_expression, Rule};
use vm::opcode::{OpCode, instruction::{encode_abc, encode_abx}};
use pest::iterators::Pair;
use std::collections::HashMap;

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

    // String Internet
    // Maps "string" -> u32 (handle)
    // The real strings are stored in the heap, but for now
    // we save them here to pass them to the VM
    pub strings: Vec<String>,   // String arena
    string_cache: HashMap<String, u32>, // Cache for duplicate strings
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
            constants: Vec::new(),
            reg_top: 0,
            strings: Vec::new(),
            string_cache: HashMap::new(),
        }
    }
    
    pub fn compile(&mut self, source: &str) -> Result<Vec<u32>, CompilerError> {
        let pairs = parse_expression(source).map_err(|e| CompilerError::ParseError(e.to_string()))?;
        
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
                 Rule::expr => { // Fallback if grammar allows expr at top (it does via expr_stmt)
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
            },
            Rule::mut_decl => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();
                
                let val_reg = self.compile_expr(expr)?;
                let handle = self.intern_string(&name);
                let name_idx = self.add_constant(Value::string(handle));
                
                // DefGlobalVar
                self.emit_abx(OpCode::DefGlobalVar, val_reg, name_idx as u16);
            },
            Rule::assignment => {
                let mut p = inner.into_inner();
                let name = p.next().unwrap().as_str().to_string();
                let expr = p.next().unwrap();
                
                let val_reg = self.compile_expr(expr)?;
                let handle = self.intern_string(&name);
                let name_idx = self.add_constant(Value::string(handle));
                
                // SetGlobal
                self.emit_abx(OpCode::SetGlobal, val_reg, name_idx as u16);
            },
            Rule::print_stmt => {
                 let expr = inner.into_inner().next().unwrap();
                 let val_reg = self.compile_expr(expr)?;
                 // Print
                 self.emit_abc(OpCode::Print, val_reg, 0, 0);
            },
            Rule::expr_stmt => {
                 let expr = inner.into_inner().next().unwrap();
                 let _ = self.compile_expr(expr)?;
            },
            _ => return Err(CompilerError::UnexpectedRule(format!("{:?}", inner.as_rule()))),
        }
        Ok(())
    }

    fn compile_expr(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        match pair.as_rule() {
            Rule::expr => self.compile_expr(pair.into_inner().next().unwrap()),
            Rule::additive => self.compile_binary(pair, OpCode::Add, OpCode::Sub),
            Rule::multiplicative => self.compile_binary(pair, OpCode::Mul, OpCode::Div),
            Rule::power => self.compile_binary(pair, OpCode::Pow, OpCode::Nop), // ToDo: Chaining
            Rule::primary => {
                let inner = pair.into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::number => self.compile_number(inner),
                    Rule::complex => self.compile_complex(inner),
                    Rule::identifier => {
                        let name = inner.as_str().to_string();
                        let reg = self.alloc_reg()?;
                        let handle = self.intern_string(&name);
                        let name_idx = self.add_constant(Value::string(handle));
                        // GetGlobal
                        self.emit_abx(OpCode::GetGlobal, reg, name_idx as u16);
                        Ok(reg)
                    },
                    Rule::expr => self.compile_expr(inner), // ( expr )
                    _ => Err(CompilerError::UnexpectedRule(format!("{:?}", inner.as_rule()))),
                }
            }
            _ => {
                let rule = pair.as_rule();
                let mut inner = pair.into_inner();
                if let Some(first) = inner.next() {
                    self.compile_expr(first)
                } else {
                    Err(CompilerError::UnexpectedRule(format!("Empty rule: {:?}", rule)))
                }
            }
        }
    }

    // Handles logic for additive, multiplicative, power (left associative for add/mul)
    fn compile_binary(&mut self, pair: Pair<Rule>, op1: OpCode, op2: OpCode) -> Result<u8, CompilerError> {
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

            // Result in a new register or reuse left? 
            // For SSA-like simplicity, we can reuse left if it's a temp, but let's alloc new for safety first.
            let res_reg = self.alloc_reg()?;
            self.emit_abc(opcode, res_reg, left_reg, right_reg);
            
            // Free the operand registers (simplified)
            // In a real allocator we'd define liveness. Here we assume stack discipline:
            // if left_reg and right_reg were just allocated, we can conceptually "pop" them if result replaces them.
            // But strict stack register machine requires care. 
            // Strategy: Accumulate into `res_reg` which becomes the new `left_reg` for next iteration.
            
            // Optimization: Reuse left_reg if it is the top temp?
            // Let's just return res_reg for now.
            left_reg = res_reg;
        }
        Ok(left_reg)
    }

    fn compile_number(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let s = pair.as_str();
        let val = s.parse::<f64>().map_err(|_| CompilerError::InvalidNumber)?;
        
        let reg = self.alloc_reg()?;
        // Optimization: if fitting in load_imm_i8? 
        // For now always LoadConst
        let const_idx = self.add_constant(Value::number(val));
        
        if const_idx <= 0xFFFF {
            self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        } else {
            return Err(CompilerError::TooManyConstants);
        }
        
        Ok(reg)
    }

    fn compile_complex(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
         // "3i" -> number part is "3"
         let s = pair.as_str();
         let num_str = &s[..s.len()-1]; // Remove 'i'
         let val = num_str.parse::<f64>().map_err(|_| CompilerError::InvalidComplex)?;
         
         // In new VM, Complex might be a value type or object. 
         // Assuming we can treat it as basic for now or need NewComplex opcode.
         // OpCode::NewComplex R[A] = Complex(R[B], R[C])
         // For "3i", real is 0, imag is 3.
         
         let reg = self.alloc_reg()?;
         let zero_reg = self.alloc_reg()?;
         let val_reg = self.alloc_reg()?;
         
         // Load 0
         let z_idx = self.add_constant(Value::number(0.0));
         self.emit_abx(OpCode::LoadConst, zero_reg, z_idx as u16);
         
         // Load Val
         let v_idx = self.add_constant(Value::number(val));
         self.emit_abx(OpCode::LoadConst, val_reg, v_idx as u16);
         
         // NewComplex
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

    fn intern_string(&mut self, s:&str) -> u32 {
        // Check if string already exist
        if let Some(&handle) = self.string_cache.get(s) {
            return handle;
        }

        // If not exist, add it to the arena
        let handle = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.string_cache.insert(s.to_string(), handle);
        handle
    }

    fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.bytecode.push(encode_abc(op.as_u8(), a, b, c));
    }
    
    fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.bytecode.push(encode_abx(op.as_u8(), a, bx));
    }
}
