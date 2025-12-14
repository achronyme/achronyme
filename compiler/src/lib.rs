use memory::Value;
use achronyme_parser::{parse_expression, Rule};
use vm::opcode::{OpCode, instruction::{encode_abc, encode_abx}};
use pest::iterators::Pair;

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
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
            constants: Vec::new(),
            reg_top: 0,
        }
    }
    
    pub fn compile(&mut self, source: &str) -> Result<Vec<u32>, String> {
        let pairs = parse_expression(source).map_err(|e| e.to_string())?;
        
        // We expect a single top-level expression for now
        for pair in pairs {
            let res_reg = self.compile_expr(pair)?;
            // Implicit return of the last expression result
            self.emit_abc(OpCode::Return, res_reg, 0, 0);
        }
        
        Ok(self.bytecode.clone())
    }

    fn compile_expr(&mut self, pair: Pair<Rule>) -> Result<u8, String> {
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
                    Rule::expr => self.compile_expr(inner), // ( expr )
                    _ => Err(format!("Unexpected primary rule: {:?}", inner.as_rule())),
                }
            }
            _ => {
                let rule = pair.as_rule();
                let mut inner = pair.into_inner();
                if let Some(first) = inner.next() {
                    self.compile_expr(first)
                } else {
                    Err(format!("Empty rule: {:?}", rule))
                }
            }
        }
    }

    // Handles logic for additive, multiplicative, power (left associative for add/mul)
    fn compile_binary(&mut self, pair: Pair<Rule>, op1: OpCode, op2: OpCode) -> Result<u8, String> {
        let mut pairs = pair.into_inner();
        let mut left_reg = self.compile_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right_pair = pairs.next().ok_or("Missing right operand")?;
            let right_reg = self.compile_expr(right_pair)?;
            
            let opcode = match op_pair.as_str() {
                "+" | "*" | "^" => op1,
                "-" | "/" => op2,
                _ => return Err(format!("Unknown operator: {}", op_pair.as_str())),
            };

            // Result in a new register or reuse left? 
            // For SSA-like simplicity, we can reuse left if it's a temp, but let's alloc new for safety first.
            let res_reg = self.alloc_reg();
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

    fn compile_number(&mut self, pair: Pair<Rule>) -> Result<u8, String> {
        let s = pair.as_str();
        let val = s.parse::<f64>().map_err(|_| "Invalid number")?;
        
        let reg = self.alloc_reg();
        // Optimization: if fitting in load_imm_i8? 
        // For now always LoadConst
        let const_idx = self.add_constant(Value::Number(val));
        
        if const_idx <= 0xFFFF {
            self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        } else {
            return Err("Too many constants".to_string());
        }
        
        Ok(reg)
    }

    fn compile_complex(&mut self, pair: Pair<Rule>) -> Result<u8, String> {
         // "3i" -> number part is "3"
         let s = pair.as_str();
         let num_str = &s[..s.len()-1]; // Remove 'i'
         let val = num_str.parse::<f64>().map_err(|_| "Invalid complex number")?;
         
         // In new VM, Complex might be a value type or object. 
         // Assuming we can treat it as basic for now or need NewComplex opcode.
         // OpCode::NewComplex R[A] = Complex(R[B], R[C])
         // For "3i", real is 0, imag is 3.
         
         let reg = self.alloc_reg();
         let zero_reg = self.alloc_reg();
         let val_reg = self.alloc_reg();
         
         // Load 0
         let z_idx = self.add_constant(Value::Number(0.0));
         self.emit_abx(OpCode::LoadConst, zero_reg, z_idx as u16);
         
         // Load Val
         let v_idx = self.add_constant(Value::Number(val));
         self.emit_abx(OpCode::LoadConst, val_reg, v_idx as u16);
         
         // NewComplex
         self.emit_abc(OpCode::NewComplex, reg, zero_reg, val_reg);
         
         Ok(reg)
    }

    // --- Helpers ---

    fn alloc_reg(&mut self) -> u8 {
        let r = self.reg_top;
        if r == 255 {
            panic!("Register overflow");
        }
        self.reg_top += 1;
        r
    }
    
    // Rudimentary reset for expression boundaries needed usually
    
    fn add_constant(&mut self, val: Value) -> usize {
        self.constants.push(val);
        self.constants.len() - 1
    }

    fn emit_abc(&mut self, op: OpCode, a: u8, b: u8, c: u8) {
        self.bytecode.push(encode_abc(op.as_u8(), a, b, c));
    }
    
    fn emit_abx(&mut self, op: OpCode, a: u8, bx: u16) {
        self.bytecode.push(encode_abx(op.as_u8(), a, bx));
    }
}
