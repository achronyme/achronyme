use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler; // For block/if/while
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::functions::FunctionDefinitionCompiler; // For fn_expr
use crate::scopes::ScopeCompiler; // For resolve_local
use achronyme_parser::Rule;
use memory::Value;
use pest::iterators::Pair;
use vm::opcode::OpCode;

pub trait AtomCompiler {
    fn compile_atom(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_number(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_string(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_list(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_map(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_dot_key(&mut self, name: &str) -> Result<u8, CompilerError>;
    fn unescape_string(raw: &str) -> String;
}

impl AtomCompiler for Compiler {
    fn compile_atom(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::number => self.compile_number(inner),
            Rule::string => self.compile_string(inner),
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
            Rule::prove_expr => self.compile_prove(inner),
            Rule::identifier => {
                let name = inner.as_str().to_string();
                let reg = self.alloc_reg()?;

                // 1. First check locals (including function parameters)
                if let Some((_, local_reg)) = self.resolve_local(&name) {
                    // Local variable - just MOVE from its register
                    self.emit_abc(OpCode::Move, reg, local_reg, 0);

                    Ok(reg)
                } else if let Some(upval_idx) =
                    self.resolve_upvalue(self.compilers.len() - 1, &name)
                {
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

        let mut count: usize = 0;
        let start_reg = self.current().reg_top;

        for expr in inside {
            let reg = self.compile_expr(expr)?;
            // Verify contiguity (sanity check)
            if reg != start_reg.wrapping_add(count as u8) {
                return Err(CompilerError::CompilerLimitation(
                    "Register allocation fragmentation in list literal".into(),
                ));
            }
            count += 1;
        }

        if count > 255 {
            return Err(CompilerError::TooManyConstants); // Reuse for size limit
        }

        // R[A] = List(R[B]...R[B+C-1])
        // If count == 0, B is irrelevant, we pass 0
        self.emit_abc(OpCode::BuildList, target_reg, start_reg, count as u8);

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

        if count > 127 {
            // 255 / 2 approx
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
                Rule::string => &raw_s[1..raw_s.len() - 1], // Strip quotes
                _ => {
                    return Err(CompilerError::UnexpectedRule(
                        "Map key must be identifier or string".into(),
                    ))
                }
            };

            // Intern and LoadConst
            let key_handle = self.intern_string(key_slice);
            let key_val = Value::string(key_handle);
            let const_idx = self.add_constant(key_val);

            if const_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants);
            }
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
        let val: i64 = s.parse().map_err(|_| CompilerError::InvalidNumber)?;

        let reg = self.alloc_reg()?;
        let const_idx = self.add_constant(Value::int(val));

        if const_idx <= 0xFFFF {
            self.emit_abx(OpCode::LoadConst, reg, const_idx as u16);
        } else {
            return Err(CompilerError::TooManyConstants);
        }

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
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => {
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
}
