use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::scopes::ScopeCompiler;
use crate::expressions::ExpressionCompiler;
use crate::statements::StatementCompiler; // For compile_stmt in block
use crate::types::{LoopContext, Local};
use achronyme_parser::{AchronymeParser, Rule};
use memory::Value;
use pest::iterators::Pair;
use pest::Parser;
use vm::opcode::{OpCode, instruction::encode_abx};

pub trait ControlFlowCompiler {
    fn compile_block(&mut self, pair: Pair<Rule>, target_reg: u8) -> Result<(), CompilerError>;
    fn compile_if(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_while(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_for(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_forever(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    
    // Low level
    fn emit_jump(&mut self, op: OpCode, a: u8) -> usize;
    fn patch_jump(&mut self, idx: usize);
    fn enter_loop(&mut self, start_label: usize);
    fn exit_loop(&mut self);
    
    // Statements
    fn compile_break(&mut self) -> Result<(), CompilerError>;
    fn compile_continue(&mut self) -> Result<(), CompilerError>;

    // ZK
    fn compile_prove(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
}

impl ControlFlowCompiler for Compiler {

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

        // Collect all stmts to handle 'last one' logic if expression
        let stmt_list: Vec<Pair<Rule>> = stmts.collect();
        let len = stmt_list.len();

        for (i, stmt) in stmt_list.into_iter().enumerate() {
            let is_last = i == len - 1;

            if is_last {
                let inner = stmt.clone().into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::expr => {
                        // Directly compile into target
                        let _ = self.compile_expr_into(inner, target_reg)?;
                    }
                    _ => {
                        self.compile_stmt(stmt)?;
                        self.emit_abx(OpCode::LoadNil, target_reg, 0);
                    }
                }
                last_processed = true;
            } else {
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
        let mut inner = pair.into_inner();
        let cond_expr = inner.next().unwrap();
        let then_block = inner.next().unwrap();
        let else_part = inner.next(); // Optional

        let target_reg = self.alloc_reg()?;

        // 1. Compile Condition
        let cond_reg = self.compile_expr(cond_expr)?;

        // 2. Jump if False -> Else
        let jump_else = self.emit_jump(OpCode::JumpIfFalse, cond_reg);
        self.free_reg(cond_reg); 

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
                     let res = self.compile_if(else_pair)?;
                     self.emit_abc(OpCode::Move, target_reg, res, 0);
                 },
                 _ => return Err(CompilerError::UnexpectedRule(format!("Else: {:?}", else_pair.as_rule())))
             }
        } else {
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
        
        let jump = self.emit_jump(OpCode::Jump, 0);
        self.current().loop_stack.last_mut().unwrap().break_jumps.push(jump);
        
        Ok(())
    }

    fn compile_continue(&mut self) -> Result<(), CompilerError> {
        let loop_ctx = self.current_ref().loop_stack.last()
            .ok_or(CompilerError::CompileError("continue outside of loop".into()))?;
            
        let target_depth = loop_ctx.scope_depth;
        let start_label = loop_ctx.start_label;
        
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
        
        self.emit_abx(OpCode::Jump, 0, start_label as u16);
        Ok(())
    }

    fn compile_for(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let mut inner = pair.into_inner();
        let var_name = inner.next().unwrap().as_str().to_string();

        let iterable_expr = inner.next().unwrap();
        let body_block = inner.next().unwrap();

        let iter_src_reg = self.compile_expr(iterable_expr)?;
        
        let iter_reg = self.alloc_contiguous(2)?;
        let val_reg = iter_reg + 1;
        
        self.emit_abc(OpCode::GetIter, iter_reg, iter_src_reg, 0); 
        
        let start_label = self.current().bytecode.len();
        self.enter_loop(start_label);
        
        let jump_exit_idx = self.emit_jump(OpCode::ForIter, iter_reg);
        
        self.begin_scope();
        let depth = self.current().scope_depth;
        self.current().locals.push(Local {
            name: var_name,
            depth,
            is_captured: false,
            reg: val_reg,
        });

        let body_target = self.alloc_reg()?;
        self.compile_block(body_block, body_target)?;
        self.free_reg(body_target);
        
        self.emit_abx(OpCode::Jump, 0, start_label as u16);
        
        self.patch_jump(jump_exit_idx);
        
        self.end_scope();

        self.exit_loop();

        self.free_reg(iter_reg);
        self.free_reg(iter_src_reg);
        
        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);
        Ok(target_reg)
    }

    fn compile_forever(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
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
        let mut inner = pair.into_inner();
        let cond_expr = inner.next().unwrap();
        let body_block = inner.next().unwrap();

        let start_label = self.current().bytecode.len();

        let cond_reg = self.compile_expr(cond_expr)?;

        let jump_end = self.emit_jump(OpCode::JumpIfFalse, cond_reg);
        
        self.free_reg(cond_reg); 

        self.enter_loop(start_label);
        
        let body_reg = self.alloc_reg()?;
        self.compile_block(body_block, body_reg)?;
        self.free_reg(body_reg); 

        self.emit_abx(OpCode::Jump, 0, start_label as u16);

        self.patch_jump(jump_end);
        
        self.exit_loop();

        let target_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadNil, target_reg, 0);

        Ok(target_reg)
    }

    fn compile_prove(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        // pair is prove_expr: "prove" ~ block
        let block = pair.into_inner().next().unwrap(); // the block
        let block_source = block.as_str().to_string();

        // Pre-scan: parse block source to find public/witness declarations
        let capture_names = prescan_prove_declarations(&block_source)?;

        // Build capture map: { "name": value, ... }
        let count = capture_names.len();
        if count > 127 {
            return Err(CompilerError::CompilerLimitation(
                "prove block captures too many variables".into(),
            ));
        }

        let map_reg = self.alloc_reg()?;

        if count > 0 {
            let start_reg = self.alloc_contiguous((count * 2) as u8)?;

            for (i, name) in capture_names.iter().enumerate() {
                let key_reg = start_reg + (i as u8 * 2);
                let val_reg = key_reg + 1;

                // Key: string constant
                let key_handle = self.intern_string(name);
                let key_val = Value::string(key_handle);
                let key_idx = self.add_constant(key_val);
                if key_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants);
                }
                self.emit_abx(OpCode::LoadConst, key_reg, key_idx as u16);

                // Value: resolve from current scope
                if let Some((_, local_reg)) = self.resolve_local(name) {
                    self.emit_abc(OpCode::Move, val_reg, local_reg, 0);
                } else if let Some(upval_idx) =
                    self.resolve_upvalue(self.compilers.len() - 1, name)
                {
                    self.emit_abx(OpCode::GetUpvalue, val_reg, upval_idx as u16);
                } else if let Some(&global_idx) = self.global_symbols.get(name) {
                    self.emit_abx(OpCode::GetGlobal, val_reg, global_idx);
                } else {
                    return Err(CompilerError::CompileError(format!(
                        "prove: variable `{name}` not found in scope"
                    )));
                }
            }

            self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8);

            // Free key/value registers
            for _ in 0..(count * 2) {
                let top = self.current().reg_top - 1;
                self.free_reg(top);
            }
        } else {
            // Empty capture map
            let start = self.current().reg_top;
            self.emit_abc(OpCode::BuildMap, map_reg, start, 0);
        }

        // Store block source as string constant
        let src_handle = self.intern_string(&block_source);
        let src_val = Value::string(src_handle);
        let src_idx = self.add_constant(src_val);
        if src_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants);
        }

        // Emit Prove R[map_reg], K[src_idx]
        self.emit_abx(OpCode::Prove, map_reg, src_idx as u16);

        // Result is nil (handler sets R[A] = nil)
        Ok(map_reg)
    }
}

/// Pre-scan a prove block source to extract public/witness declaration names.
///
/// Parses the block as `Rule::block` and collects all identifiers from
/// `public_decl` and `witness_decl` statements. Supports array syntax `x[N]`
/// which expands to `x_0, x_1, ..., x_{N-1}`.
fn prescan_prove_declarations(block_source: &str) -> Result<Vec<String>, CompilerError> {
    let pairs = AchronymeParser::parse(Rule::block, block_source)
        .map_err(|e| CompilerError::ParseError(format!("prove pre-scan: {e}")))?;

    let block_pair = pairs.into_iter().next().unwrap();
    let mut names = Vec::new();

    for stmt in block_pair.into_inner() {
        if stmt.as_rule() != Rule::stmt {
            continue;
        }
        let inner = match stmt.into_inner().next() {
            Some(inner) => inner,
            None => continue,
        };
        match inner.as_rule() {
            Rule::public_decl | Rule::witness_decl => {
                let mut children = inner.into_inner().peekable();
                while let Some(child) = children.next() {
                    if child.as_rule() == Rule::identifier {
                        let name = child.as_str().to_string();
                        if children.peek().map(|p| p.as_rule()) == Some(Rule::array_size) {
                            let size_pair = children.next().unwrap();
                            let s = size_pair.into_inner().next().unwrap().as_str();
                            let n: usize = s.parse().map_err(|_| {
                                CompilerError::ParseError(format!("invalid array size: {s}"))
                            })?;
                            if n > 10_000 {
                                return Err(CompilerError::ParseError(format!(
                                    "array size {n} exceeds maximum of 10,000"
                                )));
                            }
                            for i in 0..n {
                                names.push(format!("{name}_{i}"));
                            }
                        } else {
                            names.push(name);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(names)
}
