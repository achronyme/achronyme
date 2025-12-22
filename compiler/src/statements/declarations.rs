use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::expressions::PostfixCompiler;
use crate::types::Local;
use achronyme_parser::Rule;
use pest::iterators::Pair;
use vm::opcode::OpCode;
use memory::Value;

pub trait DeclarationCompiler {
    fn compile_let_decl(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError>;
    fn compile_mut_decl(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError>;
    fn compile_assignment(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError>;
}

impl DeclarationCompiler for Compiler {
    fn compile_let_decl(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError> {
        let mut inner = pair.into_inner();
        let name_pair = inner.next().unwrap();
        let name = name_pair.as_str(); 
        let expr = inner.next().unwrap();

        let reg = self.compile_expr(expr)?;

        if self.current().scope_depth > 0 {
            let depth = self.current().scope_depth;
            self.current().locals.push(Local {
                name: name.to_string(),
                depth,
                is_captured: false,
                reg,
            });
        } else {
             if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants);
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;
            
            self.global_symbols.insert(name.to_string(), idx);
            self.emit_abx(OpCode::DefGlobalLet, reg, idx);
            self.free_reg(reg);
        }
        Ok(())
    }

    fn compile_mut_decl(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError> {
        let mut inner = pair.into_inner();
        let name_pair = inner.next().unwrap();
        let name = name_pair.as_str(); 
        let expr = inner.next().unwrap();

        let reg = self.compile_expr(expr)?;

        if self.current().scope_depth > 0 {
            let depth = self.current().scope_depth;
            self.current().locals.push(Local {
                name: name.to_string(),
                depth,
                is_captured: false,
                reg,
            });
        } else {
             if self.next_global_idx == u16::MAX {
                return Err(CompilerError::TooManyConstants);
            }
            let idx = self.next_global_idx;
            self.next_global_idx += 1;
            
            self.global_symbols.insert(name.to_string(), idx);
            self.emit_abx(OpCode::DefGlobalVar, reg, idx);
            self.free_reg(reg);
        }
        Ok(())
    }

    fn compile_assignment(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError> {
        let mut inner = pair.into_inner();
        let lhs_pair = inner.next().unwrap(); // postfix_expr
        let rhs_pair = inner.next().unwrap();

        let mut lhs_inner = lhs_pair.into_inner();
        let atom = lhs_inner.next().unwrap();
        let mut suffixes: Vec<Pair<Rule>> = lhs_inner.collect();

        if suffixes.is_empty() {
             // Simple Identifier Assignment
             let atom_inner = atom.into_inner().next().unwrap();
             if atom_inner.as_rule() != Rule::identifier {
                  return Err(CompilerError::UnexpectedRule("LHS atom must be identifier".into()));
             }
             let name = atom_inner.as_str();

             let val_reg = self.compile_expr(rhs_pair)?;

             if let Some((_, local_reg)) = self.resolve_local(name) {
                  self.emit_abc(OpCode::Move, local_reg, val_reg, 0);
             } else if let Some(upval_idx) = self.resolve_upvalue(self.compilers.len() - 1, name) {
                  self.emit_abx(OpCode::SetUpvalue, val_reg, upval_idx as u16);
             } else if let Some(global_idx) = self.global_symbols.get(name) {
                  self.emit_abx(OpCode::SetGlobal, val_reg, *global_idx);
             } else {
                  return Err(CompilerError::UnknownOperator(format!("Undefined variable '{}'", name)));
             }
             
             self.free_reg(val_reg);
             Ok(())
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
                 Rule::identifier => {
                     // Key is string literal
                     let name = inner_op.as_str();
                     let handle = self.intern_string(name);
                     let reg = self.alloc_reg()?;
                     let val = Value::string(handle);
                     let idx = self.add_constant(val);
                     if idx > 65535 {
                         return Err(CompilerError::TooManyConstants);
                     }
                     self.emit_abx(OpCode::LoadConst, reg, idx as u16);
                     reg
                 },
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
             Ok(())
        }
    }
}
