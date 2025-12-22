use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::{AtomCompiler, ExpressionCompiler};
use achronyme_parser::Rule;
use pest::iterators::Pair;
use vm::opcode::OpCode;

pub trait PostfixCompiler {
    fn compile_postfix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_prefix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_postfix_op(&mut self, reg: u8, op: Pair<Rule>) -> Result<(), CompilerError>;
}

impl PostfixCompiler for Compiler {
    fn compile_prefix(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        let mut inner: Vec<Pair<Rule>> = pair.into_inner().collect();
        // Last item is always the expression (postfix_expr)
        let expr_pair = inner.pop().ok_or(CompilerError::UnexpectedRule("Empty prefix expr".into()))?;
        
        let reg = self.compile_postfix(expr_pair)?;
        
        // Iterating operators in reverse (innermost first)
        for op in inner.into_iter().rev() {
            match op.as_str() {
                "-" => {
                    self.emit_abc(OpCode::Neg, reg, reg, 0);
                }
                "!" => {
                    // Placeholder for Not if supported later
                }
                _ => return Err(CompilerError::UnknownOperator(op.as_str().to_string())),
            }
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
}
