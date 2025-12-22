use vm::opcode::OpCode;
use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::declarations::DeclarationCompiler;
use crate::control_flow::ControlFlowCompiler;
use crate::expressions::ExpressionCompiler;
use achronyme_parser::Rule;
use pest::iterators::Pair;

pub mod declarations;

pub trait StatementCompiler {
    fn compile_stmt(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError>;
}

impl StatementCompiler for Compiler {
    fn compile_stmt(&mut self, pair: Pair<Rule>) -> Result<(), CompilerError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::let_decl => self.compile_let_decl(inner),
            Rule::mut_decl => self.compile_mut_decl(inner),
            Rule::assignment => self.compile_assignment(inner),
            Rule::print_stmt => {
                let expr = inner.into_inner().next().unwrap();
                
                // 1. Prepare Call Frame: Func Reg, Arg Reg
                let func_reg = self.alloc_reg()?;
                let arg_reg = self.alloc_reg()?; // Must be func_reg + 1
                
                // 2. Load "print" (Pre-defined)
                let print_idx = *self
                    .global_symbols
                    .get("print")
                    .expect("Natives not initialized");
                self.emit_abx(OpCode::GetGlobal, func_reg, print_idx);
                
                // 3. Compile Argument
                self.compile_expr_into(expr, arg_reg)?;
                
                // 4. Call
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1);
                
                self.free_reg(arg_reg);
                self.free_reg(func_reg);
                Ok(())
            },
            Rule::break_stmt => self.compile_break(),
            Rule::continue_stmt => self.compile_continue(),
            Rule::return_stmt => {
                 let expr_pair = inner.into_inner().next();
                 if let Some(expr) = expr_pair {
                     let reg = self.compile_expr(expr)?;
                     self.emit_abc(OpCode::Return, reg, 1, 0); 
                     self.free_reg(reg);
                 } else {
                     // Void return (0 values), do NOT load Nil
                     self.emit_abc(OpCode::Return, 0, 0, 0);
                 }
                 Ok(())
            },
            Rule::expr => {
                let reg = self.compile_expr(inner)?;
                self.free_reg(reg);
                Ok(())
            },
            _ => Err(CompilerError::UnexpectedRule(format!("{:?}", inner.as_rule()))) 
        }
    }
}
