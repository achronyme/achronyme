use crate::codegen::Compiler;
use crate::error::CompilerError;
use achronyme_parser::Rule;
use pest::iterators::Pair;
use vm::opcode::OpCode;
use crate::control_flow::ControlFlowCompiler;

pub mod atoms;
pub mod binary;
pub mod postfix;

pub use atoms::AtomCompiler;
pub use binary::BinaryCompiler;
pub use postfix::PostfixCompiler;

pub trait ExpressionCompiler {
    fn compile_expr(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError>;
    fn compile_expr_into(&mut self, pair: Pair<Rule>, target: u8) -> Result<(), CompilerError>;
}

impl ExpressionCompiler for Compiler {
    fn compile_expr(&mut self, pair: Pair<Rule>) -> Result<u8, CompilerError> {
        match pair.as_rule() {
            Rule::expr => self.compile_expr(pair.into_inner().next().unwrap()),
            Rule::or_expr => self.compile_or(pair),
            Rule::and_expr => self.compile_and(pair),
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

    // Specialized compile_expr that targets a register
    fn compile_expr_into(&mut self, pair: Pair<Rule>, target: u8) -> Result<(), CompilerError> {
        let reg = self.compile_expr(pair)?;
        if reg != target {
            self.emit_abc(OpCode::Move, target, reg, 0);
            self.free_reg(reg); // Hygiene: Free the temp register
        }
        Ok(())
    }
}
