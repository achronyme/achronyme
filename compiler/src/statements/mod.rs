use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::declarations::DeclarationCompiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::functions::FunctionDefinitionCompiler;
use achronyme_parser::ast::*;
use vm::opcode::OpCode;

pub mod declarations;

pub trait StatementCompiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError>;
}

/// Extract the source line number from a statement (1-based), or 0 if unavailable.
fn stmt_line(stmt: &Stmt) -> u32 {
    match stmt {
        Stmt::LetDecl { span, .. }
        | Stmt::MutDecl { span, .. }
        | Stmt::Assignment { span, .. }
        | Stmt::Print { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::FnDecl { span, .. }
        | Stmt::PublicDecl { span, .. }
        | Stmt::WitnessDecl { span, .. }
        | Stmt::Break { span }
        | Stmt::Continue { span } => span.line as u32,
        Stmt::Expr(expr) => expr_line(expr),
    }
}

/// Extract the source line number from an expression (1-based), or 0 if unavailable.
fn expr_line(expr: &Expr) -> u32 {
    expr.span().line as u32
}

impl StatementCompiler for Compiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError> {
        // Track source line for error reporting
        self.current().current_line = stmt_line(stmt);

        match stmt {
            Stmt::LetDecl { name, value, .. } => self.compile_let_decl(name, value),
            Stmt::MutDecl { name, value, .. } => self.compile_mut_decl(name, value),
            Stmt::Assignment { target, value, .. } => self.compile_assignment(target, value),
            Stmt::Print { value, .. } => {
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
                self.compile_expr_into(value, arg_reg)?;

                // 4. Call
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1);

                self.free_reg(arg_reg);
                self.free_reg(func_reg);
                Ok(())
            }
            Stmt::Break { .. } => self.compile_break(),
            Stmt::Continue { .. } => self.compile_continue(),
            Stmt::Return { value, .. } => {
                if let Some(expr) = value {
                    let reg = self.compile_expr(expr)?;
                    self.emit_abc(OpCode::Return, reg, 1, 0);
                    self.free_reg(reg);
                } else {
                    // Void return (0 values), do NOT load Nil
                    self.emit_abc(OpCode::Return, 0, 0, 0);
                }
                Ok(())
            }
            Stmt::FnDecl {
                name, params, body, ..
            } => {
                let reg = self.compile_fn_core(Some(name), params, body)?;
                self.free_reg(reg);
                Ok(())
            }
            Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. } => Ok(()), // no-op in VM
            Stmt::Expr(expr) => {
                let reg = self.compile_expr(expr)?;
                self.free_reg(reg);
                Ok(())
            }
        }
    }
}
