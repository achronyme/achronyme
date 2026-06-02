use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::error::CompilerError;
use crate::functions::FunctionDefinitionCompiler;
use achronyme_parser::ast::*;
use akron::opcode::OpCode;

pub mod binary;

mod helpers;
mod static_access;

pub use binary::BinaryCompiler;

pub trait ExpressionCompiler {
    fn compile_expr(&mut self, expr: &Expr) -> Result<u8, CompilerError>;
    fn compile_expr_into(&mut self, expr: &Expr, target: u8) -> Result<(), CompilerError>;
}

impl ExpressionCompiler for Compiler {
    fn compile_expr(&mut self, expr: &Expr) -> Result<u8, CompilerError> {
        self.current_span = Some(expr.span().clone());
        // Stash the current expression id so dispatch helpers
        // (`compile_ident`, …) can form the `(module, expr_id)`
        // annotation key without a signature change. Set
        // unconditionally; synthetic expressions
        // (id == ExprId::SYNTHETIC) simply miss the annotation map.
        self.current_expr_id = Some(expr.id());
        match expr {
            // === Atoms ===
            Expr::Number { value, .. } => self.compile_number(value),
            Expr::FieldLit { value, radix, .. } => self.compile_field_lit(value, radix),
            Expr::BigIntLit {
                value,
                width,
                radix,
                ..
            } => self.compile_bigint_lit(value, *width, radix),
            Expr::StringLit { value, .. } => self.compile_string(value),
            Expr::Bool { value: true, .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadTrue, reg, 0)?;
                Ok(reg)
            }
            Expr::Bool { value: false, .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadFalse, reg, 0)?;
                Ok(reg)
            }
            Expr::Nil { .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadNil, reg, 0)?;
                Ok(reg)
            }
            Expr::Ident { name, .. } => self.compile_ident(name),
            Expr::Array { elements, .. } => self.compile_list(elements),
            Expr::Map { pairs, .. } => self.compile_map(pairs),

            // === Binary operations ===
            Expr::BinOp {
                op: BinOp::And,
                lhs,
                rhs,
                ..
            } => self.compile_and(lhs, rhs),
            Expr::BinOp {
                op: BinOp::Or,
                lhs,
                rhs,
                ..
            } => self.compile_or(lhs, rhs),
            Expr::BinOp { op, lhs, rhs, .. } => self.compile_binop(op, lhs, rhs),

            // === Unary operations ===
            Expr::UnaryOp { op, operand, .. } => {
                let reg = self.compile_expr(operand)?;
                match op {
                    UnaryOp::Neg => self.emit_abc(OpCode::Neg, reg, reg, 0)?,
                    UnaryOp::Not => self.emit_abc(OpCode::LogNot, reg, reg, 0)?,
                }
                Ok(reg)
            }

            // === Postfix (Call, Index, DotAccess) ===
            Expr::Call {
                callee, args, span, ..
            } => {
                // If any arg has a keyword name, route to circuit call handler
                if args.iter().any(|a| a.name.is_some()) {
                    let name = match callee.as_ref() {
                        Expr::Ident { name, .. } => name,
                        _ => {
                            return Err(CompilerError::CompileError(
                                "keyword arguments require a simple function name".into(),
                                self.cur_span(),
                            ));
                        }
                    };
                    let kw_args: Vec<(String, Expr)> = args
                        .iter()
                        .map(|a| (a.name.clone().unwrap_or_default(), a.value.clone()))
                        .collect();
                    self.compile_circuit_call(name, &kw_args, span)
                } else {
                    let positional: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                    self.compile_call(callee, &positional)
                }
            }
            Expr::Index { object, index, .. } => self.compile_index_expr(object, index),
            Expr::DotAccess { object, field, .. } => self.compile_dot_access(object, field),

            // === Control flow ===
            Expr::If {
                condition,
                then_block,
                else_branch,
                ..
            } => self.compile_if(condition, then_block, else_branch.as_ref()),
            Expr::While {
                condition, body, ..
            } => self.compile_while(condition, body),
            Expr::For {
                var,
                iterable,
                body,
                ..
            } => self.compile_for(var, iterable, body),
            Expr::Forever { body, .. } => self.compile_forever(body),
            Expr::Block { block, .. } => {
                let reg = self.alloc_reg()?;
                self.compile_block(block, reg)?;
                Ok(reg)
            }

            // === Functions ===
            Expr::FnExpr {
                name, params, body, ..
            } => self.compile_fn_core(name.as_deref(), params, body),

            // === ZK ===
            Expr::Prove {
                name, body, params, ..
            } => self.compile_prove(body, params, name.as_deref()),

            // === Static access (Type::MEMBER) ===
            Expr::StaticAccess {
                type_name, member, ..
            } => self.compile_static_access(type_name, member),

            // CircuitCall removed — handled by Call with keyword args

            // === Error recovery placeholder ===
            Expr::Error { .. } => {
                let reg = self.alloc_reg()?;
                self.emit_abx(OpCode::LoadNil, reg, 0)?;
                Ok(reg)
            }
        }
    }

    fn compile_expr_into(&mut self, expr: &Expr, target: u8) -> Result<(), CompilerError> {
        let reg = self.compile_expr(expr)?;
        if reg != target {
            self.emit_abc(OpCode::Move, target, reg, 0)?;
            self.free_reg(reg)?;
        }
        Ok(())
    }
}
