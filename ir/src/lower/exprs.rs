use achronyme_parser::ast::*;
use memory::FieldElement;

use crate::error::IrError;
use crate::types::{Instruction, IrType, SsaVar};

use super::{field_to_u64, to_ir_span, EnvValue, IrLowering};

impl IrLowering {
    pub(super) fn lower_expr(&mut self, expr: &Expr) -> Result<SsaVar, IrError> {
        match expr {
            Expr::Number { value, span } => self.lower_number(value, span),
            Expr::FieldLit {
                value,
                radix,
                span,
            } => self.lower_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ONE,
                });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            Expr::Bool { value: false, .. } => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ZERO,
                });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            Expr::Ident { name, span } => {
                let sp = to_ir_span(span);
                // Try direct lookup first, then prefixed for module-internal vars
                let val = self.env.get(name.as_str()).or_else(|| {
                    self.fn_call_prefix
                        .as_ref()
                        .and_then(|prefix| self.env.get(&format!("{prefix}::{name}")))
                });
                match val {
                    Some(EnvValue::Scalar(v)) => Ok(*v),
                    Some(EnvValue::Array(_)) => Err(IrError::TypeMismatch {
                        expected: "scalar".into(),
                        got: "array".into(),
                        span: sp,
                    }),
                    None => Err(IrError::UndeclaredVariable(name.clone(), sp)),
                }
            }
            Expr::BinOp { op, lhs, rhs, span } => self.lower_binop(op, lhs, rhs, span),
            Expr::UnaryOp { op, operand, span } => self.lower_unary(op, operand, span),
            Expr::Call { callee, args, span } => self.lower_call(callee, args, span),
            Expr::Index { object, index, span } => self.lower_index(object, index, span),
            Expr::If {
                condition,
                then_block,
                else_branch,
                span: _,
            } => self.lower_if(condition, then_block, else_branch.as_ref()),
            Expr::For {
                var,
                iterable,
                body,
                span,
            } => self.lower_for(var, iterable, body, span),
            Expr::Block(block) => self.lower_block(block),
            Expr::While { span, .. } | Expr::Forever { span, .. } => {
                Err(IrError::UnboundedLoop(to_ir_span(span)))
            }
            Expr::Prove { span, .. } => Err(IrError::UnsupportedOperation(
                "prove blocks cannot be nested inside circuits (a circuit is already generating constraints)".into(),
                to_ir_span(span),
            )),
            Expr::FnExpr { span, .. } => Err(IrError::UnsupportedOperation(
                "closures are not supported in circuits (captured variables cannot be tracked as circuit wires — use 'fn' declarations instead)".into(),
                to_ir_span(span),
            )),
            Expr::StringLit { span, .. } => {
                Err(IrError::TypeNotConstrainable("string".into(), to_ir_span(span)))
            }
            Expr::Nil { span } => {
                Err(IrError::TypeNotConstrainable("nil".into(), to_ir_span(span)))
            }
            Expr::Array { span, .. } => Err(IrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: to_ir_span(span),
            }),
            Expr::Map { span, .. } => {
                Err(IrError::TypeNotConstrainable("map".into(), to_ir_span(span)))
            }
            Expr::DotAccess {
                object,
                field,
                span,
            } => {
                // Support module.name access for imported constants
                if let Expr::Ident { name: module, .. } = object.as_ref() {
                    let qualified = format!("{module}::{field}");
                    if let Some(val) = self.env.get(&qualified) {
                        match val {
                            EnvValue::Scalar(v) => return Ok(*v),
                            EnvValue::Array(_) => {
                                return Err(IrError::UnsupportedOperation(
                                    format!("`{module}.{field}` is an array, not a scalar"),
                                    to_ir_span(span),
                                ));
                            }
                        }
                    }
                }
                Err(IrError::UnsupportedOperation(
                    "dot access is not supported in circuits (use arrays with static indexing instead)".into(),
                    to_ir_span(span),
                ))
            }
            Expr::BigIntLit { span, .. } => Err(IrError::TypeNotConstrainable(
                "BigInt".into(),
                to_ir_span(span),
            )),
        }
    }

    fn lower_number(&mut self, s: &str, span: &Span) -> Result<SsaVar, IrError> {
        if s.contains('.') {
            return Err(IrError::TypeNotConstrainable(
                "decimal".into(),
                to_ir_span(span),
            ));
        }
        let (negative, digits) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };
        let fe = FieldElement::from_decimal_str(digits)
            .ok_or_else(|| IrError::ParseError(format!("invalid integer: {s}")))?;
        let v = self.program.fresh_var();
        if negative {
            let pos = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: pos,
                value: fe,
            });
            self.program.set_type(pos, IrType::Field);
            self.program.push(Instruction::Neg {
                result: v,
                operand: pos,
            });
        } else {
            self.program.push(Instruction::Const {
                result: v,
                value: fe,
            });
        }
        self.program.set_type(v, IrType::Field);
        Ok(v)
    }

    fn lower_field_lit(
        &mut self,
        value: &str,
        radix: &FieldRadix,
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        let fe = match radix {
            FieldRadix::Decimal => FieldElement::from_decimal_str(value),
            FieldRadix::Hex => FieldElement::from_hex_str(value),
            FieldRadix::Binary => FieldElement::from_binary_str(value),
        }
        .ok_or_else(|| {
            IrError::ParseError(format!("invalid field literal at line {}", span.line))
        })?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::Const {
            result: v,
            value: fe,
        });
        self.program.set_type(v, IrType::Field);
        Ok(v)
    }

    pub(super) fn lower_binop(
        &mut self,
        op: &BinOp,
        lhs: &Expr,
        rhs: &Expr,
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        match op {
            BinOp::Add => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::Add { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            BinOp::Sub => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::Sub { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            BinOp::Mul => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::Mul { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            BinOp::Div => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::Div { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Field);
                Ok(v)
            }
            BinOp::Mod => Err(IrError::UnsupportedOperation(
                "modulo is not supported in circuits (the '%' operator has no efficient field arithmetic equivalent — use range_check for bounds)".into(),
                to_ir_span(span),
            )),
            BinOp::Pow => {
                let base = self.lower_expr(lhs)?;
                let exp_var = self.lower_expr(rhs)?;

                let exp_val = self.get_const_value(exp_var).ok_or_else(|| {
                    IrError::UnsupportedOperation(
                        "exponent must be a constant integer in circuits (x^n is unrolled to n multiplications at compile time)".into(),
                        None,
                    )
                })?;
                let exp_u64 = field_to_u64(&exp_val).ok_or_else(|| {
                    IrError::UnsupportedOperation(
                        "exponent too large for circuit compilation".into(),
                        None,
                    )
                })?;

                if exp_u64 == 0 {
                    let v = self.program.fresh_var();
                    self.program.push(Instruction::Const {
                        result: v,
                        value: FieldElement::ONE,
                    });
                    self.program.set_type(v, IrType::Field);
                    return Ok(v);
                }

                self.pow_by_squaring(base, exp_u64)
            }
            BinOp::Eq => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::IsEq { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::Neq => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::IsNeq { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::Lt => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::IsLt { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::Le => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::IsLe { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::Gt => {
                // a > b  ≡  b < a
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::IsLt { result: v, lhs: r, rhs: l });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::Ge => {
                // a >= b  ≡  b <= a
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::IsLe { result: v, lhs: r, rhs: l });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::And => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::And { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
            BinOp::Or => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program
                    .push(Instruction::Or { result: v, lhs: l, rhs: r });
                self.program.set_type(v, IrType::Bool);
                Ok(v)
            }
        }
    }

    pub(super) fn lower_unary(
        &mut self,
        op: &UnaryOp,
        operand: &Expr,
        _span: &Span,
    ) -> Result<SsaVar, IrError> {
        // Double negation / double NOT cancellation: --x → x, !!x → x
        if let Expr::UnaryOp {
            op: inner_op,
            operand: inner_operand,
            ..
        } = operand
        {
            if inner_op == op {
                return self.lower_expr(inner_operand);
            }
        }
        let inner = self.lower_expr(operand)?;
        let v = self.program.fresh_var();
        match op {
            UnaryOp::Neg => {
                self.program.push(Instruction::Neg {
                    result: v,
                    operand: inner,
                });
                self.program.set_type(v, IrType::Field);
            }
            UnaryOp::Not => {
                // Validate operand is Bool if typed
                if let Some(IrType::Field) = self.program.get_type(inner) {
                    return Err(IrError::AnnotationMismatch {
                        name: "!operand".into(),
                        declared: "Bool".into(),
                        inferred: "Field".into(),
                        span: to_ir_span(_span),
                    });
                }
                self.program.push(Instruction::Not {
                    result: v,
                    operand: inner,
                });
                self.program.set_type(v, IrType::Bool);
            }
        }
        Ok(v)
    }
}
