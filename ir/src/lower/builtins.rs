use achronyme_parser::ast::*;
use memory::FieldElement;

use crate::error::{IrError, OptSpan};
use crate::types::{Instruction, IrType, SsaVar};

use super::{to_ir_span, EnvValue, IrLowering};

impl IrLowering {
    pub(super) fn lower_call(
        &mut self,
        callee: &Expr,
        args: &[&Expr],
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        let sp = to_ir_span(span);
        // Identifier or DotAccess callees are supported
        let name = match callee {
            Expr::Ident { name, .. } => name.clone(),
            Expr::DotAccess { object, field, .. } => {
                // Method call pattern: expr.len() → treat as len(expr)
                if field == "len" {
                    // Synthesize args: the object becomes the sole argument
                    let mut method_args: Vec<&Expr> = vec![object.as_ref()];
                    method_args.extend(args.iter());
                    return self.lower_len(&method_args, sp);
                }
                // module.func() → qualified name "module::func"
                if let Expr::Ident { name: module, .. } = object.as_ref() {
                    format!("{module}::{field}")
                } else {
                    return Err(IrError::UnsupportedOperation(
                        "only named function calls are supported in circuits (dynamic dispatch cannot be compiled to constraints)".into(),
                        sp,
                    ));
                }
            }
            _ => {
                return Err(IrError::UnsupportedOperation(
                    "only named function calls are supported in circuits (dynamic dispatch cannot be compiled to constraints)".into(),
                    sp,
                ));
            }
        };

        match name.as_str() {
            "assert_eq" => self.lower_assert_eq(args, sp),
            "assert" => self.lower_assert(args, sp),
            "poseidon" => self.lower_poseidon(args, sp),
            "mux" => self.lower_mux(args, sp),
            "range_check" => self.lower_range_check(args, sp),
            "len" => self.lower_len(args, sp),
            "poseidon_many" => self.lower_poseidon_many(args, sp),
            "merkle_verify" => self.lower_merkle_verify(args, span),
            _ => self.lower_user_fn_call(&name, args, sp),
        }
    }

    fn lower_assert_eq(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "assert_eq".into(),
                expected: 2,
                got: args.len(),
                span: sp,
            });
        }
        let a = self.lower_expr(args[0])?;
        let b = self.lower_expr(args[1])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::AssertEq {
            result: v,
            lhs: a,
            rhs: b,
        });
        Ok(v)
    }

    fn lower_assert(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.len() != 1 {
            return Err(IrError::WrongArgumentCount {
                builtin: "assert".into(),
                expected: 1,
                got: args.len(),
                span: sp,
            });
        }
        let operand = self.lower_expr(args[0])?;
        let v = self.program.fresh_var();
        self.program
            .push(Instruction::Assert { result: v, operand });
        Ok(v)
    }

    fn lower_poseidon(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "poseidon".into(),
                expected: 2,
                got: args.len(),
                span: sp,
            });
        }
        let left = self.lower_expr(args[0])?;
        let right = self.lower_expr(args[1])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::PoseidonHash {
            result: v,
            left,
            right,
        });
        self.program.set_type(v, IrType::Field);
        Ok(v)
    }

    fn lower_mux(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.len() != 3 {
            return Err(IrError::WrongArgumentCount {
                builtin: "mux".into(),
                expected: 3,
                got: args.len(),
                span: sp,
            });
        }
        let cond = self.lower_expr(args[0])?;
        let if_true = self.lower_expr(args[1])?;
        let if_false = self.lower_expr(args[2])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::Mux {
            result: v,
            cond,
            if_true,
            if_false,
        });
        // Result type = branch type if both agree
        if let (Some(t), Some(f)) = (
            self.program.get_type(if_true),
            self.program.get_type(if_false),
        ) {
            if t == f {
                self.program.set_type(v, t);
            }
        }
        Ok(v)
    }

    fn lower_range_check(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "range_check".into(),
                expected: 2,
                got: args.len(),
                span: sp,
            });
        }
        let operand = self.lower_expr(args[0])?;
        let bits_var = self.lower_expr(args[1])?;

        let bits_fe = self.get_const_value(bits_var).ok_or_else(|| {
            IrError::UnsupportedOperation(
                "range_check bits argument must be a constant integer".into(),
                None,
            )
        })?;
        let bits = super::field_to_u64(&bits_fe).ok_or_else(|| {
            IrError::UnsupportedOperation("range_check bits value too large".into(), None)
        })? as u32;

        let v = self.program.fresh_var();
        self.program.push(Instruction::RangeCheck {
            result: v,
            operand,
            bits,
        });
        Ok(v)
    }

    fn lower_len(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.len() != 1 {
            return Err(IrError::WrongArgumentCount {
                builtin: "len".into(),
                expected: 1,
                got: args.len(),
                span: sp.clone(),
            });
        }
        let arg_name = match args[0] {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(IrError::UnsupportedOperation(
                    "len() argument must be an array identifier".into(),
                    sp,
                ));
            }
        };
        match self.env.get(&arg_name) {
            Some(EnvValue::Array(elems)) => {
                Ok(self.emit_const(FieldElement::from_u64(elems.len() as u64)))
            }
            Some(EnvValue::Scalar(_)) => Err(IrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: sp,
            }),
            None => Err(IrError::UndeclaredVariable(arg_name, sp)),
        }
    }

    fn lower_poseidon_many(&mut self, args: &[&Expr], sp: OptSpan) -> Result<SsaVar, IrError> {
        if args.is_empty() {
            return Err(IrError::WrongArgumentCount {
                builtin: "poseidon_many".into(),
                expected: 1,
                got: 0,
                span: sp,
            });
        }
        let lowered: Vec<SsaVar> = args
            .iter()
            .map(|a| self.lower_expr(a))
            .collect::<Result<_, _>>()?;

        let zero = self.emit_const(FieldElement::ZERO);
        let mut acc = if lowered.len() == 1 {
            let v = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: v,
                left: lowered[0],
                right: zero,
            });
            v
        } else {
            let v = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: v,
                left: lowered[0],
                right: lowered[1],
            });
            v
        };
        for arg in lowered.iter().skip(2) {
            let v = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: v,
                left: acc,
                right: *arg,
            });
            acc = v;
        }
        Ok(acc)
    }

    fn lower_merkle_verify(&mut self, args: &[&Expr], span: &Span) -> Result<SsaVar, IrError> {
        let sp = to_ir_span(span);
        if args.len() != 4 {
            return Err(IrError::WrongArgumentCount {
                builtin: "merkle_verify".into(),
                expected: 4,
                got: args.len(),
                span: sp.clone(),
            });
        }

        let root_val = self.resolve_arg_value(args[0])?;
        let leaf_val = self.resolve_arg_value(args[1])?;
        let path_val = self.resolve_arg_value(args[2])?;
        let indices_val = self.resolve_arg_value(args[3])?;

        let root = match root_val {
            EnvValue::Scalar(v) => v,
            EnvValue::Array(_) => {
                return Err(IrError::TypeMismatch {
                    expected: "scalar".into(),
                    got: "array".into(),
                    span: sp.clone(),
                })
            }
        };
        let mut current = match leaf_val {
            EnvValue::Scalar(v) => v,
            EnvValue::Array(_) => {
                return Err(IrError::TypeMismatch {
                    expected: "scalar".into(),
                    got: "array".into(),
                    span: sp.clone(),
                })
            }
        };
        let path = match path_val {
            EnvValue::Array(v) => v,
            EnvValue::Scalar(_) => {
                return Err(IrError::TypeMismatch {
                    expected: "array".into(),
                    got: "scalar".into(),
                    span: sp.clone(),
                })
            }
        };
        let indices = match indices_val {
            EnvValue::Array(v) => v,
            EnvValue::Scalar(_) => {
                return Err(IrError::TypeMismatch {
                    expected: "array".into(),
                    got: "scalar".into(),
                    span: sp.clone(),
                })
            }
        };

        if path.len() != indices.len() {
            return Err(IrError::ArrayLengthMismatch {
                expected: path.len(),
                got: indices.len(),
                span: sp,
            });
        }

        for i in 0..path.len() {
            let left_hash = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: left_hash,
                left: current,
                right: path[i],
            });
            let right_hash = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: right_hash,
                left: path[i],
                right: current,
            });
            let mux_result = self.program.fresh_var();
            self.program.push(Instruction::Mux {
                result: mux_result,
                cond: indices[i],
                if_true: right_hash,
                if_false: left_hash,
            });
            current = mux_result;
        }

        let v = self.program.fresh_var();
        self.program.push(Instruction::AssertEq {
            result: v,
            lhs: current,
            rhs: root,
        });
        Ok(v)
    }
}
