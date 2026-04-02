use std::collections::HashSet;

use achronyme_parser::ast::*;
use memory::{FieldBackend, FieldElement};

use crate::error::{IrError, OptSpan};
use crate::types::{Instruction, IrType, SsaVar};

use super::{
    annotation_to_ir_type, field_to_u64, to_ir_span, type_compatible, EnvValue, FnDef, IrLowering,
};

impl<F: FieldBackend> IrLowering<F> {
    /// Handle a call to a user-defined function (inline the body).
    pub(super) fn lower_user_fn_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        sp: OptSpan,
    ) -> Result<SsaVar, IrError> {
        // Try direct lookup first, then prefixed lookup for internal module calls
        let (resolved_name, fn_def) = match self.fn_table.get(name).cloned() {
            Some(fd) => (name.to_string(), fd),
            None => {
                // If we're inlining a module function, try module::name
                if let Some(ref prefix) = self.fn_call_prefix {
                    let qualified = format!("{prefix}::{name}");
                    match self.fn_table.get(&qualified).cloned() {
                        Some(fd) => (qualified, fd),
                        None => {
                            return Err(IrError::UnsupportedOperation(
                                format!("function `{name}` is not defined"),
                                sp,
                            ));
                        }
                    }
                } else {
                    return Err(IrError::UnsupportedOperation(
                        format!("function `{name}` is not defined"),
                        sp,
                    ));
                }
            }
        };

        let mut arg_vars: Vec<SsaVar> = args
            .iter()
            .map(|a| self.lower_expr(a))
            .collect::<Result<_, _>>()?;

        if arg_vars.len() != fn_def.params.len() {
            return Err(IrError::WrongArgumentCount {
                builtin: name.to_string(),
                expected: fn_def.params.len(),
                got: arg_vars.len(),
                span: sp,
            });
        }

        // Validate typed params against argument types, enforce Bool on untyped args
        for (param, arg_var) in fn_def.params.iter().zip(arg_vars.iter_mut()) {
            if let Some(ref ann) = param.type_ann {
                let declared = annotation_to_ir_type(ann);
                if let Some(inferred) = self.program.get_type(*arg_var) {
                    if !type_compatible(declared, inferred) {
                        return Err(IrError::AnnotationMismatch {
                            name: param.name.clone(),
                            declared: declared.to_string(),
                            inferred: inferred.to_string(),
                            span: sp.clone(),
                        });
                    }
                } else if declared == IrType::Bool {
                    // Untyped arg passed to Bool param — emit RangeCheck enforcement
                    let enforced = self.program.fresh_var();
                    self.program.push(Instruction::RangeCheck {
                        result: enforced,
                        operand: *arg_var,
                        bits: 1,
                    });
                    self.program.set_type(enforced, IrType::Bool);
                    *arg_var = enforced;
                }
            }
        }

        // Recursion guard
        if self.call_stack.contains(&resolved_name) {
            return Err(IrError::RecursiveFunction(resolved_name));
        }
        self.call_stack.insert(resolved_name.clone());

        // Save env for params and bind args
        let param_names: Vec<String> = fn_def.params.iter().map(|p| p.name.clone()).collect();
        let saved: Vec<(String, Option<EnvValue>)> = param_names
            .iter()
            .map(|p| (p.clone(), self.env.get(p).cloned()))
            .collect();
        for (param, arg) in param_names.iter().zip(arg_vars.iter()) {
            self.env.insert(param.clone(), EnvValue::Scalar(*arg));
        }

        // Set fn_call_prefix so unqualified calls inside the body resolve
        // to the same module (e.g., helper() → mod::helper when inlining mod::func)
        let old_prefix = self.fn_call_prefix.take();
        if let Some(pos) = resolved_name.find("::") {
            self.fn_call_prefix = Some(resolved_name[..pos].to_string());
        }

        // Lower the function body directly (no re-parsing!)
        let mut result = self.lower_block(&fn_def.body)?;

        // Set return type if declared
        if let Some(ref ret_ann) = fn_def.return_type {
            let ret_ty = annotation_to_ir_type(ret_ann);
            if let Some(inferred) = self.program.get_type(result) {
                if !type_compatible(ret_ty, inferred) {
                    return Err(IrError::AnnotationMismatch {
                        name: format!("{resolved_name}() return"),
                        declared: ret_ty.to_string(),
                        inferred: inferred.to_string(),
                        span: sp.clone(),
                    });
                }
                self.program.set_type(result, ret_ty);
            } else if ret_ty == IrType::Bool {
                // Untyped return value with Bool return type — emit enforcement
                let enforced = self.program.fresh_var();
                self.program.push(Instruction::RangeCheck {
                    result: enforced,
                    operand: result,
                    bits: 1,
                });
                self.program.set_type(enforced, IrType::Bool);
                result = enforced;
            } else {
                self.program.set_type(result, ret_ty);
            }
        }

        // Restore env and fn_call_prefix
        for (param, old_val) in saved {
            match old_val {
                Some(v) => {
                    self.env.insert(param, v);
                }
                None => {
                    self.env.remove(&param);
                }
            }
        }
        self.fn_call_prefix = old_prefix;

        self.call_stack.remove(&resolved_name);
        Ok(result)
    }

    pub(super) fn lower_index(
        &mut self,
        object: &Expr,
        index: &Expr,
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        let sp = to_ir_span(span);
        let name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(IrError::UnsupportedOperation(
                    "indexing is only supported on array identifiers".into(),
                    sp,
                ));
            }
        };

        match self.env.get(&name).cloned() {
            Some(EnvValue::Array(elements)) => {
                let idx_var = self.lower_expr(index)?;
                let idx_fe = self.get_const_value(idx_var).ok_or_else(|| {
                    IrError::UnsupportedOperation(
                        "array index must be a compile-time constant in circuits (dynamic indexing would require expensive lookup arguments)".into(),
                        sp.clone(),
                    )
                })?;
                let idx = field_to_u64(&idx_fe).ok_or_else(|| {
                    IrError::UnsupportedOperation(
                        format!(
                            "array index for `{name}` is too large to represent (must fit in 64 bits)"
                        ),
                        sp.clone(),
                    )
                })? as usize;
                if idx >= elements.len() {
                    return Err(IrError::IndexOutOfBounds {
                        name,
                        index: idx,
                        length: elements.len(),
                        span: sp,
                    });
                }
                Ok(elements[idx])
            }
            Some(EnvValue::Scalar(_)) => Err(IrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: sp,
            }),
            None => Err(IrError::UndeclaredVariable(name, sp)),
        }
    }

    /// Lower `if cond { a } else { b }` as a MUX: `result = mux(cond, a, b)`.
    ///
    /// **Important**: Both branches are always fully lowered and all their
    /// constraints (assert_eq, assert, etc.) are emitted unconditionally.
    /// The MUX only selects which *value* to return. This is an inherent
    /// limitation of arithmetic circuits — there is no conditional execution.
    pub(super) fn lower_if(
        &mut self,
        condition: &Expr,
        then_block: &Block,
        else_branch: Option<&ElseBranch>,
    ) -> Result<SsaVar, IrError> {
        let cond = self.lower_expr(condition)?;
        let if_true = self.lower_block(then_block)?;

        let if_false = match else_branch {
            Some(ElseBranch::Block(block)) => self.lower_block(block)?,
            Some(ElseBranch::If(if_expr)) => self.lower_expr(if_expr)?,
            None => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::<F>::zero(),
                });
                v
            }
        };

        let v = self.program.fresh_var();
        self.program.push(Instruction::Mux {
            result: v,
            cond,
            if_true,
            if_false,
        });
        // Result type from branches if both agree
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

    pub(super) fn lower_for(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        match iterable {
            ForIterable::Range { start, end } => {
                let iterations = end.saturating_sub(*start);
                if iterations > super::MAX_UNROLL_ITERATIONS {
                    return Err(IrError::UnsupportedOperation(
                        format!(
                            "for loop range {start}..{end} has {iterations} iterations, \
                             exceeding the maximum of {}",
                            super::MAX_UNROLL_ITERATIONS
                        ),
                        to_ir_span(span),
                    ));
                }

                let mut last = None;
                for i in *start..*end {
                    let cv = self.program.fresh_var();
                    self.program.push(Instruction::Const {
                        result: cv,
                        value: FieldElement::<F>::from_u64(i),
                    });
                    self.env.insert(var.to_string(), EnvValue::Scalar(cv));
                    last = Some(self.lower_block(body)?);
                }

                self.env.remove(var);
                Ok(last.unwrap_or_else(|| {
                    let v = self.program.fresh_var();
                    self.program.push(Instruction::Const {
                        result: v,
                        value: FieldElement::<F>::zero(),
                    });
                    v
                }))
            }
            ForIterable::Expr(iterable_expr) => {
                let sp = to_ir_span(span);
                // Try to resolve as identifier → array
                let name = match iterable_expr.as_ref() {
                    Expr::Ident { name, .. } => Some(name.clone()),
                    _ => None,
                };
                if let Some(name) = name {
                    if let Some(EnvValue::Array(elems)) = self.env.get(&name).cloned() {
                        let mut last = None;
                        for elem_var in &elems {
                            self.env
                                .insert(var.to_string(), EnvValue::Scalar(*elem_var));
                            last = Some(self.lower_block(body)?);
                        }
                        self.env.remove(var);
                        return Ok(last.unwrap_or_else(|| {
                            let v = self.program.fresh_var();
                            self.program.push(Instruction::Const {
                                result: v,
                                value: FieldElement::<F>::zero(),
                            });
                            v
                        }));
                    }
                }
                Err(IrError::UnsupportedOperation(
                    "for loops in circuits require a literal range (e.g., 0..5) or an array (the loop must be fully unrolled at compile time)".into(),
                    sp,
                ))
            }
        }
    }

    pub(super) fn lower_block(&mut self, block: &Block) -> Result<SsaVar, IrError> {
        let outer_keys: HashSet<String> = self.env.keys().cloned().collect();
        let mut last_var = None;

        for stmt in &block.stmts {
            match stmt {
                Stmt::LetDecl {
                    name,
                    type_ann,
                    value,
                    span,
                    ..
                } => {
                    self.lower_let(name, type_ann.as_ref(), value, span)?;
                    last_var = None;
                }
                Stmt::Expr(expr) => {
                    last_var = Some(self.lower_expr(expr)?);
                }
                Stmt::FnDecl {
                    name,
                    params,
                    return_type,
                    body,
                    ..
                } => {
                    self.fn_table.insert(
                        name.clone(),
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                        },
                    );
                    last_var = None;
                }
                other => {
                    self.lower_stmt(other)?;
                    last_var = None;
                }
            }
        }

        self.env.retain(|k, _| outer_keys.contains(k));

        Ok(last_var.unwrap_or_else(|| {
            let v = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: v,
                value: FieldElement::<F>::zero(),
            });
            v
        }))
    }

    /// Square-and-multiply exponentiation in the IR.
    pub(super) fn pow_by_squaring(&mut self, base: SsaVar, exp: u64) -> Result<SsaVar, IrError> {
        if exp == 0 {
            let v = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: v,
                value: FieldElement::<F>::one(),
            });
            self.program.set_type(v, IrType::Field);
            return Ok(v);
        }
        if exp == 1 {
            return Ok(base);
        }

        let mut result = None;
        let mut current = base;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = Some(match result {
                    None => current,
                    Some(r) => {
                        let v = self.program.fresh_var();
                        self.program.push(Instruction::Mul {
                            result: v,
                            lhs: r,
                            rhs: current,
                        });
                        self.program.set_type(v, IrType::Field);
                        v
                    }
                });
            }
            e >>= 1;
            if e > 0 {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Mul {
                    result: v,
                    lhs: current,
                    rhs: current,
                });
                self.program.set_type(v, IrType::Field);
                current = v;
            }
        }
        Ok(result.unwrap())
    }

    /// Look up the constant value of an SSA variable (if it was defined by a Const instruction).
    pub(super) fn get_const_value(&self, var: SsaVar) -> Option<FieldElement<F>> {
        for inst in &self.program.instructions {
            if let Instruction::Const { result, value } = inst {
                if *result == var {
                    return Some(*value);
                }
            }
        }
        None
    }

    /// Emit a constant field element and return its SSA variable.
    pub(super) fn emit_const(&mut self, value: FieldElement<F>) -> SsaVar {
        let v = self.program.fresh_var();
        self.program.push(Instruction::Const { result: v, value });
        v
    }

    /// Resolve a call argument to either Scalar or Array.
    pub(super) fn resolve_arg_value(&mut self, expr: &Expr) -> Result<EnvValue, IrError> {
        // Check if the argument is a bare identifier referencing an array
        if let Expr::Ident { name, .. } = expr {
            if let Some(ev) = self.env.get(name) {
                return Ok(ev.clone());
            }
        }
        // Otherwise lower as scalar expression
        let v = self.lower_expr(expr)?;
        Ok(EnvValue::Scalar(v))
    }
}
