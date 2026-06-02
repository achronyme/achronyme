use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(in crate::ast_lower) fn compile_let(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Circom template call bound to a let: `let r = T(args)(inputs)`.
        // Must run before the scalar fall-through so multi-output and
        // array-output templates can bind per-output env entries that
        // compile_dot_access will later resolve as `r.out_name`.
        if self.compile_let_for_circom_call(name, value, span)? {
            return Ok(());
        }

        // decompose(value, bits) → Decompose node (creates array of bit vars)
        if let Expr::Call { callee, args, .. } = value {
            if let Expr::Ident { name: fn_name, .. } = callee.as_ref() {
                if fn_name == "decompose" {
                    let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                    self.check_arity("decompose", 2, arg_vals.len(), span)?;
                    let compiled_value = self.compile_expr(arg_vals[0])?;
                    let num_bits = self.extract_const_u64(arg_vals[1], span)? as u32;

                    let elem_names: Vec<String> =
                        (0..num_bits).map(|i| format!("{name}_{i}")).collect();

                    self.body.push(CircuitNode::Decompose {
                        name: name.to_string(),
                        value: compiled_value,
                        num_bits,
                        span: Some(SpanRange::from(span)),
                    });

                    for ename in &elem_names {
                        self.env
                            .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                    }
                    self.env
                        .insert(name.to_string(), CompEnvValue::Array(elem_names));
                    return Ok(());
                }
            }
        }

        // Array literal → LetArray
        if let Expr::Array {
            elements,
            span: arr_span,
            ..
        } = value
        {
            if elements.is_empty() {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "empty arrays are not allowed in circuits".into(),
                    span: to_span(arr_span),
                });
            }
            let compiled: Result<Vec<_>, _> =
                elements.iter().map(|e| self.compile_expr(e)).collect();
            let compiled = compiled?;
            let elem_names: Vec<String> =
                (0..compiled.len()).map(|i| format!("{name}_{i}")).collect();
            self.body.push(CircuitNode::LetArray {
                name: name.to_string(),
                elements: compiled,
                span: Some(SpanRange::from(span)),
            });
            for ename in &elem_names {
                self.env
                    .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
            }
            self.env
                .insert(name.to_string(), CompEnvValue::Array(elem_names));
            return Ok(());
        }

        // Function call returning an array → inline the function and adopt
        // the resulting array under this binding's name.
        if let Some(result_array_name) =
            self.try_compile_array_fn_call(name, type_ann, value, span)?
        {
            // The function was inlined and created an array in the env under
            // an internal SSA name. Re-register it under the let-binding name.
            if let Some(CompEnvValue::Array(elems)) = self.env.get(&result_array_name).cloned() {
                // Create new element names under the let-binding name.
                let new_elem_names: Vec<String> =
                    (0..elems.len()).map(|i| format!("{name}_{i}")).collect();
                let elem_exprs: Vec<CircuitExpr> = elems
                    .iter()
                    .map(|e| match self.env.get(e) {
                        Some(CompEnvValue::Scalar(s)) => CircuitExpr::Var(s.clone()),
                        _ => CircuitExpr::Var(e.clone()),
                    })
                    .collect();
                self.body.push(CircuitNode::LetArray {
                    name: name.to_string(),
                    elements: elem_exprs,
                    span: Some(SpanRange::from(span)),
                });
                for ename in &new_elem_names {
                    self.env
                        .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                }
                self.env
                    .insert(name.to_string(), CompEnvValue::Array(new_elem_names));
                return Ok(());
            }
        }

        // Scalar value → Let
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: name.to_string(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });
        self.env
            .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
        Ok(())
    }

    /// Try to compile a function call that returns an array.
    ///
    /// Returns `Some(array_name_in_env)` if the call was handled as an
    /// array-returning function, or `None` if it should be compiled as a
    /// normal scalar expression.
    pub(in crate::ast_lower) fn try_compile_array_fn_call(
        &mut self,
        _let_name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<Option<String>, ProveIrError> {
        // Only handle direct named calls
        let (callee_name, args) = match value {
            Expr::Call { callee, args, .. } => {
                if let Expr::Ident { name, .. } = callee.as_ref() {
                    let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                    (name.as_str(), arg_vals)
                } else {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        };

        // Check if the function exists and has an array return type
        let fn_def = match self.fn_table.get(callee_name) {
            Some(fd) => fd.clone(),
            None => return Ok(None), // Not a user function (might be a builtin)
        };

        let has_array_return = fn_def
            .return_type
            .as_ref()
            .and_then(|ta| ta.array_size)
            .is_some();

        // Also check if the let-binding has an array type annotation
        let let_expects_array = type_ann.and_then(|ta| ta.array_size).is_some();

        if !has_array_return && !let_expects_array {
            return Ok(None);
        }

        // This is an array-returning function call. Inline it using the
        // same mechanism as compile_user_fn_call but capture the array result.

        // Arity check
        if args.len() != fn_def.params.len() {
            return Err(ProveIrError::WrongArgumentCount {
                name: callee_name.into(),
                expected: fn_def.params.len(),
                got: args.len(),
                span: to_span(span),
            });
        }

        // Recursion guard
        if self.call_stack.contains(callee_name) {
            return Err(ProveIrError::RecursiveFunction {
                name: callee_name.into(),
            });
        }
        self.call_stack.insert(callee_name.to_string());

        // Save env
        let param_names: Vec<String> = fn_def.params.iter().map(|p| p.name.clone()).collect();
        let mut all_shadow_names: Vec<String> = param_names.clone();
        for (i, param) in fn_def.params.iter().enumerate() {
            if let Some(ref ta) = param.type_ann {
                if let Some(size) = ta.array_size {
                    for j in 0..size {
                        all_shadow_names.push(format!("{}_{j}", param_names[i]));
                    }
                }
            }
        }
        let saved: Vec<(String, Option<CompEnvValue>)> = all_shadow_names
            .iter()
            .map(|p| (p.clone(), self.env.get(p).cloned()))
            .collect();

        let invoke_id = self.inline_counter;
        self.inline_counter = self.inline_counter.wrapping_add(1);

        // Bind parameters (array-aware)
        for (i, (param, arg)) in param_names.iter().zip(args.iter()).enumerate() {
            let is_array_param = fn_def.params[i]
                .type_ann
                .as_ref()
                .and_then(|ta| ta.array_size)
                .is_some();

            if is_array_param {
                self.bind_array_fn_param(callee_name, invoke_id, param, arg, span)?;
            } else {
                let compiled = self.compile_expr(arg)?;
                let param_ssa = format!("__{callee_name}${invoke_id}_{param}");
                self.body.push(CircuitNode::Let {
                    name: param_ssa.clone(),
                    value: compiled,
                    span: Some(SpanRange::from(span)),
                });
                self.env
                    .insert(param.clone(), CompEnvValue::Scalar(param_ssa));
            }
        }

        // Compile the function body — all statements except the last one
        // (which is the array return expression, not a real statement).
        let stmts = &fn_def.body.stmts;
        if !stmts.is_empty() {
            for stmt in &stmts[..stmts.len() - 1] {
                self.compile_stmt(stmt)?;
            }
        }

        // Find the array result: the last expression should be an array name.
        let result_array = self.find_array_result(stmts, span)?;

        // Restore env
        for (p, old_val) in saved {
            match old_val {
                Some(v) => {
                    self.env.insert(p, v);
                }
                None => {
                    self.env.remove(&p);
                }
            }
        }

        self.call_stack.remove(callee_name);
        Ok(Some(result_array))
    }

    /// Find the array name returned by the last statement/expression in a
    /// function body. The last statement should be either:
    /// - A bare `Expr::Ident` referencing an array
    /// - A `Stmt::Return` with an `Expr::Ident` referencing an array
    /// - Any other statement (compiled normally) followed by checking env
    pub(in crate::ast_lower) fn find_array_result(
        &mut self,
        stmts: &[Stmt],
        span: &Span,
    ) -> Result<String, ProveIrError> {
        let last = stmts
            .last()
            .ok_or_else(|| ProveIrError::UnsupportedOperation {
                description: "array-returning function has an empty body".into(),
                span: to_span(span),
            })?;

        // Extract the array identifier from the last statement
        let ident = match last {
            Stmt::Expr(Expr::Ident { name, .. }) => name.clone(),
            Stmt::Return {
                value: Some(Expr::Ident { name, .. }),
                ..
            } => name.clone(),
            // If the last statement is something else (e.g. a let that creates
            // the array), compile it and then we can't determine the name.
            other => {
                self.compile_stmt(other)?;
                return Err(ProveIrError::UnsupportedOperation {
                    description: "array-returning function must end with an array variable name \
                                  (e.g., `return arr` or just `arr`)"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        match self.env.get(ident.as_str()) {
            Some(CompEnvValue::Array(_)) => Ok(ident),
            _ => Err(ProveIrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: to_span(span),
            }),
        }
    }
}
