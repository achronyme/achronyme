//! Expression compilation on [`ProveIrCompiler`].
//!
//! 17 methods that turn an AST [`Expr`] into a [`CircuitExpr`]:
//!
//! - **dispatch** — `compile_expr` (the big match on every Expr variant).
//! - **literal/atom helpers** — `compile_number`, `compile_field_lit`,
//!   `compile_ident`.
//! - **control flow** — `compile_if_expr`, `compile_for_expr`,
//!   `compile_index`, `compile_block_as_expr`.
//! - **user-fn inlining** — `compile_user_fn_call`, `bind_array_fn_param`.
//! - **arithmetic / boolean / comparison** — `compile_binop`,
//!   `compile_arith_binop`, `compile_comparison`, `compile_bool_binop`,
//!   `compile_pow`, `compile_unary`, `extract_const_u64`.
//!
//! Statement-level compilation lives in [`super::stmts`]; call dispatch
//! and builtin lowering in [`super::calls`]; method lookups in
//! [`super::methods`].

use std::collections::{BTreeSet, HashMap, HashSet};

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::{FieldBackend, FieldElement};

use super::helpers::to_span;
use super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

mod atoms;

impl<F: FieldBackend> ProveIrCompiler<F> {
    // -----------------------------------------------------------------------
    // Statement compilation
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Expression compilation
    // -----------------------------------------------------------------------

    /// Compile an AST expression into a `CircuitExpr`.
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<CircuitExpr, ProveIrError> {
        // Phase 3E.1: thread the current ExprId so the shadow-dispatch
        // hooks in compile_ident / compile_named_call can read it off
        // the compiler. Mirrors the VM compiler's pattern in
        // `compiler/src/expressions/mod.rs::compile_expr`. We don't
        // need the previous id for scoping because compile_expr is
        // the only site that writes the field, and each recursive
        // call re-overrides it before any hook reads it.
        self.current_expr_id = Some(expr.id());
        match expr {
            Expr::Number { value, span, .. } => self.compile_number(value, span),
            Expr::FieldLit {
                value, radix, span, ..
            } => self.compile_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => Ok(CircuitExpr::Const(FieldConst::one())),
            Expr::Bool { value: false, .. } => Ok(CircuitExpr::Const(FieldConst::zero())),
            Expr::Ident { name, span, .. } => self.compile_ident(name, span),

            Expr::BinOp {
                op, lhs, rhs, span, ..
            } => self.compile_binop(op, lhs, rhs, span),
            Expr::UnaryOp {
                op, operand, span, ..
            } => self.compile_unary(op, operand, span),

            Expr::StaticAccess {
                type_name,
                member,
                span,
                ..
            } => self.compile_static_access(type_name, member, span),

            Expr::Call {
                callee, args, span, ..
            } => {
                let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                self.compile_call(callee, &arg_vals, span)
            }

            Expr::DotAccess {
                object,
                field,
                span,
                ..
            } => self.compile_dot_access(object, field, span),

            Expr::If {
                condition,
                then_block,
                else_branch,
                span,
                ..
            } => self.compile_if_expr(condition, then_block, else_branch.as_ref(), span),

            Expr::For {
                var,
                iterable,
                body,
                span,
                ..
            } => self.compile_for_expr(var, iterable, body, span),

            Expr::Block { block, .. } => self.compile_block_as_expr(block),

            Expr::Index {
                object,
                index,
                span,
                ..
            } => self.compile_index(object, index, span),

            // --- Rejections (same as IrLowering, with better messages) ---
            Expr::While { span, .. } | Expr::Forever { span, .. } => {
                Err(ProveIrError::UnboundedLoop {
                    span: to_span(span),
                })
            }
            Expr::Prove { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "prove blocks cannot be nested inside circuits".into(),
                span: to_span(span),
            }),
            // CircuitCall removed — keyword-arg calls are now unified in Call
            Expr::FnExpr { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "closures are not supported in circuits \
                              (use named fn declarations instead)"
                    .into(),
                span: to_span(span),
            }),
            Expr::StringLit { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "string".into(),
                span: to_span(span),
            }),
            Expr::Nil { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "nil".into(),
                span: to_span(span),
            }),
            Expr::Map { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "map".into(),
                span: to_span(span),
            }),
            Expr::BigIntLit { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            Expr::Array { span, .. } => Err(ProveIrError::TypeMismatch {
                expected: "scalar expression".into(),
                got: "array literal (use let binding for arrays)".into(),
                span: to_span(span),
            }),
            Expr::Error { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "cannot compile error placeholder (source has parse errors)".into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Static access (Type::MEMBER)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Dot access (non-call)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------

    pub(super) fn compile_if_expr(
        &mut self,
        condition: &Expr,
        then_block: &Block,
        else_branch: Option<&ElseBranch>,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let cond = self.compile_expr(condition)?;

        // Bind condition to a temporary to avoid duplicating it in both
        // the CircuitNode::If and the Mux (which would double constraint cost).
        let cond_var = format!("$cond{}", self.inline_counter);
        self.inline_counter = self.inline_counter.wrapping_add(1);
        self.body.push(CircuitNode::Let {
            name: cond_var.clone(),
            value: cond,
            span: Some(SpanRange::from(span)),
        });
        let cond_ref = CircuitExpr::Var(cond_var);

        // Save body vec, compile then/else into separate buffers
        let saved_body = std::mem::take(&mut self.body);

        // Then branch
        self.body = Vec::new();
        let then_result = self.compile_block_as_expr(then_block)?;
        let then_nodes = std::mem::take(&mut self.body);

        // Else branch
        self.body = Vec::new();
        let (else_result, else_nodes) = match else_branch {
            Some(ElseBranch::Block(block)) => {
                let r = self.compile_block_as_expr(block)?;
                (r, std::mem::take(&mut self.body))
            }
            Some(ElseBranch::If(if_expr)) => {
                let r = self.compile_expr(if_expr)?;
                (r, std::mem::take(&mut self.body))
            }
            None => (CircuitExpr::Const(FieldConst::zero()), Vec::new()),
        };

        // Restore body and emit the If node
        self.body = saved_body;

        // If both branches have side-effect nodes (Let, Assert, etc.),
        // emit them as a CircuitNode::If. The result values become
        // the Mux during instantiation (Phase B).
        if !then_nodes.is_empty() || !else_nodes.is_empty() {
            self.body.push(CircuitNode::If {
                cond: cond_ref.clone(),
                then_body: then_nodes,
                else_body: else_nodes,
                span: Some(SpanRange::from(span)),
            });
        }

        // The expression result is a Mux over the two branch results
        Ok(CircuitExpr::Mux {
            cond: Box::new(cond_ref),
            if_true: Box::new(then_result),
            if_false: Box::new(else_result),
        })
    }

    pub(super) fn compile_for_expr(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        /// Maximum number of iterations allowed for literal ranges.
        const MAX_LOOP_ITERATIONS: u64 = 1_000_000;

        // Carry-set detection: if the body re-assigns any mutable variable
        // declared *outside* this loop (and not redeclared / shadowed
        // inside), we must eager-unroll at lower time so each iteration's
        // SSA chain references the previous iteration's output. The default
        // path captures the body once with frozen SSA names, which would
        // silently drop the carry across iterations.
        //
        // Mirror of `circom/src/lowering/statements/loops.rs:body_writes_to_outer_scope_var`
        // adapted to the achronyme prove-block AST. Industry-standard pattern
        // — Noir, Leo, and Zokrates apply per-iteration SSA re-versioning
        // before emit; the canonical SSA representation of this construct is
        // a loop-header phi (Cytron et al. 1991) whose β-reduction over a
        // bounded literal range is the eager-unroll form (formally
        // equivalent for static ranges with no early exits).
        let carries = body_writes_to_outer_mut_var(body, &self.ssa_versions, var);

        let range = match iterable {
            ForIterable::Range { start, end } => {
                let iterations = end.saturating_sub(*start);
                if iterations > MAX_LOOP_ITERATIONS {
                    return Err(ProveIrError::RangeTooLarge {
                        iterations,
                        max: MAX_LOOP_ITERATIONS,
                        span: to_span(span),
                    });
                }
                ForRange::Literal {
                    start: *start,
                    end: *end,
                }
            }
            ForIterable::ExprRange { start, end } => {
                // Dynamic end bound: compile to WithCapture or WithExpr.
                // Simple capture name → WithCapture; expression → WithExpr.
                if let Expr::Ident { name, .. } = end.as_ref() {
                    if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Capture(_))) {
                        self.captured_names.insert(name.clone());
                        ForRange::WithCapture {
                            start: *start,
                            end_capture: name.clone(),
                        }
                    } else {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "dynamic loop bound `{name}` must be a captured variable \
                                 (from outer scope)"
                            ),
                            span: to_span(span),
                        });
                    }
                } else {
                    // Compile the end expression to a CircuitExpr
                    let end_circuit = self.compile_expr(end)?;
                    ForRange::WithExpr {
                        start: *start,
                        end_expr: Box::new(end_circuit),
                    }
                }
            }
            ForIterable::Expr(expr) => {
                // Must be an array identifier
                if let Expr::Ident { name, .. } = expr.as_ref() {
                    if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Array(_))) {
                        ForRange::Array(name.clone())
                    } else if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Capture(_)))
                    {
                        // Capture used as iterable — could be an array, defer to instantiation
                        ForRange::Array(name.clone())
                    } else {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "for loop iterable `{name}` must be an array or range \
                                 in circuits"
                            ),
                            span: to_span(span),
                        });
                    }
                } else {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "for loops in circuits require a literal range \
                                      (e.g., 0..5), a dynamic range (0..n), or an array"
                            .into(),
                        span: to_span(span),
                    });
                }
            }
        };

        // Carry-set + eager-unroll path: lower the body N times in place,
        // letting `ssa_versions` and `env` advance naturally per iteration.
        // Supported when the bound is statically resolvable at lower time
        // (literal range or array iteration where element names are
        // already in env). Dynamic-capture / expression bounds are
        // rejected — the same restriction Noir / Leo / Zokrates impose on
        // non-constant bounds in compiled circuits.
        if !carries.is_empty() {
            return match range {
                ForRange::Literal { start, end } => {
                    self.compile_for_eager_unroll(var, start, end, body, span)
                }
                ForRange::Array(arr_name) => {
                    self.compile_for_eager_unroll_array(var, &arr_name, body, span)
                }
                ForRange::WithCapture { .. } | ForRange::WithExpr { .. } => {
                    Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "for loop with mutable accumulator(s) {} requires a \
                             statically-known bound (literal range or array iteration); \
                             dynamic bounds (`0..n`) are not supported in this case. \
                             Use a literal bound or rewrite the loop without `mut` \
                             reassignment.",
                            format_carry_list(&carries)
                        ),
                        span: to_span(span),
                    })
                }
            };
        }

        // Save body, compile loop body into a separate buffer
        let saved_body = std::mem::take(&mut self.body);

        // Register loop var in env
        let saved_var = self.env.get(var).cloned();
        self.env
            .insert(var.to_string(), CompEnvValue::Scalar(var.to_string()));

        self.body = Vec::new();
        let _body_result = self.compile_block_as_expr(body)?;
        let loop_body = std::mem::take(&mut self.body);

        // Restore
        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }
        self.body = saved_body;

        // Emit the For node (preserved, unrolled during Phase B instantiation)
        self.body.push(CircuitNode::For {
            var: var.to_string(),
            range,
            body: loop_body,
            span: Some(SpanRange::from(span)),
        });

        // For loops don't produce a useful expression value in circuit context
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    /// Eager-unroll a `for` loop with literal bounds when the body
    /// carries mutable state across iterations. Lowers the body in place
    /// `end - start` times; each iteration calls `compile_block_as_expr`
    /// fresh, which advances `ssa_versions` and `env` so the next iter's
    /// `Var(name)` reads point at the previous iter's `Let("name$vK")`
    /// output. The natural SSA chain falls out of standard tree walking
    /// — same mechanism the circom Class A fix uses for var-accumulator
    /// escape.
    fn compile_for_eager_unroll(
        &mut self,
        var: &str,
        start: u64,
        end: u64,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let iterations = end.saturating_sub(start);
        const MAX_LOOP_ITERATIONS: u64 = 1_000_000;
        if iterations > MAX_LOOP_ITERATIONS {
            return Err(ProveIrError::RangeTooLarge {
                iterations,
                max: MAX_LOOP_ITERATIONS,
                span: to_span(span),
            });
        }

        // Save the loop var's prior binding (if any) so we can restore it
        // when the unroll exits — matches the rolled-loop scoping shape.
        let saved_var = self.env.get(var).cloned();

        for i in start..end {
            // Bind the loop var to the current const at lower time. Each
            // iteration emits its own Let so the inline body's `Var(var)`
            // reads resolve to a fresh const SSA at instantiate.
            self.body.push(CircuitNode::Let {
                name: var.to_string(),
                value: CircuitExpr::Const(FieldConst::from_u64(i)),
                span: Some(SpanRange::from(span)),
            });
            self.env
                .insert(var.to_string(), CompEnvValue::Scalar(var.to_string()));

            // Re-walk the source AST. ssa_versions advances on every
            // assignment to a mut var, so iter k+1 sees iter k's output
            // through env.
            let _result = self.compile_block_as_expr(body)?;
        }

        // Restore the loop var. Body-local mut decls (re-declared each
        // iter) are intentionally left in env at their last-iter binding;
        // post-loop reads of those names follow current rolled-loop
        // semantics (no scope reset).
        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }

        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    /// Eager-unroll counterpart of [`Self::compile_for_eager_unroll`] for
    /// array iteration (`for x in arr`). The element name list is
    /// already in env (populated by `compile_let` / `compile_mut_decl`
    /// when the array binding was lowered), so the iteration count is
    /// known statically here. Per iter, bind the loop var to one element
    /// name and re-walk the body.
    fn compile_for_eager_unroll_array(
        &mut self,
        var: &str,
        arr_name: &str,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let elem_names = match self.env.get(arr_name) {
            Some(CompEnvValue::Array(elems)) => elems.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "for loop iterable `{arr_name}` must be an array \
                         (eager-unroll path)"
                    ),
                    span: to_span(span),
                });
            }
        };

        let saved_var = self.env.get(var).cloned();

        for elem_name in &elem_names {
            // Bind the loop var to the current element's scalar name. No
            // intermediate Let needed — the element already lives in env
            // as a Scalar from the array's lowering, so a direct alias
            // entry suffices for the body's `Var(var)` reads.
            self.env
                .insert(var.to_string(), CompEnvValue::Scalar(elem_name.clone()));

            let _result = self.compile_block_as_expr(body)?;
        }

        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }

        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    pub(super) fn compile_index(
        &mut self,
        object: &Expr,
        index: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "indexing is only supported on array identifiers in circuits"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check the array exists
        if !matches!(
            self.env.get(name.as_str()),
            Some(CompEnvValue::Array(_)) | Some(CompEnvValue::Capture(_))
        ) {
            return Err(ProveIrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: to_span(span),
            });
        }

        // Try to resolve as a constant index → direct element access
        if let Expr::Number { value, .. } = index {
            if let Ok(idx) = value.parse::<usize>() {
                if let Some(CompEnvValue::Array(elems)) = self.env.get(name.as_str()) {
                    if idx >= elems.len() {
                        return Err(ProveIrError::IndexOutOfBounds {
                            name: name.clone(),
                            index: idx,
                            length: elems.len(),
                            span: to_span(span),
                        });
                    }
                    return Ok(CircuitExpr::Var(elems[idx].clone()));
                }
            }
        }

        // Dynamic or capture-based index → ArrayIndex node
        let idx_expr = self.compile_expr(index)?;
        Ok(CircuitExpr::ArrayIndex {
            array: name,
            index: Box::new(idx_expr),
        })
    }

    // -----------------------------------------------------------------------
    // User function inlining
    // -----------------------------------------------------------------------

    pub(super) fn compile_user_fn_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let fn_def =
            self.fn_table
                .get(name)
                .cloned()
                .ok_or_else(|| ProveIrError::UndeclaredVariable {
                    name: name.into(),
                    span: to_span(span),
                    suggestion: None,
                })?;

        // Phase 4: reject Vm-only functions inside prove/circuit blocks.
        if let Some(avail) = fn_def.availability {
            if !avail.includes_prove_ir() {
                return Err(ProveIrError::VmOnlyFunction {
                    name: name.into(),
                    span: to_span(span),
                });
            }
        }

        // Arity check
        if args.len() != fn_def.params.len() {
            return Err(ProveIrError::WrongArgumentCount {
                name: name.into(),
                expected: fn_def.params.len(),
                got: args.len(),
                span: to_span(span),
            });
        }

        // Recursion guard
        if self.call_stack.contains(name) {
            return Err(ProveIrError::RecursiveFunction { name: name.into() });
        }
        self.call_stack.insert(name.to_string());

        // Phase 3F — gap 2.4 structural fix: push the definer's
        // module onto the resolver module stack before compiling the
        // inlined body. Both the annotation-driven dispatch path and
        // the legacy name-based path land here, so all inlined bodies
        // consistently resolve bare identifiers against their
        // definer's scope. `owner_module` is embedded in FnDef at
        // registration time from the dispatch maps.
        let module_pushed = fn_def
            .owner_module
            .map(|module| {
                self.resolver_module_stack.push(module);
                true
            })
            .unwrap_or(false);

        // Save env for param names (+ array element names) and bind args
        let param_names: Vec<String> = fn_def.params.iter().map(|p| p.name.clone()).collect();

        // Collect all names that might be shadowed (param names + element names
        // for array params) so we can restore them after inlining.
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

        // Use a unique invocation counter to avoid name collisions when the
        // same function is inlined multiple times.
        let invoke_id = self.inline_counter;
        self.inline_counter = self.inline_counter.wrapping_add(1);

        // Emit Let/LetArray nodes for each parameter binding.
        for (i, (param, arg)) in param_names.iter().zip(args.iter()).enumerate() {
            let is_array_param = fn_def.params[i]
                .type_ann
                .as_ref()
                .and_then(|ta| ta.array_size)
                .is_some();

            if is_array_param {
                // Array parameter: resolve the argument as an array identifier
                // and create SSA copies of each element.
                self.bind_array_fn_param(name, invoke_id, param, arg, span)?;
            } else {
                // Scalar parameter: compile as expression and bind.
                let compiled = self.compile_expr(arg)?;
                let param_ssa = format!("__{name}${invoke_id}_{param}");
                self.body.push(CircuitNode::Let {
                    name: param_ssa.clone(),
                    value: compiled,
                    span: Some(SpanRange::from(span)),
                });
                self.env
                    .insert(param.clone(), CompEnvValue::Scalar(param_ssa));
            }
        }

        // Compile the function body, collecting the result
        let result = self.compile_block_as_expr(&fn_def.body)?;

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

        // Phase 3F: pop the definer's module we pushed above.
        // Paired with the push so the stack stays balanced across
        // nested inlinings. Only executes when we actually pushed —
        // see the `module_pushed` discussion above.
        if module_pushed {
            self.resolver_module_stack.pop();
        }

        self.call_stack.remove(name);
        Ok(result)
    }

    /// Bind an array parameter for function inlining.
    ///
    /// Resolves the argument as an array name in the environment, creates
    /// SSA-renamed copies of each element, and registers the parameter as
    /// `CompEnvValue::Array` in the env.
    pub(super) fn bind_array_fn_param(
        &mut self,
        fn_name: &str,
        invoke_id: u32,
        param_name: &str,
        arg: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let arg_ident = match arg {
            Expr::Ident { name, .. } => name.as_str(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "array argument for parameter `{param_name}` must be a variable name, \
                         not an expression"
                    ),
                    span: to_span(span),
                });
            }
        };

        let src_elems = match self.env.get(arg_ident) {
            Some(CompEnvValue::Array(elems)) => elems.clone(),
            Some(CompEnvValue::Capture(_)) => {
                // Captured array from outer scope — look up the capture's
                // element names which follow the convention `name_0`, `name_1`, etc.
                // The outer scope must have provided an array-size entry.
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "captured array `{arg_ident}` cannot be passed directly as a parameter; \
                         bind it to a local array first: `let local = {arg_ident}`"
                    ),
                    span: to_span(span),
                });
            }
            _ => {
                return Err(ProveIrError::TypeMismatch {
                    expected: "array".into(),
                    got: "scalar".into(),
                    span: to_span(span),
                });
            }
        };

        let base_ssa = format!("__{fn_name}${invoke_id}_{param_name}");
        let new_elem_names: Vec<String> = (0..src_elems.len())
            .map(|j| format!("{base_ssa}_{j}"))
            .collect();

        // Emit LetArray node with references to the source elements.
        let elem_exprs: Vec<CircuitExpr> = src_elems
            .iter()
            .map(|e| match self.env.get(e) {
                Some(CompEnvValue::Scalar(s)) => CircuitExpr::Var(s.clone()),
                Some(CompEnvValue::Capture(c)) => {
                    self.captured_names.insert(c.clone());
                    CircuitExpr::Capture(c.clone())
                }
                _ => CircuitExpr::Var(e.clone()),
            })
            .collect();

        self.body.push(CircuitNode::LetArray {
            name: base_ssa.clone(),
            elements: elem_exprs,
            span: Some(SpanRange::from(span)),
        });

        // Register each element as Scalar and the array in env.
        for ename in &new_elem_names {
            self.env
                .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
        }
        self.env
            .insert(param_name.to_string(), CompEnvValue::Array(new_elem_names));

        Ok(())
    }

    /// Compile a block of statements and return the result of the last expression.
    /// Intermediate statements (Let, AssertEq, etc.) are appended to self.body.
    /// The last expression statement becomes the return value.
    /// If the block has no expression result, returns Const(ZERO).
    pub(super) fn compile_block_as_expr(
        &mut self,
        block: &Block,
    ) -> Result<CircuitExpr, ProveIrError> {
        let stmts = &block.stmts;
        if stmts.is_empty() {
            return Ok(CircuitExpr::Const(FieldConst::zero()));
        }

        // Compile all but the last statement normally
        for stmt in &stmts[..stmts.len() - 1] {
            // Handle Return inside function body
            if let Stmt::Return { value, .. } = stmt {
                return match value {
                    Some(expr) => self.compile_expr(expr),
                    None => Ok(CircuitExpr::Const(FieldConst::zero())),
                };
            }
            self.compile_stmt(stmt)?;
        }

        // The last statement: if it's an Expr, return its value; otherwise compile and return ZERO
        let last = &stmts[stmts.len() - 1];
        match last {
            Stmt::Expr(expr) => self.compile_expr(expr),
            Stmt::Return { value, .. } => match value {
                Some(expr) => self.compile_expr(expr),
                None => Ok(CircuitExpr::Const(FieldConst::zero())),
            },
            other => {
                self.compile_stmt(other)?;
                Ok(CircuitExpr::Const(FieldConst::zero()))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Binary operations
    // -----------------------------------------------------------------------

    pub(super) fn compile_binop(
        &mut self,
        op: &BinOp,
        lhs: &Expr,
        rhs: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match op {
            // Arithmetic → CircuitBinOp
            BinOp::Add => self.compile_arith_binop(CircuitBinOp::Add, lhs, rhs),
            BinOp::Sub => self.compile_arith_binop(CircuitBinOp::Sub, lhs, rhs),
            BinOp::Mul => self.compile_arith_binop(CircuitBinOp::Mul, lhs, rhs),
            BinOp::Div => self.compile_arith_binop(CircuitBinOp::Div, lhs, rhs),

            // Comparisons → CircuitCmpOp
            BinOp::Eq => self.compile_comparison(CircuitCmpOp::Eq, lhs, rhs),
            BinOp::Neq => self.compile_comparison(CircuitCmpOp::Neq, lhs, rhs),
            BinOp::Lt => self.compile_comparison(CircuitCmpOp::Lt, lhs, rhs),
            BinOp::Le => self.compile_comparison(CircuitCmpOp::Le, lhs, rhs),
            BinOp::Gt => self.compile_comparison(CircuitCmpOp::Gt, lhs, rhs),
            BinOp::Ge => self.compile_comparison(CircuitCmpOp::Ge, lhs, rhs),

            // Boolean → CircuitBoolOp
            BinOp::And => self.compile_bool_binop(CircuitBoolOp::And, lhs, rhs),
            BinOp::Or => self.compile_bool_binop(CircuitBoolOp::Or, lhs, rhs),

            // Mod → error
            BinOp::Mod => Err(ProveIrError::UnsupportedOperation {
                description: "modulo (%) is not supported in circuits \
                              (no efficient field arithmetic equivalent — use range_check)"
                    .into(),
                span: to_span(span),
            }),

            // Pow → CircuitExpr::Pow (exponent must be a constant)
            BinOp::Pow => self.compile_pow(lhs, rhs, span),
        }
    }

    pub(super) fn compile_arith_binop(
        &mut self,
        op: CircuitBinOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::BinOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    pub(super) fn compile_comparison(
        &mut self,
        op: CircuitCmpOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::Comparison {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    pub(super) fn compile_bool_binop(
        &mut self,
        op: CircuitBoolOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::BoolOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    pub(super) fn compile_pow(
        &mut self,
        base_expr: &Expr,
        exp_expr: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let base = self.compile_expr(base_expr)?;
        let exp = self.extract_const_u64(exp_expr, span)?;
        Ok(CircuitExpr::Pow {
            base: Box::new(base),
            exp,
        })
    }

    /// Try to extract a constant u64 from an expression (for exponents, range_check bits, etc.)
    pub(super) fn extract_const_u64(&self, expr: &Expr, span: &Span) -> Result<u64, ProveIrError> {
        match expr {
            Expr::Number { value, .. } => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "expected a non-negative integer constant, got `{value}`"
                        ),
                        span: to_span(span),
                    })?;
                Ok(n)
            }
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "exponent must be a constant integer in circuits \
                     (x^n is unrolled to n multiplications at compile time)"
                    .into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Unary operations
    // -----------------------------------------------------------------------

    pub(super) fn compile_unary(
        &mut self,
        op: &UnaryOp,
        operand: &Expr,
        _span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Double negation / double NOT cancellation: --x → x, !!x → x
        if let Expr::UnaryOp {
            op: inner_op,
            operand: inner_operand,
            ..
        } = operand
        {
            if inner_op == op {
                return self.compile_expr(inner_operand);
            }
        }

        let inner = self.compile_expr(operand)?;
        let circuit_op = match op {
            UnaryOp::Neg => CircuitUnaryOp::Neg,
            UnaryOp::Not => CircuitUnaryOp::Not,
        };
        Ok(CircuitExpr::UnaryOp {
            op: circuit_op,
            operand: Box::new(inner),
        })
    }
}

// ---------------------------------------------------------------------------
// Carry-set detection for `for` loops with mutable accumulators.
//
// Returns the deterministically-sorted list of mutable variable names
// declared *outside* the body that the body re-assigns. An empty result
// means the body is safe for the rolled-loop path; a non-empty result
// means `compile_for_expr` must eager-unroll at lower (literal range) or
// reject (dynamic range).
//
// Mirrors `circom/src/lowering/statements/loops.rs::body_writes_to_outer_scope_var`
// adapted to the achronyme prove-block AST (`achronyme_parser::ast::Stmt`,
// `Expr`, `Block`). The detection is the same two-phase shape:
//
//   1. Collect every name declared inside the body — recursively
//      descending into nested if/else, for, while, forever, block.
//   2. Walk every assignment in the body. A target whose name is (a) in
//      the outer `ssa_versions` map (declared with `mut` outside),
//      (b) not in the body's local declaration set, and (c) not the
//      loop variable, is a carry.
//
// The walk stays purely structural — no type-checking, no constant
// folding. An identifier-target lookup against `ssa_versions` is the
// authoritative "declared with mut in outer scope" predicate because
// `compile_mut_decl` is the only path that inserts into `ssa_versions`.
// ---------------------------------------------------------------------------

fn body_writes_to_outer_mut_var(
    body: &Block,
    ssa_versions: &HashMap<String, u32>,
    loop_var: &str,
) -> Vec<String> {
    let mut body_decls: HashSet<String> = HashSet::new();
    collect_block_decls(body, &mut body_decls);

    let mut out: BTreeSet<String> = BTreeSet::new();
    walk_block_writes(body, ssa_versions, &body_decls, loop_var, &mut out);
    out.into_iter().collect()
}

fn format_carry_list(carries: &[String]) -> String {
    let quoted: Vec<String> = carries.iter().map(|n| format!("`{n}`")).collect();
    quoted.join(", ")
}

/// Collect every binding name introduced inside this block — let, mut,
/// fn parameters, and any nested control-flow bodies. Used to mask
/// inner-shadowed names from the carry-set: if the loop body redeclares
/// `acc`, writes to that inner `acc` are not carries.
fn collect_block_decls(block: &Block, acc: &mut HashSet<String>) {
    for stmt in &block.stmts {
        collect_stmt_decls(stmt, acc);
    }
}

fn collect_stmt_decls(stmt: &Stmt, acc: &mut HashSet<String>) {
    match stmt {
        Stmt::LetDecl { name, value, .. } | Stmt::MutDecl { name, value, .. } => {
            acc.insert(name.clone());
            collect_expr_decls(value, acc);
        }
        Stmt::FnDecl {
            name, params, body, ..
        } => {
            acc.insert(name.clone());
            for p in params {
                acc.insert(p.name.clone());
            }
            collect_block_decls(body, acc);
        }
        Stmt::Assignment { value, .. } => collect_expr_decls(value, acc),
        Stmt::Print { value, .. } => collect_expr_decls(value, acc),
        Stmt::Return { value: Some(v), .. } => collect_expr_decls(v, acc),
        Stmt::Export { inner, .. } => collect_stmt_decls(inner, acc),
        Stmt::Expr(e) => collect_expr_decls(e, acc),
        // Top-level / module-level declarations and parse-error
        // placeholders carry no body-local binding semantics for our
        // purposes here.
        _ => {}
    }
}

fn collect_expr_decls(expr: &Expr, acc: &mut HashSet<String>) {
    match expr {
        Expr::If {
            then_block,
            else_branch,
            ..
        } => {
            collect_block_decls(then_block, acc);
            match else_branch {
                Some(ElseBranch::Block(b)) => collect_block_decls(b, acc),
                Some(ElseBranch::If(e)) => collect_expr_decls(e, acc),
                None => {}
            }
        }
        Expr::For { var, body, .. } => {
            // The inner loop's induction var is body-local relative to
            // *that* loop. For the outer-loop carry analysis, treat it
            // as introduced inside the body.
            acc.insert(var.clone());
            collect_block_decls(body, acc);
        }
        Expr::While { body, .. } | Expr::Forever { body, .. } => {
            collect_block_decls(body, acc);
        }
        Expr::Block { block, .. } => collect_block_decls(block, acc),
        Expr::FnExpr { params, body, .. } => {
            for p in params {
                acc.insert(p.name.clone());
            }
            collect_block_decls(body, acc);
        }
        // Other expression variants don't introduce bindings; their
        // sub-expressions are scanned only if they could host one of
        // the above (covered by the recursive variants).
        _ => {}
    }
}

fn walk_block_writes(
    block: &Block,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    for stmt in &block.stmts {
        walk_stmt_writes(stmt, ssa_versions, body_decls, loop_var, out);
    }
}

fn walk_stmt_writes(
    stmt: &Stmt,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    match stmt {
        // Indexed assignments (`arr[i] = ...`) are handled by a separate
        // lowering path (`compile_indexed_assignment`) that emits
        // `LetIndexed`, not SSA-versioned `Let`. They don't share the
        // per-iter SSA-rebind shape, so they are intentionally not
        // treated as carries here.
        Stmt::Assignment {
            target: Expr::Ident { name, .. },
            ..
        } if name != loop_var && ssa_versions.contains_key(name) && !body_decls.contains(name) => {
            out.insert(name.clone());
        }
        Stmt::Expr(e) => walk_expr_writes(e, ssa_versions, body_decls, loop_var, out),
        Stmt::Print { value, .. } => {
            walk_expr_writes(value, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::Return { value: Some(v), .. } => {
            walk_expr_writes(v, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => {
            walk_expr_writes(value, ssa_versions, body_decls, loop_var, out)
        }
        Stmt::Export { inner, .. } => {
            walk_stmt_writes(inner, ssa_versions, body_decls, loop_var, out)
        }
        _ => {}
    }
}

fn walk_expr_writes(
    expr: &Expr,
    ssa_versions: &HashMap<String, u32>,
    body_decls: &HashSet<String>,
    loop_var: &str,
    out: &mut BTreeSet<String>,
) {
    match expr {
        Expr::If {
            then_block,
            else_branch,
            ..
        } => {
            walk_block_writes(then_block, ssa_versions, body_decls, loop_var, out);
            match else_branch {
                Some(ElseBranch::Block(b)) => {
                    walk_block_writes(b, ssa_versions, body_decls, loop_var, out)
                }
                Some(ElseBranch::If(e)) => {
                    walk_expr_writes(e, ssa_versions, body_decls, loop_var, out)
                }
                None => {}
            }
        }
        Expr::For { body, .. } | Expr::While { body, .. } | Expr::Forever { body, .. } => {
            walk_block_writes(body, ssa_versions, body_decls, loop_var, out);
        }
        Expr::Block { block, .. } => {
            walk_block_writes(block, ssa_versions, body_decls, loop_var, out)
        }
        // Other expression variants don't host assignments directly.
        _ => {}
    }
}
