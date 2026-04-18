//! Statement-level compilation on [`ProveIrCompiler`].
//!
//! The 16 methods that walk a `Block` and lower each `Stmt` into the
//! ProveIR body. Cleanly split into:
//!
//! - **block walker** — `compile_block_stmts`, `compile_stmt`.
//! - **module imports** — `resolve_import_path`, `register_module_exports`,
//!   `compile_import`, `compile_selective_import`.
//! - **declarations** — `compile_public_decl`, `compile_witness_decl`,
//!   `compile_input_decl`, `compile_let`, `compile_mut_decl`.
//! - **assignments** — `compile_assignment`, `compile_indexed_assignment`.
//! - **expression-as-statement** — `compile_expr_stmt`.
//! - **array-fn helpers** — `try_compile_array_fn_call`, `find_array_result`.
//!
//! Expression compilation lives in [`super::exprs`]; call dispatch +
//! builtin lowering in [`super::calls`]; method lookups in
//! [`super::methods`].

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::helpers::{annotation_to_ir_type, to_span};
use super::{CompEnvValue, FnDef, ProveIrCompiler};
use crate::prove_ir::error::ProveIrError;
use crate::prove_ir::types::*;
use crate::types::IrType;

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Compile all statements in a block, appending to self.body.
    pub(super) fn compile_block_stmts(&mut self, block: &Block) -> Result<(), ProveIrError> {
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        Ok(())
    }

    /// Compile a single statement.
    pub(super) fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), ProveIrError> {
        match stmt {
            Stmt::PublicDecl { names, span } => self.compile_public_decl(names, span),
            Stmt::WitnessDecl { names, span } => self.compile_witness_decl(names, span),
            Stmt::LetDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => self.compile_let(name, type_ann.as_ref(), value, span),
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
                        owner_module: None,
                        availability: None,
                    },
                );
                Ok(())
            }
            Stmt::Expr(expr) => self.compile_expr_stmt(expr),
            Stmt::Export { inner, .. } => self.compile_stmt(inner),
            Stmt::ExportList { .. } | Stmt::Error { .. } => Ok(()),

            Stmt::MutDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => self.compile_mut_decl(name, type_ann.as_ref(), value, span),
            Stmt::Assignment {
                target,
                value,
                span,
            } => self.compile_assignment(target, value, span),
            Stmt::Print { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "print is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Break { span } => Err(ProveIrError::UnsupportedOperation {
                description: "break is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Continue { span } => Err(ProveIrError::UnsupportedOperation {
                description: "continue is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Return { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "return is not supported at the top level of a circuit".into(),
                span: to_span(span),
            }),
            Stmt::Import { path, alias, span } => self.compile_import(path, alias, span),
            Stmt::SelectiveImport { names, path, span } => {
                self.compile_selective_import(names, path, span)
            }
            Stmt::CircuitDecl { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "circuit declarations are not supported inside circuits".into(),
                span: to_span(span),
            }),
            Stmt::ImportCircuit { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "circuit imports are not supported inside circuits".into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Imports
    // -----------------------------------------------------------------------

    /// Resolve a relative import path against the source directory.
    pub(super) fn resolve_import_path(
        &self,
        path: &str,
        _span: &Span,
    ) -> Result<std::path::PathBuf, ProveIrError> {
        let base = self.source_dir.as_ref().ok_or_else(|| {
            ProveIrError::ModuleLoadError(
                "imports require a file path context (not available in inline prove blocks)".into(),
            )
        })?;
        let full_path = base.join(path);
        if !full_path.exists() {
            return Err(ProveIrError::ModuleNotFound(format!(
                "{} (resolved from {})",
                full_path.display(),
                path
            )));
        }
        full_path.canonicalize().map_err(|e| {
            ProveIrError::ModuleLoadError(format!("cannot resolve {}: {}", full_path.display(), e))
        })
    }

    /// Register exported functions from a module into fn_table with alias prefix.
    pub(super) fn register_module_exports(
        &mut self,
        alias: &str,
        module: &crate::module_loader::ModuleExports,
    ) {
        for stmt in &module.program.stmts {
            let inner = match stmt {
                Stmt::Export { inner, .. } => inner.as_ref(),
                other => other,
            };
            if let Stmt::FnDecl {
                name,
                params,
                body,
                return_type,
                ..
            } = inner
            {
                if module.exported_names.contains(name) {
                    let qualified = format!("{alias}::{name}");
                    self.fn_table.insert(
                        qualified,
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                            owner_module: None,
                            availability: None,
                        },
                    );
                }
            }
        }
    }

    /// `import "./module.ach" as alias`
    pub(super) fn compile_import(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let canonical = self.resolve_import_path(path, span)?;
        if self.compiling_modules.contains(&canonical) {
            return Err(ProveIrError::CircularImport(path.to_string()));
        }
        self.compiling_modules.insert(canonical.clone());
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(ProveIrError::ModuleLoadError)?;
        // Clone what we need before releasing the borrow on module_loader.
        let exported_names = module.exported_names.clone();
        let stmts = module.program.stmts.clone();
        let exports = crate::module_loader::ModuleExports {
            exported_names,
            program: achronyme_parser::ast::Program { stmts },
        };
        self.register_module_exports(alias, &exports);
        Ok(())
    }

    /// `import { fn1, fn2 } from "./module.ach"`
    pub(super) fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let canonical = self.resolve_import_path(path, span)?;
        if self.compiling_modules.contains(&canonical) {
            return Err(ProveIrError::CircularImport(path.to_string()));
        }
        self.compiling_modules.insert(canonical.clone());
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(ProveIrError::ModuleLoadError)?;
        let exported_names = module.exported_names.clone();
        let stmts = module.program.stmts.clone();

        // Validate requested names are actually exported
        for name in names {
            if !exported_names.contains(name) {
                return Err(ProveIrError::ModuleLoadError(format!(
                    "`{name}` is not exported from `{path}`"
                )));
            }
        }

        // Register each requested function directly (no alias prefix)
        for stmt in &stmts {
            let inner = match stmt {
                Stmt::Export { inner, .. } => inner.as_ref(),
                other => other,
            };
            if let Stmt::FnDecl {
                name,
                params,
                body,
                return_type,
                ..
            } = inner
            {
                if names.contains(name) {
                    self.fn_table.insert(
                        name.clone(),
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                            owner_module: None,
                            availability: None,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Public/Witness declarations
    // -----------------------------------------------------------------------

    pub(super) fn compile_public_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
    ) -> Result<(), ProveIrError> {
        self.compile_input_decl(names, span, true)
    }

    pub(super) fn compile_witness_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
    ) -> Result<(), ProveIrError> {
        self.compile_input_decl(names, span, false)
    }

    /// Shared implementation for public/witness input declarations.
    pub(super) fn compile_input_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
        is_public: bool,
    ) -> Result<(), ProveIrError> {
        for decl in names {
            // Check for duplicate declarations across both public and witness inputs.
            // We check the input lists directly (not self.env) because env also
            // contains captures from the outer scope, which are legitimately
            // "overridden" by an explicit public/witness declaration.
            let already_declared = self
                .public_inputs
                .iter()
                .chain(self.witness_inputs.iter())
                .any(|d| d.name == decl.name);
            if already_declared {
                return Err(ProveIrError::DuplicateInput {
                    name: decl.name.clone(),
                    span: to_span(span),
                });
            }

            let ir_type = decl
                .type_ann
                .as_ref()
                .map(annotation_to_ir_type)
                .unwrap_or(IrType::Field);

            let inputs = if is_public {
                &mut self.public_inputs
            } else {
                &mut self.witness_inputs
            };

            if let Some(size) = decl.array_size {
                inputs.push(ProveInputDecl {
                    name: decl.name.clone(),
                    array_size: Some(ArraySize::Literal(size)),
                    ir_type,
                });
                let elem_names: Vec<String> =
                    (0..size).map(|i| format!("{}_{i}", decl.name)).collect();
                for ename in &elem_names {
                    self.env
                        .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                }
                self.env
                    .insert(decl.name.clone(), CompEnvValue::Array(elem_names));
            } else {
                inputs.push(ProveInputDecl {
                    name: decl.name.clone(),
                    array_size: None,
                    ir_type,
                });
                self.env
                    .insert(decl.name.clone(), CompEnvValue::Scalar(decl.name.clone()));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Let declaration
    // -----------------------------------------------------------------------

    pub(super) fn compile_let(
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
    pub(super) fn try_compile_array_fn_call(
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
    pub(super) fn find_array_result(
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

    // -----------------------------------------------------------------------
    // Expression statement (handles assert_eq / assert as nodes)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Mut declaration (desugared to SSA)
    // -----------------------------------------------------------------------

    pub(super) fn compile_mut_decl(
        &mut self,
        name: &str,
        _type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array literal → mutable LetArray
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
            // Mark as mutable so arr[i] = expr is allowed
            self.ssa_versions.insert(name.to_string(), 0);
            return Ok(());
        }

        // Type annotations intentionally ignored (see compile_let).
        // Compile value and emit Let node (same as immutable let for v0)
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: name.to_string(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });
        // Register in env as the current name (v0 uses the original name)
        self.env
            .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
        // Mark as mutable with version 0
        self.ssa_versions.insert(name.to_string(), 0);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Assignment (desugared to SSA rebinding)
    // -----------------------------------------------------------------------

    pub(super) fn compile_assignment(
        &mut self,
        target: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array element assignment: arr[i] = expr → LetIndexed
        if let Expr::Index {
            object,
            index,
            span: idx_span,
            ..
        } = target
        {
            return self.compile_indexed_assignment(object, index, value, idx_span);
        }

        // Simple ident assignment: x = expr
        let name = match target {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "only simple variable or array element assignment \
                         is supported in circuits"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check that the variable was declared with mut
        let version = self.ssa_versions.get(&name).copied().ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!(
                    "cannot assign to `{name}` — it was not declared with `mut` \
                     (use `mut {name} = ...` to declare a mutable variable)"
                ),
                span: to_span(span),
            }
        })?;

        // Increment version (checked to avoid panic on theoretical overflow)
        let new_version =
            version
                .checked_add(1)
                .ok_or_else(|| ProveIrError::UnsupportedOperation {
                    description: format!(
                        "SSA version overflow for `{name}` — too many reassignments"
                    ),
                    span: to_span(span),
                })?;
        self.ssa_versions.insert(name.clone(), new_version);

        // Generate SSA name using $ separator (not valid in user identifiers).
        let ssa_name = format!("{name}$v{new_version}");

        // Compile the new value
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: ssa_name.clone(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });

        // Update env to point to the new SSA name
        self.env.insert(name, CompEnvValue::Scalar(ssa_name));
        Ok(())
    }

    /// Compile `arr[i] = expr` → `LetIndexed { array, index, value }`.
    pub(super) fn compile_indexed_assignment(
        &mut self,
        object: &Expr,
        index: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let array_name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "indexed assignment requires an array identifier \
                         (e.g., arr[i] = expr)"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check the array exists and is an array
        if !matches!(
            self.env.get(array_name.as_str()),
            Some(CompEnvValue::Array(_))
        ) {
            return Err(ProveIrError::TypeMismatch {
                expected: "mutable array".into(),
                got: "scalar or undeclared".into(),
                span: to_span(span),
            });
        }

        // Check the array was declared with mut
        if !self.ssa_versions.contains_key(&array_name) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "cannot assign to `{array_name}[..]` — array was not declared with `mut` \
                     (use `mut {array_name} = [...]` to declare a mutable array)"
                ),
                span: to_span(span),
            });
        }

        let compiled_index = self.compile_expr(index)?;
        let compiled_value = self.compile_expr(value)?;

        self.body.push(CircuitNode::LetIndexed {
            array: array_name,
            index: compiled_index,
            value: compiled_value,
            span: Some(SpanRange::from(span)),
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expression statement (handles assert_eq / assert as nodes)
    // -----------------------------------------------------------------------

    pub(super) fn compile_expr_stmt(&mut self, expr: &Expr) -> Result<(), ProveIrError> {
        // Detect assert_eq(a, b) and assert(x) to emit constraint nodes
        if let Expr::Call {
            callee, args, span, ..
        } = expr
        {
            let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
            if let Expr::Ident { name, .. } = callee.as_ref() {
                match name.as_str() {
                    "assert_eq" => {
                        self.check_assert_eq_arity(arg_vals.len(), span)?;
                        let lhs = self.compile_expr(arg_vals[0])?;
                        let rhs = self.compile_expr(arg_vals[1])?;
                        let message = self.extract_assert_message(arg_vals.get(2), span)?;
                        self.body.push(CircuitNode::AssertEq {
                            lhs,
                            rhs,
                            message,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    "assert" => {
                        self.check_assert_arity(arg_vals.len(), span)?;
                        let cond = self.compile_expr(arg_vals[0])?;
                        let message = self.extract_assert_message(arg_vals.get(1), span)?;
                        self.body.push(CircuitNode::Assert {
                            expr: cond,
                            message,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // General expression statement
        let compiled = self.compile_expr(expr)?;
        self.body.push(CircuitNode::Expr {
            expr: compiled,
            span: Some(SpanRange::from(expr.span())),
        });
        Ok(())
    }
}
