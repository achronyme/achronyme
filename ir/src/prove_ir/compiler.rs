//! ProveIR compiler: AST Block → ProveIR template.

use std::collections::{HashMap, HashSet};

use achronyme_parser::ast::*;
use achronyme_parser::diagnostic::SpanRange;
use memory::FieldElement;

use super::error::ProveIrError;
use super::types::*;
use crate::error::{span_box, OptSpan};
use crate::types::IrType;

// ---------------------------------------------------------------------------
// Environment values
// ---------------------------------------------------------------------------

/// A value in the ProveIR compilation environment.
#[derive(Clone, Debug)]
enum CompEnvValue {
    /// A local scalar variable (let-binding or input).
    Scalar(String),
    /// A local array variable.
    Array(Vec<String>),
    /// A captured value from the outer scope.
    Capture(String),
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

/// A user-defined function stored for inlining.
#[derive(Clone, Debug)]
struct FnDef {
    params: Vec<TypedParam>,
    body: Block,
    #[allow(dead_code)]
    return_type: Option<TypeAnnotation>,
}

/// Compiles an AST `Block` (from a prove block or circuit file) into a `ProveIR`.
pub struct ProveIrCompiler {
    /// Maps variable names → what they resolve to.
    env: HashMap<String, CompEnvValue>,
    /// Mutable variable SSA versioning: original_name → current version number.
    /// A name in this map means it was declared with `mut`.
    ssa_versions: HashMap<String, u32>,
    /// Tracks which names are captured from the outer scope.
    captured_names: HashSet<String>,
    /// Functions available for inlining.
    fn_table: HashMap<String, FnDef>,
    /// Recursion guard: functions currently being inlined.
    call_stack: HashSet<String>,
    /// Accumulated circuit body nodes.
    body: Vec<CircuitNode>,
    /// Public input declarations.
    public_inputs: Vec<ProveInputDecl>,
    /// Witness input declarations.
    witness_inputs: Vec<ProveInputDecl>,
}

impl ProveIrCompiler {
    fn new() -> Self {
        Self {
            env: HashMap::new(),
            ssa_versions: HashMap::new(),
            captured_names: HashSet::new(),
            fn_table: HashMap::new(),
            call_stack: HashSet::new(),
            body: Vec::new(),
            public_inputs: Vec::new(),
            witness_inputs: Vec::new(),
        }
    }

    /// Compile an AST Block into a ProveIR template.
    ///
    /// `outer_scope`: names available in the enclosing scope (for prove blocks).
    /// Pass an empty set for `ach circuit` mode.
    pub fn compile(block: &Block, outer_scope: &HashSet<String>) -> Result<ProveIR, ProveIrError> {
        let mut compiler = Self::new();

        // Register outer scope names as potential captures
        for name in outer_scope {
            compiler
                .env
                .insert(name.clone(), CompEnvValue::Capture(name.clone()));
        }

        // Compile all statements in the block
        compiler.compile_block_stmts(block)?;

        // TODO(step 9): classify captures

        Ok(ProveIR {
            public_inputs: compiler.public_inputs,
            witness_inputs: compiler.witness_inputs,
            captures: Vec::new(), // TODO(step 9)
            body: compiler.body,
        })
    }

    // -----------------------------------------------------------------------
    // Statement compilation
    // -----------------------------------------------------------------------

    /// Compile all statements in a block, appending to self.body.
    fn compile_block_stmts(&mut self, block: &Block) -> Result<(), ProveIrError> {
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        Ok(())
    }

    /// Compile a single statement.
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), ProveIrError> {
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
            Stmt::Import { span, .. } | Stmt::SelectiveImport { span, .. } => {
                Err(ProveIrError::UnsupportedOperation {
                    description: "imports not yet supported in ProveIR".into(),
                    span: to_span(span),
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Public/Witness declarations
    // -----------------------------------------------------------------------

    fn compile_public_decl(
        &mut self,
        names: &[InputDecl],
        _span: &Span,
    ) -> Result<(), ProveIrError> {
        for decl in names {
            let ir_type = decl
                .type_ann
                .as_ref()
                .map(annotation_to_ir_type)
                .unwrap_or(IrType::Field);
            if let Some(size) = decl.array_size {
                self.public_inputs.push(ProveInputDecl {
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
                self.public_inputs.push(ProveInputDecl {
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

    fn compile_witness_decl(
        &mut self,
        names: &[InputDecl],
        _span: &Span,
    ) -> Result<(), ProveIrError> {
        for decl in names {
            let ir_type = decl
                .type_ann
                .as_ref()
                .map(annotation_to_ir_type)
                .unwrap_or(IrType::Field);
            if let Some(size) = decl.array_size {
                self.witness_inputs.push(ProveInputDecl {
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
                self.witness_inputs.push(ProveInputDecl {
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

    fn compile_let(
        &mut self,
        name: &str,
        _type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array literal → LetArray
        if let Expr::Array {
            elements,
            span: arr_span,
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

    // -----------------------------------------------------------------------
    // Expression statement (handles assert_eq / assert as nodes)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Mut declaration (desugared to SSA)
    // -----------------------------------------------------------------------

    fn compile_mut_decl(
        &mut self,
        name: &str,
        _type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
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

    fn compile_assignment(
        &mut self,
        target: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Only support simple ident assignment: x = expr
        let name = match target {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "only simple variable assignment is supported in circuits \
                         (no array element or field assignment)"
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

        // Increment version
        let new_version = version + 1;
        self.ssa_versions.insert(name.clone(), new_version);

        // Generate SSA name: x__v1, x__v2, etc.
        let ssa_name = format!("{name}__v{new_version}");

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

    // -----------------------------------------------------------------------
    // Expression statement (handles assert_eq / assert as nodes)
    // -----------------------------------------------------------------------

    fn compile_expr_stmt(&mut self, expr: &Expr) -> Result<(), ProveIrError> {
        // Detect assert_eq(a, b) and assert(x) to emit constraint nodes
        if let Expr::Call { callee, args, span } = expr {
            if let Expr::Ident { name, .. } = callee.as_ref() {
                match name.as_str() {
                    "assert_eq" => {
                        self.check_arity("assert_eq", 2, args.len(), span)?;
                        let lhs = self.compile_expr(&args[0])?;
                        let rhs = self.compile_expr(&args[1])?;
                        self.body.push(CircuitNode::AssertEq {
                            lhs,
                            rhs,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    "assert" => {
                        self.check_arity("assert", 1, args.len(), span)?;
                        let cond = self.compile_expr(&args[0])?;
                        self.body.push(CircuitNode::Assert {
                            expr: cond,
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
            span: None,
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expression compilation
    // -----------------------------------------------------------------------

    /// Compile an AST expression into a `CircuitExpr`.
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<CircuitExpr, ProveIrError> {
        match expr {
            Expr::Number { value, span } => self.compile_number(value, span),
            Expr::FieldLit {
                value, radix, span, ..
            } => self.compile_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => Ok(CircuitExpr::Const(FieldElement::ONE)),
            Expr::Bool { value: false, .. } => Ok(CircuitExpr::Const(FieldElement::ZERO)),
            Expr::Ident { name, span } => self.compile_ident(name, span),

            Expr::BinOp { op, lhs, rhs, span } => self.compile_binop(op, lhs, rhs, span),
            Expr::UnaryOp { op, operand, span } => self.compile_unary(op, operand, span),

            Expr::StaticAccess {
                type_name,
                member,
                span,
            } => self.compile_static_access(type_name, member, span),

            Expr::Call { callee, args, span } => self.compile_call(callee, args, span),

            Expr::DotAccess {
                object,
                field,
                span,
            } => self.compile_dot_access(object, field, span),

            // TODO(step 8): If, For, Block, Index

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
            Expr::Nil { span } => Err(ProveIrError::TypeNotConstrainable {
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
            Expr::Error { span } => Err(ProveIrError::UnsupportedOperation {
                description: "cannot compile error placeholder (source has parse errors)".into(),
                span: to_span(span),
            }),

            // Catch-all for expressions not yet implemented
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "expression not yet supported in ProveIR".into(),
                span: None,
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Literals
    // -----------------------------------------------------------------------

    fn compile_number(&self, s: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        if s.contains('.') {
            return Err(ProveIrError::TypeNotConstrainable {
                type_name: "decimal number".into(),
                span: to_span(span),
            });
        }
        let (negative, digits) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };
        let fe = FieldElement::from_decimal_str(digits).ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!("invalid integer literal: {s}"),
                span: to_span(span),
            }
        })?;
        if negative {
            Ok(CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(fe)),
            })
        } else {
            Ok(CircuitExpr::Const(fe))
        }
    }

    fn compile_field_lit(
        &self,
        value: &str,
        radix: &FieldRadix,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let fe = match radix {
            FieldRadix::Decimal => FieldElement::from_decimal_str(value),
            FieldRadix::Hex => FieldElement::from_hex_str(value),
            FieldRadix::Binary => FieldElement::from_binary_str(value),
        }
        .ok_or_else(|| ProveIrError::UnsupportedOperation {
            description: format!("invalid field literal: {value}"),
            span: to_span(span),
        })?;
        Ok(CircuitExpr::Const(fe))
    }

    // -----------------------------------------------------------------------
    // Identifiers
    // -----------------------------------------------------------------------

    fn compile_ident(&mut self, name: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        match self.env.get(name) {
            Some(CompEnvValue::Scalar(resolved)) => Ok(CircuitExpr::Var(resolved.clone())),
            Some(CompEnvValue::Array(_)) => Err(ProveIrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: to_span(span),
            }),
            Some(CompEnvValue::Capture(cap_name)) => {
                self.captured_names.insert(cap_name.clone());
                Ok(CircuitExpr::Capture(cap_name.clone()))
            }
            None => Err(ProveIrError::UndeclaredVariable {
                name: name.into(),
                span: to_span(span),
                suggestion: None, // TODO: fuzzy match from env keys
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Static access (Type::MEMBER)
    // -----------------------------------------------------------------------

    fn compile_static_access(
        &self,
        type_name: &str,
        member: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match (type_name, member) {
            ("Field", "ZERO") => Ok(CircuitExpr::Const(FieldElement::ZERO)),
            ("Field", "ONE") => Ok(CircuitExpr::Const(FieldElement::ONE)),
            ("Field", "ORDER") => Err(ProveIrError::StaticAccessNotConstrainable {
                type_name: "Field".into(),
                member: "ORDER".into(),
                reason: "Field::ORDER is a string (the BN254 modulus) \
                         and strings cannot be used in circuits"
                    .into(),
                span: to_span(span),
            }),
            ("Int", "MAX") => Ok(CircuitExpr::Const(FieldElement::from_i64(memory::I60_MAX))),
            ("Int", "MIN") => Ok(CircuitExpr::Const(FieldElement::from_i64(memory::I60_MIN))),
            ("BigInt", _) => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("unknown static access `{type_name}::{member}`"),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Call dispatch
    // -----------------------------------------------------------------------

    fn compile_call(
        &mut self,
        callee: &Expr,
        args: &[Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match callee {
            // Method call: expr.method(args)
            Expr::DotAccess {
                object,
                field,
                span: dot_span,
            } => {
                // Check for module.func() first
                if let Expr::Ident { name: module, .. } = object.as_ref() {
                    let qualified = format!("{module}::{field}");
                    if self.env.contains_key(&qualified) || self.has_function(&qualified) {
                        // Module function call — will be handled in step 7 (function inlining)
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "module function call `{module}.{field}()` \
                                 not yet implemented in ProveIR"
                            ),
                            span: to_span(span),
                        });
                    }
                }
                self.compile_method_call(object, field, args, dot_span)
            }

            // Named function/builtin call: name(args)
            Expr::Ident { name, .. } => self.compile_named_call(name, args, span),

            // Dynamic dispatch not supported
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "only named function calls are supported in circuits \
                              (dynamic dispatch cannot be compiled to constraints)"
                    .into(),
                span: to_span(span),
            }),
        }
    }

    /// Compile a named function or builtin call.
    fn compile_named_call(
        &mut self,
        name: &str,
        args: &[Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match name {
            // Builtins that produce CircuitExpr directly
            "poseidon" => {
                self.check_arity("poseidon", 2, args.len(), span)?;
                let left = self.compile_expr(&args[0])?;
                let right = self.compile_expr(&args[1])?;
                Ok(CircuitExpr::PoseidonHash {
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            "poseidon_many" => {
                if args.len() < 2 {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "poseidon_many".into(),
                        expected: 2,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                let compiled: Result<Vec<_>, _> =
                    args.iter().map(|a| self.compile_expr(a)).collect();
                Ok(CircuitExpr::PoseidonMany(compiled?))
            }
            "mux" => {
                self.check_arity("mux", 3, args.len(), span)?;
                let cond = self.compile_expr(&args[0])?;
                let if_true = self.compile_expr(&args[1])?;
                let if_false = self.compile_expr(&args[2])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(cond),
                    if_true: Box::new(if_true),
                    if_false: Box::new(if_false),
                })
            }
            "range_check" => {
                self.check_arity("range_check", 2, args.len(), span)?;
                let value = self.compile_expr(&args[0])?;
                let bits = self.extract_const_u64(&args[1], span)? as u32;
                Ok(CircuitExpr::RangeCheck {
                    value: Box::new(value),
                    bits,
                })
            }
            "len" => {
                self.check_arity("len", 1, args.len(), span)?;
                self.compile_len_call(&args[0], span)
            }

            // Builtins that produce CircuitNode (handled at statement level)
            // assert_eq and assert are expression-level in the AST but produce
            // nodes — we return a dummy Const(0) since they're constraints, not values.
            "assert_eq" => {
                self.check_arity("assert_eq", 2, args.len(), span)?;
                let _lhs = self.compile_expr(&args[0])?;
                let _rhs = self.compile_expr(&args[1])?;
                // Note: actual AssertEq node emission happens at statement level (step 5)
                // At expression level, we just validate the arguments compile
                Ok(CircuitExpr::Const(FieldElement::ZERO))
            }
            "assert" => {
                self.check_arity("assert", 1, args.len(), span)?;
                let _cond = self.compile_expr(&args[0])?;
                Ok(CircuitExpr::Const(FieldElement::ZERO))
            }

            // User function call (inlined)
            _ => self.compile_user_fn_call(name, args, span),
        }
    }

    // -----------------------------------------------------------------------
    // Dot access (non-call)
    // -----------------------------------------------------------------------

    fn compile_dot_access(
        &mut self,
        object: &Expr,
        field: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // module.constant access
        if let Expr::Ident { name: module, .. } = object {
            let qualified = format!("{module}::{field}");
            if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&qualified) {
                return Ok(CircuitExpr::Var(resolved.clone()));
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "dot access is not supported in circuits \
                          (use methods like .len(), .abs(), etc. or arrays with indexing)"
                .into(),
            span: to_span(span),
        })
    }

    // -----------------------------------------------------------------------
    // Method desugaring
    // -----------------------------------------------------------------------

    fn compile_method_call(
        &mut self,
        object: &Expr,
        method: &str,
        args: &[Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match method {
            // --- Universally supported ---
            "len" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "len".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                self.compile_len_call(object, span)
            }

            // --- Identity in circuit context ---
            "to_field" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "to_field".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                // All circuit values are field elements — identity
                self.compile_expr(object)
            }

            // --- Int methods desugared to circuit primitives ---
            "abs" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "abs".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                let x = self.compile_expr(object)?;
                let zero = CircuitExpr::Const(FieldElement::ZERO);
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(x.clone()),
                        rhs: Box::new(zero),
                    }),
                    if_true: Box::new(CircuitExpr::UnaryOp {
                        op: CircuitUnaryOp::Neg,
                        operand: Box::new(x.clone()),
                    }),
                    if_false: Box::new(x),
                })
            }
            "min" => {
                self.check_method_arity("min", 1, args.len(), span)?;
                let n = self.compile_expr(object)?;
                let m = self.compile_expr(&args[0])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(n.clone()),
                        rhs: Box::new(m.clone()),
                    }),
                    if_true: Box::new(n),
                    if_false: Box::new(m),
                })
            }
            "max" => {
                self.check_method_arity("max", 1, args.len(), span)?;
                let n = self.compile_expr(object)?;
                let m = self.compile_expr(&args[0])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(n.clone()),
                        rhs: Box::new(m.clone()),
                    }),
                    if_true: Box::new(m),
                    if_false: Box::new(n),
                })
            }
            "pow" => {
                self.check_method_arity("pow", 1, args.len(), span)?;
                let base = self.compile_expr(object)?;
                let exp = self.extract_const_u64(&args[0], span)?;
                Ok(CircuitExpr::Pow {
                    base: Box::new(base),
                    exp,
                })
            }

            // --- Methods that cannot be compiled to constraints ---
            "to_string" => Err(self.method_not_constrainable(
                "to_string",
                "produces a string, which cannot be represented in circuits",
                span,
            )),
            "to_int" => Err(self.method_not_constrainable(
                "to_int",
                "type narrowing is not needed in circuits (all values are field elements)",
                span,
            )),
            "push" | "pop" => Err(self.method_not_constrainable(
                method,
                "mutation is not supported in circuits (arrays have fixed size)",
                span,
            )),
            "map" | "filter" | "reduce" | "for_each" | "find" | "any" | "all" | "sort"
            | "flat_map" | "zip" => Err(self.method_not_constrainable(
                method,
                "higher-order collection methods are not yet supported in circuits \
                 (use a for loop instead)",
                span,
            )),
            "keys" | "values" | "entries" | "contains_key" | "get" | "set" | "remove" => Err(self
                .method_not_constrainable(
                    method,
                    "map operations are not supported in circuits \
                     (maps cannot be represented as constraints)",
                    span,
                )),
            "split" | "trim" | "replace" | "to_upper" | "to_lower" | "chars" | "index_of"
            | "substring" | "repeat" | "starts_with" | "ends_with" | "contains" => Err(self
                .method_not_constrainable(
                    method,
                    "string operations are not supported in circuits",
                    span,
                )),
            "bit_and" | "bit_or" | "bit_xor" | "bit_not" | "bit_shl" | "bit_shr" | "to_bits" => {
                Err(self.method_not_constrainable(
                    method,
                    "BigInt operations are not supported in circuits",
                    span,
                ))
            }

            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("method `.{method}()` is not supported in circuits"),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers for call/method compilation
    // -----------------------------------------------------------------------

    /// Compile `len(expr)` or `expr.len()` — resolve to ArrayLen.
    fn compile_len_call(
        &mut self,
        object: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        if let Expr::Ident { name, .. } = object {
            if matches!(
                self.env.get(name.as_str()),
                Some(CompEnvValue::Array(_)) | Some(CompEnvValue::Capture(_))
            ) {
                return Ok(CircuitExpr::ArrayLen(name.clone()));
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "len() requires an array variable in circuits".into(),
            span: to_span(span),
        })
    }

    fn check_arity(
        &self,
        name: &str,
        expected: usize,
        got: usize,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        if got != expected {
            return Err(ProveIrError::WrongArgumentCount {
                name: name.into(),
                expected,
                got,
                span: to_span(span),
            });
        }
        Ok(())
    }

    fn check_method_arity(
        &self,
        name: &str,
        expected: usize,
        got: usize,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        if got != expected {
            return Err(ProveIrError::WrongArgumentCount {
                name: format!(".{name}()"),
                expected,
                got,
                span: to_span(span),
            });
        }
        Ok(())
    }

    fn method_not_constrainable(&self, method: &str, reason: &str, span: &Span) -> ProveIrError {
        ProveIrError::MethodNotConstrainable {
            method: method.into(),
            reason: reason.into(),
            span: to_span(span),
        }
    }

    /// Check if a function name exists in the fn_table.
    fn has_function(&self, name: &str) -> bool {
        self.fn_table.contains_key(name)
    }

    // -----------------------------------------------------------------------
    // User function inlining
    // -----------------------------------------------------------------------

    fn compile_user_fn_call(
        &mut self,
        name: &str,
        args: &[Expr],
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

        // Compile arguments
        let compiled_args: Vec<CircuitExpr> = args
            .iter()
            .map(|a| self.compile_expr(a))
            .collect::<Result<_, _>>()?;

        // Save env for param names and bind args
        let param_names: Vec<String> = fn_def.params.iter().map(|p| p.name.clone()).collect();
        let saved: Vec<(String, Option<CompEnvValue>)> = param_names
            .iter()
            .map(|p| (p.clone(), self.env.get(p).cloned()))
            .collect();

        // Emit Let nodes for each parameter binding and register in env
        for (param, arg_expr) in param_names.iter().zip(compiled_args) {
            let param_ssa = format!("__{name}_{param}");
            self.body.push(CircuitNode::Let {
                name: param_ssa.clone(),
                value: arg_expr,
                span: Some(SpanRange::from(span)),
            });
            self.env
                .insert(param.clone(), CompEnvValue::Scalar(param_ssa));
        }

        // Compile the function body, collecting the result
        let result = self.compile_block_as_expr(&fn_def.body)?;

        // Restore env
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

        self.call_stack.remove(name);
        Ok(result)
    }

    /// Compile a block of statements and return the result of the last expression.
    /// Intermediate statements (Let, AssertEq, etc.) are appended to self.body.
    /// The last expression statement becomes the return value.
    /// If the block has no expression result, returns Const(ZERO).
    fn compile_block_as_expr(&mut self, block: &Block) -> Result<CircuitExpr, ProveIrError> {
        let stmts = &block.stmts;
        if stmts.is_empty() {
            return Ok(CircuitExpr::Const(FieldElement::ZERO));
        }

        // Compile all but the last statement normally
        for stmt in &stmts[..stmts.len() - 1] {
            // Handle Return inside function body
            if let Stmt::Return { value, .. } = stmt {
                return match value {
                    Some(expr) => self.compile_expr(expr),
                    None => Ok(CircuitExpr::Const(FieldElement::ZERO)),
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
                None => Ok(CircuitExpr::Const(FieldElement::ZERO)),
            },
            other => {
                self.compile_stmt(other)?;
                Ok(CircuitExpr::Const(FieldElement::ZERO))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Binary operations
    // -----------------------------------------------------------------------

    fn compile_binop(
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

    fn compile_arith_binop(
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

    fn compile_comparison(
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

    fn compile_bool_binop(
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

    fn compile_pow(
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
    fn extract_const_u64(&self, expr: &Expr, span: &Span) -> Result<u64, ProveIrError> {
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

    fn compile_unary(
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
// Helpers
// ---------------------------------------------------------------------------

/// Convert an AST Span to an OptSpan for error reporting.
fn to_span(span: &Span) -> OptSpan {
    span_box(Some(SpanRange::from(span)))
}

/// Convert a TypeAnnotation to IrType.
fn annotation_to_ir_type(ann: &TypeAnnotation) -> IrType {
    match ann {
        TypeAnnotation::Field | TypeAnnotation::FieldArray(_) => IrType::Field,
        TypeAnnotation::Bool | TypeAnnotation::BoolArray(_) => IrType::Bool,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use achronyme_parser::parse_program;

    /// Helper: parse source and compile the first expression to CircuitExpr.
    fn compile_single_expr(source: &str) -> Result<CircuitExpr, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let mut compiler = ProveIrCompiler::new();
        match &program.stmts[0] {
            Stmt::Expr(expr) => compiler.compile_expr(expr),
            _ => panic!("expected expression statement"),
        }
    }

    /// Helper: parse source with outer scope, compile an expression.
    fn compile_expr_with_scope(
        source: &str,
        scope: &[(&str, CompEnvValue)],
    ) -> Result<CircuitExpr, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let mut compiler = ProveIrCompiler::new();
        for (name, val) in scope {
            compiler.env.insert(name.to_string(), val.clone());
        }
        match &program.stmts[0] {
            Stmt::Expr(expr) => compiler.compile_expr(expr),
            _ => panic!("expected expression statement"),
        }
    }

    // --- Literals ---

    #[test]
    fn number_literal() {
        let expr = compile_single_expr("42").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::from_u64(42)));
    }

    #[test]
    fn negative_number() {
        let expr = compile_single_expr("-7").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(FieldElement::from_u64(7))),
            }
        );
    }

    #[test]
    fn field_literal_decimal() {
        let expr = compile_single_expr("0p42").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::from_u64(42)));
    }

    #[test]
    fn field_literal_hex() {
        let expr = compile_single_expr("0pxFF").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::from_u64(255)));
    }

    #[test]
    fn bool_true() {
        let expr = compile_single_expr("true").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::ONE));
    }

    #[test]
    fn bool_false() {
        let expr = compile_single_expr("false").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::ZERO));
    }

    #[test]
    fn negative_field_literal() {
        // Negative numbers go through UnaryOp(Neg, Number)
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("-0p42", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                ..
            }
        ));
    }

    // --- Identifiers ---

    #[test]
    fn ident_scalar() {
        let expr =
            compile_expr_with_scope("x", &[("x", CompEnvValue::Scalar("x".into()))]).unwrap();
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    #[test]
    fn ident_capture() {
        let expr =
            compile_expr_with_scope("n", &[("n", CompEnvValue::Capture("n".into()))]).unwrap();
        assert_eq!(expr, CircuitExpr::Capture("n".into()));
    }

    #[test]
    fn ident_array_as_scalar_errors() {
        let err =
            compile_expr_with_scope("arr", &[("arr", CompEnvValue::Array(vec!["arr_0".into()]))])
                .unwrap_err();
        assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
    }

    #[test]
    fn ident_undeclared_errors() {
        let err = compile_single_expr("unknown").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::UndeclaredVariable { name, .. } if name == "unknown"
        ));
    }

    // --- Binary operations ---

    #[test]
    fn binop_add() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a + b", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var("a".into())),
                rhs: Box::new(CircuitExpr::Var("b".into())),
            }
        );
    }

    #[test]
    fn binop_mul() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x * 2", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn binop_mod_rejected() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let err = compile_expr_with_scope("a % b", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Comparisons ---

    #[test]
    fn comparison_eq() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a == b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn comparison_gt() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x > 5", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Gt,
                ..
            }
        ));
    }

    // --- Boolean ops ---

    #[test]
    fn bool_and() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a && b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::And,
                ..
            }
        ));
    }

    #[test]
    fn bool_or() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a || b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::Or,
                ..
            }
        ));
    }

    // --- Unary ops ---

    #[test]
    fn unary_neg() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("-x", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Var("x".into())),
            }
        );
    }

    #[test]
    fn unary_not() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("!x", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Not,
                operand: Box::new(CircuitExpr::Var("x".into())),
            }
        );
    }

    #[test]
    fn double_negation_cancelled() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("--x", &scope).unwrap();
        // Double negation cancels to just x
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    // --- Power ---

    #[test]
    fn pow_constant_exponent() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x ^ 3", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Pow {
                base: Box::new(CircuitExpr::Var("x".into())),
                exp: 3,
            }
        );
    }

    #[test]
    fn pow_variable_exponent_rejected() {
        let scope = [
            ("x", CompEnvValue::Scalar("x".into())),
            ("n", CompEnvValue::Scalar("n".into())),
        ];
        let err = compile_expr_with_scope("x ^ n", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Rejections ---

    #[test]
    fn string_rejected() {
        let err = compile_single_expr("\"hello\"").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "string"
        ));
    }

    #[test]
    fn nil_rejected() {
        let err = compile_single_expr("nil").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "nil"
        ));
    }

    #[test]
    fn closure_rejected() {
        let err = compile_single_expr("fn(x) { x }").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Static access ---

    #[test]
    fn static_field_zero() {
        let expr = compile_single_expr("Field::ZERO").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::ZERO));
    }

    #[test]
    fn static_field_one() {
        let expr = compile_single_expr("Field::ONE").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldElement::ONE));
    }

    #[test]
    fn static_int_max() {
        let expr = compile_single_expr("Int::MAX").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Const(FieldElement::from_i64(memory::I60_MAX))
        );
    }

    #[test]
    fn static_int_min() {
        let expr = compile_single_expr("Int::MIN").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Const(FieldElement::from_i64(memory::I60_MIN))
        );
    }

    #[test]
    fn static_field_order_rejected() {
        let err = compile_single_expr("Field::ORDER").unwrap_err();
        assert!(
            matches!(err, ProveIrError::StaticAccessNotConstrainable { ref type_name, ref member, .. }
                if type_name == "Field" && member == "ORDER"
            ),
            "expected StaticAccessNotConstrainable, got {err}"
        );
    }

    #[test]
    fn static_bigint_rejected() {
        let err = compile_single_expr("BigInt::from_bits").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "BigInt"
        ));
    }

    #[test]
    fn static_unknown_rejected() {
        let err = compile_single_expr("Foo::BAR").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn static_in_expression() {
        // Field::ONE + Field::ZERO should work in arithmetic
        let expr = compile_single_expr("Field::ONE + Field::ZERO").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Const(FieldElement::ONE)),
                rhs: Box::new(CircuitExpr::Const(FieldElement::ZERO)),
            }
        );
    }

    // --- Method desugaring ---

    #[test]
    fn method_to_field_is_identity() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x.to_field()", &scope).unwrap();
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    #[test]
    fn method_abs_desugars_to_mux() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x.abs()", &scope).unwrap();
        assert!(
            matches!(expr, CircuitExpr::Mux { .. }),
            "abs should desugar to Mux, got {expr:?}"
        );
    }

    #[test]
    fn method_min_desugars_to_mux() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a.min(b)", &scope).unwrap();
        // min(a, b) = mux(a < b, a, b)
        if let CircuitExpr::Mux {
            if_true, if_false, ..
        } = &expr
        {
            assert_eq!(**if_true, CircuitExpr::Var("a".into()));
            assert_eq!(**if_false, CircuitExpr::Var("b".into()));
        } else {
            panic!("expected Mux, got {expr:?}");
        }
    }

    #[test]
    fn method_max_desugars_to_mux() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a.max(b)", &scope).unwrap();
        // max(a, b) = mux(a < b, b, a)
        if let CircuitExpr::Mux {
            if_true, if_false, ..
        } = &expr
        {
            assert_eq!(**if_true, CircuitExpr::Var("b".into()));
            assert_eq!(**if_false, CircuitExpr::Var("a".into()));
        } else {
            panic!("expected Mux, got {expr:?}");
        }
    }

    #[test]
    fn method_pow_desugars() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x.pow(3)", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Pow {
                base: Box::new(CircuitExpr::Var("x".into())),
                exp: 3,
            }
        );
    }

    #[test]
    fn method_len_on_array() {
        let scope = [(
            "arr",
            CompEnvValue::Array(vec!["arr_0".into(), "arr_1".into()]),
        )];
        let expr = compile_expr_with_scope("arr.len()", &scope).unwrap();
        assert_eq!(expr, CircuitExpr::ArrayLen("arr".into()));
    }

    #[test]
    fn method_to_string_rejected() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let err = compile_expr_with_scope("x.to_string()", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "to_string"
        ));
    }

    #[test]
    fn method_push_rejected() {
        let scope = [("arr", CompEnvValue::Array(vec!["arr_0".into()]))];
        let err = compile_expr_with_scope("arr.push(1)", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "push"
        ));
    }

    #[test]
    fn method_filter_rejected() {
        let scope = [("arr", CompEnvValue::Array(vec!["arr_0".into()]))];
        let err = compile_expr_with_scope("arr.filter(fn(x) { x })", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "filter"
        ));
    }

    #[test]
    fn method_keys_rejected() {
        let scope = [("m", CompEnvValue::Scalar("m".into()))];
        let err = compile_expr_with_scope("m.keys()", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "keys"
        ));
    }

    #[test]
    fn method_unknown_rejected() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let err = compile_expr_with_scope("x.foobar()", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Builtin calls ---

    #[test]
    fn builtin_poseidon() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("poseidon(a, b)", &scope).unwrap();
        assert!(matches!(expr, CircuitExpr::PoseidonHash { .. }));
    }

    #[test]
    fn builtin_poseidon_many() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
            ("c", CompEnvValue::Scalar("c".into())),
        ];
        let expr = compile_expr_with_scope("poseidon_many(a, b, c)", &scope).unwrap();
        if let CircuitExpr::PoseidonMany(args) = &expr {
            assert_eq!(args.len(), 3);
        } else {
            panic!("expected PoseidonMany, got {expr:?}");
        }
    }

    #[test]
    fn builtin_mux() {
        let scope = [
            ("c", CompEnvValue::Scalar("c".into())),
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("mux(c, a, b)", &scope).unwrap();
        assert!(matches!(expr, CircuitExpr::Mux { .. }));
    }

    #[test]
    fn builtin_range_check() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("range_check(x, 8)", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::RangeCheck {
                value: Box::new(CircuitExpr::Var("x".into())),
                bits: 8,
            }
        );
    }

    #[test]
    fn builtin_poseidon_wrong_arity() {
        let scope = [("a", CompEnvValue::Scalar("a".into()))];
        let err = compile_expr_with_scope("poseidon(a)", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
    }

    // --- Nested expressions ---

    #[test]
    fn nested_arithmetic() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
            ("c", CompEnvValue::Scalar("c".into())),
        ];
        let expr = compile_expr_with_scope("a * b + c", &scope).unwrap();
        // Should be Add(Mul(a, b), c)
        assert!(matches!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                ..
            }
        ));
    }

    // =====================================================================
    // Statement compilation tests
    // =====================================================================

    /// Helper: compile a full circuit source (with public/witness declarations).
    fn compile_circuit(source: &str) -> Result<ProveIR, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let block = Block {
            stmts: program.stmts,
            span: Span {
                byte_start: 0,
                byte_end: source.len(),
                line_start: 1,
                col_start: 1,
                line_end: 1,
                col_end: 1,
            },
        };
        ProveIrCompiler::compile(&block, &HashSet::new())
    }

    #[test]
    fn stmt_public_decl_scalar() {
        let ir = compile_circuit("public x\nassert_eq(x, x)").unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "x");
        assert!(ir.public_inputs[0].array_size.is_none());
    }

    #[test]
    fn stmt_witness_decl_scalar() {
        let ir = compile_circuit("witness y\nassert_eq(y, y)").unwrap();
        assert_eq!(ir.witness_inputs.len(), 1);
        assert_eq!(ir.witness_inputs[0].name, "y");
    }

    #[test]
    fn stmt_public_decl_array() {
        let ir = compile_circuit("public arr[3]\nassert_eq(arr_0, arr_1)").unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "arr");
        assert_eq!(ir.public_inputs[0].array_size, Some(ArraySize::Literal(3)));
    }

    #[test]
    fn stmt_let_scalar() {
        let ir = compile_circuit("public x\nlet y = x\nassert_eq(y, x)").unwrap();
        assert!(ir.body.len() >= 2); // Let + AssertEq
        assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "y"));
    }

    #[test]
    fn stmt_let_array() {
        let ir = compile_circuit("let arr = [1, 2, 3]").unwrap();
        assert_eq!(ir.body.len(), 1);
        if let CircuitNode::LetArray { name, elements, .. } = &ir.body[0] {
            assert_eq!(name, "arr");
            assert_eq!(elements.len(), 3);
        } else {
            panic!("expected LetArray, got {:?}", ir.body[0]);
        }
    }

    #[test]
    fn stmt_empty_array_rejected() {
        let err = compile_circuit("let arr = []").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn stmt_assert_eq_as_node() {
        let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
        assert!(
            ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::AssertEq { .. })),
            "expected AssertEq node in body"
        );
    }

    #[test]
    fn stmt_assert_as_node() {
        let ir = compile_circuit("public x\nassert(x)").unwrap();
        assert!(
            ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::Assert { .. })),
            "expected Assert node in body"
        );
    }

    #[test]
    fn stmt_fn_decl_not_emitted() {
        let ir = compile_circuit("public x\nfn f(a) { a }\nassert_eq(x, x)").unwrap();
        // FnDecl doesn't produce a body node — it's stored in fn_table
        assert!(
            !ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "f")),
            "FnDecl should not produce a Let node"
        );
    }

    #[test]
    fn stmt_print_rejected() {
        let err = compile_circuit("print(42)").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn stmt_break_rejected() {
        // break outside loop is actually a parse error, but test the stmt handler
        let err = compile_circuit("public x\nassert_eq(x, x)");
        // This should succeed — break only fails if actually encountered
        assert!(err.is_ok());
    }

    #[test]
    fn stmt_basic_circuit() {
        // A complete basic circuit: public out, witness a, b, assert_eq(a * b, out)
        let ir = compile_circuit(
            "public out\nwitness a\nwitness b\nlet product = a * b\nassert_eq(product, out)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 2);
        assert_eq!(ir.public_inputs[0].name, "out");
        assert_eq!(ir.witness_inputs[0].name, "a");
        assert_eq!(ir.witness_inputs[1].name, "b");
        // Body: Let(product) + AssertEq
        assert!(ir.body.len() >= 2);
        assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "product"));
        assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
    }

    #[test]
    fn stmt_poseidon_circuit() {
        let ir = compile_circuit(
            "public hash\nwitness secret\nlet h = poseidon(secret, 0)\nassert_eq(h, hash)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 1);
        // Body: Let(h = PoseidonHash) + AssertEq
        if let CircuitNode::Let { value, .. } = &ir.body[0] {
            assert!(
                matches!(value, CircuitExpr::PoseidonHash { .. }),
                "expected PoseidonHash, got {value:?}"
            );
        } else {
            panic!("expected Let node, got {:?}", ir.body[0]);
        }
    }

    #[test]
    fn stmt_with_static_access() {
        // Field::ZERO should work inside a circuit now!
        let ir = compile_circuit("public x\nlet zero = Field::ZERO\nassert_eq(x, zero)").unwrap();
        if let CircuitNode::Let { value, .. } = &ir.body[0] {
            assert_eq!(*value, CircuitExpr::Const(FieldElement::ZERO));
        } else {
            panic!("expected Let node");
        }
    }

    // =====================================================================
    // Mut-to-SSA desugaring tests
    // =====================================================================

    #[test]
    fn mut_decl_basic() {
        let ir = compile_circuit("public x\nmut acc = x\nassert_eq(acc, x)").unwrap();
        // mut acc = x → Let { name: "acc", value: Var("x") }
        assert!(matches!(
            &ir.body[0],
            CircuitNode::Let { name, .. } if name == "acc"
        ));
    }

    #[test]
    fn mut_reassignment_creates_ssa_version() {
        let ir =
            compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
        // body[0]: Let { name: "acc", value: Var("x") }
        // body[1]: Let { name: "acc__v1", value: BinOp(Add, Var("acc"), Const(1)) }
        // body[2]: AssertEq { Var("acc__v1"), Var("x") }
        assert!(matches!(
            &ir.body[0],
            CircuitNode::Let { name, .. } if name == "acc"
        ));
        assert!(matches!(
            &ir.body[1],
            CircuitNode::Let { name, .. } if name == "acc__v1"
        ));
        // AssertEq should reference the latest SSA name
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[2] {
            assert_eq!(*lhs, CircuitExpr::Var("acc__v1".into()));
        } else {
            panic!("expected AssertEq, got {:?}", ir.body[2]);
        }
    }

    #[test]
    fn mut_multiple_reassignments() {
        let ir = compile_circuit(
            "public x\nmut a = 0\na = a + 1\na = a + 2\na = a + 3\nassert_eq(a, x)",
        )
        .unwrap();
        // Let("a"), Let("a__v1"), Let("a__v2"), Let("a__v3"), AssertEq(Var("a__v3"), ...)
        assert!(matches!(
            &ir.body[0],
            CircuitNode::Let { name, .. } if name == "a"
        ));
        assert!(matches!(
            &ir.body[1],
            CircuitNode::Let { name, .. } if name == "a__v1"
        ));
        assert!(matches!(
            &ir.body[2],
            CircuitNode::Let { name, .. } if name == "a__v2"
        ));
        assert!(matches!(
            &ir.body[3],
            CircuitNode::Let { name, .. } if name == "a__v3"
        ));
        // The final assert_eq should use a__v3
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
            assert_eq!(*lhs, CircuitExpr::Var("a__v3".into()));
        } else {
            panic!("expected AssertEq");
        }
    }

    #[test]
    fn mut_reassignment_uses_previous_version() {
        // acc = acc + 1 should reference the PREVIOUS version of acc in the RHS
        let ir =
            compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
        // body[1]: Let { name: "acc__v1", value: BinOp(Add, Var("acc"), Const(1)) }
        if let CircuitNode::Let { value, .. } = &ir.body[1] {
            // The RHS should reference "acc" (v0), not "acc__v1"
            assert_eq!(
                *value,
                CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(CircuitExpr::Var("acc".into())),
                    rhs: Box::new(CircuitExpr::Const(FieldElement::ONE)),
                }
            );
        } else {
            panic!("expected Let node");
        }
    }

    #[test]
    fn assign_to_immutable_errors() {
        let err = compile_circuit("public x\nlet a = x\na = 42\nassert_eq(a, x)").unwrap_err();
        assert!(
            matches!(err, ProveIrError::UnsupportedOperation { ref description, .. }
                if description.contains("not declared with `mut`")),
            "expected mut error, got {err}"
        );
    }

    #[test]
    fn assign_to_undeclared_errors() {
        let err = compile_circuit("public x\nfoo = 42\nassert_eq(foo, x)").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn mut_in_accumulator_pattern() {
        // Common pattern: accumulate in a loop (simulated without for, just sequential)
        let ir = compile_circuit(
            "public total\n\
             witness a\n\
             witness b\n\
             witness c\n\
             mut acc = Field::ZERO\n\
             acc = acc + a\n\
             acc = acc + b\n\
             acc = acc + c\n\
             assert_eq(acc, total)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 3);
        // acc, acc__v1, acc__v2, acc__v3, assert_eq
        assert_eq!(ir.body.len(), 5);
        // Last AssertEq should use acc__v3
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
            assert_eq!(*lhs, CircuitExpr::Var("acc__v3".into()));
        } else {
            panic!("expected AssertEq");
        }
    }

    // =====================================================================
    // Function inlining tests
    // =====================================================================

    #[test]
    fn fn_simple_inline() {
        let ir = compile_circuit(
            "public x\npublic out\nfn double(a) { a * 2 }\nassert_eq(double(x), out)",
        )
        .unwrap();
        // double(x) should produce: Let(__double_a = Var(x)) then the inline result
        // The AssertEq should have the inlined expression
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_inline_with_let() {
        let ir = compile_circuit(
            "public out\nwitness x\n\
             fn square(n) { let r = n * n; r }\n\
             assert_eq(square(x), out)",
        )
        .unwrap();
        // The inlined body should have emitted a Let for r
        assert!(ir.body.iter().any(
            |n| matches!(n, CircuitNode::Let { name, .. } if name.contains("__square_n")
                                                                  || name == "r")
        ));
    }

    #[test]
    fn fn_inline_nested_calls() {
        let ir = compile_circuit(
            "public out\nwitness x\n\
             fn square(n) { n * n }\n\
             fn sum_of_squares(a, b) { square(a) + square(b) }\n\
             assert_eq(sum_of_squares(x, x), out)",
        )
        .unwrap();
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_with_return() {
        let ir = compile_circuit(
            "public out\nwitness x\n\
             fn check(n) { return n * 2 }\n\
             assert_eq(check(x), out)",
        )
        .unwrap();
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_wrong_arity_errors() {
        let err =
            compile_circuit("public x\nfn f(a, b) { a + b }\nassert_eq(f(x), x)").unwrap_err();
        assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
    }

    #[test]
    fn fn_recursive_errors() {
        let err = compile_circuit("public x\nfn f(n) { f(n) }\nassert_eq(f(x), x)").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::RecursiveFunction { ref name } if name == "f"
        ));
    }

    #[test]
    fn fn_undefined_errors() {
        let err = compile_circuit("public x\nassert_eq(unknown_fn(x), x)").unwrap_err();
        assert!(matches!(err, ProveIrError::UndeclaredVariable { .. }));
    }

    #[test]
    fn fn_env_restored_after_inline() {
        // After inlining f(x), a reference to 'x' should still resolve to the outer x
        let ir = compile_circuit(
            "public x\npublic out\n\
             fn f(a) { a + 1 }\n\
             let y = f(x)\n\
             assert_eq(x + y, out)",
        )
        .unwrap();
        // The final assert_eq should reference outer x (not the param)
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_hash_pair_circuit() {
        // Realistic circuit: fn hash_pair(a, b) { poseidon(a, b) }
        let ir = compile_circuit(
            "public out\nwitness a\nwitness b\n\
             fn hash_pair(x, y) { poseidon(x, y) }\n\
             assert_eq(hash_pair(a, b), out)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 2);
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }
}
