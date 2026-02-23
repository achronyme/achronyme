use std::collections::{HashMap, HashSet};

use achronyme_parser::ast::*;
use achronyme_parser::parse_program as ast_parse_program;
use memory::FieldElement;

use crate::error::{IrError, SourceSpan};
use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

/// Maximum number of iterations allowed when statically unrolling a `for` loop.
/// Prevents DoS via `for i in 0..1000000` which would generate millions of IR instructions.
pub const MAX_UNROLL_ITERATIONS: u64 = 10_000;

/// Convert an AST span to an IR source span.
fn to_ir_span(span: &Span) -> Option<SourceSpan> {
    Some(SourceSpan {
        line: span.line,
        col: span.col,
    })
}

/// A value in the lowering environment: either a single SSA variable or an array.
#[derive(Clone, Debug)]
enum EnvValue {
    Scalar(SsaVar),
    Array(Vec<SsaVar>),
}

/// A user-defined function stored for inlining.
#[derive(Clone, Debug)]
struct FnDef {
    params: Vec<String>,
    body: Block,
}

/// Lowers an Achronyme AST into an SSA IR program.
pub struct IrLowering {
    program: IrProgram,
    /// Maps variable names to their current value (scalar or array).
    env: HashMap<String, EnvValue>,
    /// User-defined functions, inlined at each call site.
    fn_table: HashMap<String, FnDef>,
    /// Tracks active function calls to detect recursion.
    call_stack: HashSet<String>,
}

impl IrLowering {
    pub fn new() -> Self {
        Self {
            program: IrProgram::new(),
            env: HashMap::new(),
            fn_table: HashMap::new(),
            call_stack: HashSet::new(),
        }
    }

    /// Declare a public input and emit an `Input` instruction.
    pub fn declare_public(&mut self, name: &str) -> SsaVar {
        let v = self.program.fresh_var();
        self.program.push(Instruction::Input {
            result: v,
            name: name.to_string(),
            visibility: Visibility::Public,
        });
        self.program.set_name(v, name.to_string());
        self.env.insert(name.to_string(), EnvValue::Scalar(v));
        v
    }

    /// Declare a witness input and emit an `Input` instruction.
    pub fn declare_witness(&mut self, name: &str) -> SsaVar {
        let v = self.program.fresh_var();
        self.program.push(Instruction::Input {
            result: v,
            name: name.to_string(),
            visibility: Visibility::Witness,
        });
        self.program.set_name(v, name.to_string());
        self.env.insert(name.to_string(), EnvValue::Scalar(v));
        v
    }

    /// Declare a public array of N inputs: `{name}_0` .. `{name}_{N-1}`.
    pub fn declare_public_array(&mut self, name: &str, size: usize) -> Vec<SsaVar> {
        let vars: Vec<SsaVar> = (0..size)
            .map(|i| {
                let elem_name = format!("{name}_{i}");
                let v = self.program.fresh_var();
                self.program.push(Instruction::Input {
                    result: v,
                    name: elem_name.clone(),
                    visibility: Visibility::Public,
                });
                self.program.set_name(v, elem_name);
                v
            })
            .collect();
        self.env.insert(name.to_string(), EnvValue::Array(vars.clone()));
        vars
    }

    /// Declare a witness array of N inputs: `{name}_0` .. `{name}_{N-1}`.
    pub fn declare_witness_array(&mut self, name: &str, size: usize) -> Vec<SsaVar> {
        let vars: Vec<SsaVar> = (0..size)
            .map(|i| {
                let elem_name = format!("{name}_{i}");
                let v = self.program.fresh_var();
                self.program.push(Instruction::Input {
                    result: v,
                    name: elem_name.clone(),
                    visibility: Visibility::Witness,
                });
                self.program.set_name(v, elem_name);
                v
            })
            .collect();
        self.env.insert(name.to_string(), EnvValue::Array(vars.clone()));
        vars
    }

    /// Parse and lower an Achronyme source string into an IR program.
    /// Public/witness inputs must be declared before calling this.
    pub fn lower(mut self, source: &str) -> Result<IrProgram, IrError> {
        let program = ast_parse_program(source)
            .map_err(|e| IrError::ParseError(e))?;
        self.lower_program(&program)?;
        Ok(self.program)
    }

    /// Convenience: declare inputs and lower in one call.
    /// Names can include array syntax like `"path[3]"` to declare `path_0, path_1, path_2`.
    ///
    /// ```
    /// use ir::IrLowering;
    ///
    /// let prog = IrLowering::lower_circuit(
    ///     "assert_eq(x * y, z)",
    ///     &["z"],
    ///     &["x", "y"],
    /// ).unwrap();
    /// assert!(!prog.instructions.is_empty());
    /// ```
    pub fn lower_circuit(
        source: &str,
        public: &[&str],
        witness: &[&str],
    ) -> Result<IrProgram, IrError> {
        // Parse array syntax and collect flat names for duplicate check
        let pub_decls = parse_decl_specs(public)?;
        let wit_decls = parse_decl_specs(witness)?;

        let mut seen = HashSet::new();
        for (name, size) in pub_decls.iter().chain(wit_decls.iter()) {
            if let Some(n) = size {
                for i in 0..*n {
                    let flat = format!("{name}_{i}");
                    if !seen.insert(flat.clone()) {
                        return Err(IrError::DuplicateInput(flat));
                    }
                }
            } else if !seen.insert(name.clone()) {
                return Err(IrError::DuplicateInput(name.clone()));
            }
        }

        let mut lowering = IrLowering::new();
        for (name, size) in &pub_decls {
            if let Some(n) = size {
                lowering.declare_public_array(name, *n);
            } else {
                lowering.declare_public(name);
            }
        }
        for (name, size) in &wit_decls {
            if let Some(n) = size {
                lowering.declare_witness_array(name, *n);
            } else {
                lowering.declare_witness(name);
            }
        }
        lowering.lower(source)
    }

    /// Parse a self-contained circuit source that uses in-source `public`/`witness`
    /// declarations. Two-pass: first collects declaration names (to ensure correct
    /// wire ordering: public first, then witness), then processes remaining statements.
    ///
    /// ```
    /// use ir::IrLowering;
    ///
    /// let (pub_names, wit_names, prog) = IrLowering::lower_self_contained(
    ///     "public x\nwitness y\nassert_eq(x, y)"
    /// ).unwrap();
    /// assert_eq!(pub_names, vec!["x"]);
    /// assert_eq!(wit_names, vec!["y"]);
    /// ```
    pub fn lower_self_contained(source: &str) -> Result<(Vec<String>, Vec<String>, IrProgram), IrError> {
        let ast_program = ast_parse_program(source)
            .map_err(|e| IrError::ParseError(e))?;

        // Pass 1: collect declaration names (with optional array sizes)
        let mut pub_decls: Vec<(String, Option<usize>)> = Vec::new();
        let mut wit_decls: Vec<(String, Option<usize>)> = Vec::new();
        for stmt in &ast_program.stmts {
            match stmt {
                Stmt::PublicDecl { names, .. } => {
                    for decl in names {
                        pub_decls.push((decl.name.clone(), decl.array_size));
                    }
                }
                Stmt::WitnessDecl { names, .. } => {
                    for decl in names {
                        wit_decls.push((decl.name.clone(), decl.array_size));
                    }
                }
                _ => {}
            }
        }

        // Build flat name lists for duplicate checking and return value
        let mut pub_names = Vec::new();
        for (name, size) in &pub_decls {
            if let Some(n) = size {
                for i in 0..*n {
                    pub_names.push(format!("{name}_{i}"));
                }
            } else {
                pub_names.push(name.clone());
            }
        }
        let mut wit_names = Vec::new();
        for (name, size) in &wit_decls {
            if let Some(n) = size {
                for i in 0..*n {
                    wit_names.push(format!("{name}_{i}"));
                }
            } else {
                wit_names.push(name.clone());
            }
        }

        // Check for duplicate names across public and witness
        let mut seen = HashSet::new();
        for name in pub_names.iter().chain(wit_names.iter()) {
            if !seen.insert(name.as_str()) {
                return Err(IrError::DuplicateInput(name.clone()));
            }
        }

        // Emit Inputs in correct order: public first, then witness
        let mut lowering = IrLowering::new();
        for (name, size) in &pub_decls {
            if let Some(n) = size {
                lowering.declare_public_array(name, *n);
            } else {
                lowering.declare_public(name);
            }
        }
        for (name, size) in &wit_decls {
            if let Some(n) = size {
                lowering.declare_witness_array(name, *n);
            } else {
                lowering.declare_witness(name);
            }
        }

        // Pass 2: process non-declaration statements
        for stmt in &ast_program.stmts {
            match stmt {
                Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. } => {} // already processed
                _ => {
                    lowering.lower_stmt(stmt)?;
                }
            }
        }

        Ok((pub_names, wit_names, lowering.program))
    }

    // ========================================================================
    // Internal: program / statements
    // ========================================================================

    fn lower_program(&mut self, program: &Program) -> Result<(), IrError> {
        for stmt in &program.stmts {
            self.lower_stmt(stmt)?;
        }
        Ok(())
    }

    fn lower_stmt(&mut self, stmt: &Stmt) -> Result<Option<SsaVar>, IrError> {
        match stmt {
            Stmt::PublicDecl { names, .. } => {
                self.lower_public_decl(names)?;
                Ok(None)
            }
            Stmt::WitnessDecl { names, .. } => {
                self.lower_witness_decl(names)?;
                Ok(None)
            }
            Stmt::LetDecl { name, value, .. } => {
                self.lower_let(name, value)?;
                Ok(None)
            }
            Stmt::FnDecl { name, params, body, .. } => {
                self.fn_table.insert(
                    name.clone(),
                    FnDef {
                        params: params.clone(),
                        body: body.clone(),
                    },
                );
                Ok(None)
            }
            Stmt::Expr(expr) => {
                let v = self.lower_expr(expr)?;
                Ok(Some(v))
            }
            Stmt::MutDecl { span, .. } => Err(IrError::UnsupportedOperation(
                "mutable variables are not supported in circuits (circuit variables are immutable — use 'let' instead)".into(),
                to_ir_span(span),
            )),
            Stmt::Print { span, .. } => Err(IrError::UnsupportedOperation(
                "print is not supported in circuits (circuits produce constraints, not output — use the VM for debugging)".into(),
                to_ir_span(span),
            )),
            Stmt::Assignment { span, .. } => Err(IrError::UnsupportedOperation(
                "assignment is not supported in circuits (circuit variables are write-once — use a new 'let' binding instead)".into(),
                to_ir_span(span),
            )),
            Stmt::Break { span } => Err(IrError::UnsupportedOperation(
                "break is not supported in circuits (loops must have statically-known bounds for unrolling)".into(),
                to_ir_span(span),
            )),
            Stmt::Continue { span } => Err(IrError::UnsupportedOperation(
                "continue is not supported in circuits (loops must have statically-known bounds for unrolling)".into(),
                to_ir_span(span),
            )),
            Stmt::Return { span, .. } => Err(IrError::UnsupportedOperation(
                "return is not supported in circuits (circuits are flat constraint systems — use the final expression as the result)".into(),
                to_ir_span(span),
            )),
        }
    }

    fn lower_public_decl(&mut self, names: &[InputDecl]) -> Result<(), IrError> {
        for decl in names {
            if let Some(size) = decl.array_size {
                self.declare_public_array(&decl.name, size);
            } else {
                self.declare_public(&decl.name);
            }
        }
        Ok(())
    }

    fn lower_witness_decl(&mut self, names: &[InputDecl]) -> Result<(), IrError> {
        for decl in names {
            if let Some(size) = decl.array_size {
                self.declare_witness_array(&decl.name, size);
            } else {
                self.declare_witness(&decl.name);
            }
        }
        Ok(())
    }

    fn lower_let(&mut self, name: &str, value: &Expr) -> Result<(), IrError> {
        // Check if RHS is an array literal
        if let Expr::Array { elements, span } = value {
            let sp = to_ir_span(span);
            if elements.is_empty() {
                return Err(IrError::UnsupportedOperation(
                    "empty arrays are not allowed in circuits".into(),
                    sp,
                ));
            }
            let vars = elements
                .iter()
                .map(|e| self.lower_expr(e))
                .collect::<Result<Vec<_>, _>>()?;
            self.env.insert(name.to_string(), EnvValue::Array(vars));
            return Ok(());
        }

        let v = self.lower_expr(value)?;
        // `let` is an alias — no instruction emitted, just env binding
        self.program.set_name(v, name.to_string());
        self.env.insert(name.to_string(), EnvValue::Scalar(v));
        Ok(())
    }

    // ========================================================================
    // Expression lowering
    // ========================================================================

    fn lower_expr(&mut self, expr: &Expr) -> Result<SsaVar, IrError> {
        match expr {
            Expr::Number { value, span } => self.lower_number(value, span),
            Expr::Bool { value: true, .. } => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ONE,
                });
                Ok(v)
            }
            Expr::Bool { value: false, .. } => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ZERO,
                });
                Ok(v)
            }
            Expr::Ident { name, span } => {
                let sp = to_ir_span(span);
                match self.env.get(name.as_str()) {
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
            Expr::If { condition, then_block, else_branch, span: _ } => {
                self.lower_if(condition, then_block, else_branch.as_ref())
            }
            Expr::For { var, iterable, body, span } => {
                self.lower_for(var, iterable, body, span)
            }
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
            Expr::DotAccess { span, .. } => Err(IrError::UnsupportedOperation(
                "dot access is not supported in circuits (use arrays with static indexing instead)".into(),
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
        Ok(v)
    }

    // ========================================================================
    // Binary operations
    // ========================================================================

    fn lower_binop(
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
                self.program.push(Instruction::Add { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Sub => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::Sub { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Mul => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::Mul { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Div => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::Div { result: v, lhs: l, rhs: r });
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
                    return Ok(v);
                }

                self.pow_by_squaring(base, exp_u64)
            }
            BinOp::Eq => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::IsEq { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Neq => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::IsNeq { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Lt => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::IsLt { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Le => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::IsLe { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Gt => {
                // a > b  ≡  b < a
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::IsLt { result: v, lhs: r, rhs: l });
                Ok(v)
            }
            BinOp::Ge => {
                // a >= b  ≡  b <= a
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::IsLe { result: v, lhs: r, rhs: l });
                Ok(v)
            }
            BinOp::And => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::And { result: v, lhs: l, rhs: r });
                Ok(v)
            }
            BinOp::Or => {
                let l = self.lower_expr(lhs)?;
                let r = self.lower_expr(rhs)?;
                let v = self.program.fresh_var();
                self.program.push(Instruction::Or { result: v, lhs: l, rhs: r });
                Ok(v)
            }
        }
    }

    // ========================================================================
    // Unary operations
    // ========================================================================

    fn lower_unary(&mut self, op: &UnaryOp, operand: &Expr, _span: &Span) -> Result<SsaVar, IrError> {
        // Double negation / double NOT cancellation: --x → x, !!x → x
        if let Expr::UnaryOp { op: inner_op, operand: inner_operand, .. } = operand {
            if inner_op == op {
                return self.lower_expr(inner_operand);
            }
        }
        let inner = self.lower_expr(operand)?;
        let v = self.program.fresh_var();
        match op {
            UnaryOp::Neg => {
                self.program.push(Instruction::Neg { result: v, operand: inner });
            }
            UnaryOp::Not => {
                self.program.push(Instruction::Not { result: v, operand: inner });
            }
        }
        Ok(v)
    }

    // ========================================================================
    // Calls (builtins + user functions)
    // ========================================================================

    fn lower_call(
        &mut self,
        callee: &Expr,
        args: &[Expr],
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        let sp = to_ir_span(span);
        // Only identifier callees are supported
        let name = match callee {
            Expr::Ident { name, .. } => name.as_str(),
            _ => {
                return Err(IrError::UnsupportedOperation(
                    "only named function calls are supported in circuits (dynamic dispatch cannot be compiled to constraints)".into(),
                    sp,
                ));
            }
        };

        match name {
            "assert_eq" => self.lower_assert_eq(args, sp),
            "assert" => self.lower_assert(args, sp),
            "poseidon" => self.lower_poseidon(args, sp),
            "mux" => self.lower_mux(args, sp),
            "range_check" => self.lower_range_check(args, sp),
            "len" => self.lower_len(args, sp),
            "poseidon_many" => self.lower_poseidon_many(args, sp),
            "merkle_verify" => self.lower_merkle_verify(args, span),
            _ => self.lower_user_fn_call(name, args, sp),
        }
    }

    fn lower_assert_eq(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "assert_eq".into(),
                expected: 2,
                got: args.len(),
                span: sp,
            });
        }
        let a = self.lower_expr(&args[0])?;
        let b = self.lower_expr(&args[1])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::AssertEq { result: v, lhs: a, rhs: b });
        Ok(v)
    }

    fn lower_assert(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
        if args.len() != 1 {
            return Err(IrError::WrongArgumentCount {
                builtin: "assert".into(),
                expected: 1,
                got: args.len(),
                span: sp,
            });
        }
        let operand = self.lower_expr(&args[0])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::Assert { result: v, operand });
        Ok(v)
    }

    fn lower_poseidon(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "poseidon".into(),
                expected: 2,
                got: args.len(),
                span: sp,
            });
        }
        let left = self.lower_expr(&args[0])?;
        let right = self.lower_expr(&args[1])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::PoseidonHash { result: v, left, right });
        Ok(v)
    }

    fn lower_mux(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
        if args.len() != 3 {
            return Err(IrError::WrongArgumentCount {
                builtin: "mux".into(),
                expected: 3,
                got: args.len(),
                span: sp,
            });
        }
        let cond = self.lower_expr(&args[0])?;
        let if_true = self.lower_expr(&args[1])?;
        let if_false = self.lower_expr(&args[2])?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::Mux { result: v, cond, if_true, if_false });
        Ok(v)
    }

    fn lower_range_check(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "range_check".into(),
                expected: 2,
                got: args.len(),
                span: sp,
            });
        }
        let operand = self.lower_expr(&args[0])?;
        let bits_var = self.lower_expr(&args[1])?;

        let bits_fe = self.get_const_value(bits_var).ok_or_else(|| {
            IrError::UnsupportedOperation(
                "range_check bits argument must be a constant integer".into(),
                None,
            )
        })?;
        let bits = field_to_u64(&bits_fe).ok_or_else(|| {
            IrError::UnsupportedOperation("range_check bits value too large".into(), None)
        })? as u32;

        let v = self.program.fresh_var();
        self.program.push(Instruction::RangeCheck { result: v, operand, bits });
        Ok(v)
    }

    fn lower_len(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
        if args.len() != 1 {
            return Err(IrError::WrongArgumentCount {
                builtin: "len".into(),
                expected: 1,
                got: args.len(),
                span: sp.clone(),
            });
        }
        let arg_name = match &args[0] {
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

    fn lower_poseidon_many(&mut self, args: &[Expr], sp: Option<SourceSpan>) -> Result<SsaVar, IrError> {
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

    fn lower_merkle_verify(&mut self, args: &[Expr], span: &Span) -> Result<SsaVar, IrError> {
        let sp = to_ir_span(span);
        if args.len() != 4 {
            return Err(IrError::WrongArgumentCount {
                builtin: "merkle_verify".into(),
                expected: 4,
                got: args.len(),
                span: sp.clone(),
            });
        }

        let root_val = self.resolve_arg_value(&args[0])?;
        let leaf_val = self.resolve_arg_value(&args[1])?;
        let path_val = self.resolve_arg_value(&args[2])?;
        let indices_val = self.resolve_arg_value(&args[3])?;

        let root = match root_val {
            EnvValue::Scalar(v) => v,
            EnvValue::Array(_) => return Err(IrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: sp.clone(),
            }),
        };
        let mut current = match leaf_val {
            EnvValue::Scalar(v) => v,
            EnvValue::Array(_) => return Err(IrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: sp.clone(),
            }),
        };
        let path = match path_val {
            EnvValue::Array(v) => v,
            EnvValue::Scalar(_) => return Err(IrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: sp.clone(),
            }),
        };
        let indices = match indices_val {
            EnvValue::Array(v) => v,
            EnvValue::Scalar(_) => return Err(IrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: sp.clone(),
            }),
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

    /// Handle a call to a user-defined function (inline the body).
    fn lower_user_fn_call(
        &mut self,
        name: &str,
        args: &[Expr],
        sp: Option<SourceSpan>,
    ) -> Result<SsaVar, IrError> {
        let fn_def = match self.fn_table.get(name).cloned() {
            Some(fd) => fd,
            None => {
                return Err(IrError::UnsupportedOperation(
                    format!("function `{name}` is not defined"),
                    sp,
                ));
            }
        };

        let arg_vars: Vec<SsaVar> = args
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

        // Recursion guard
        if self.call_stack.contains(name) {
            return Err(IrError::RecursiveFunction(name.to_string()));
        }
        self.call_stack.insert(name.to_string());

        // Save env for params and bind args
        let saved: Vec<(String, Option<EnvValue>)> = fn_def
            .params
            .iter()
            .map(|p| (p.clone(), self.env.get(p).cloned()))
            .collect();
        for (param, arg) in fn_def.params.iter().zip(arg_vars.iter()) {
            self.env.insert(param.clone(), EnvValue::Scalar(*arg));
        }

        // Lower the function body directly (no re-parsing!)
        let result = self.lower_block(&fn_def.body)?;

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

    // ========================================================================
    // Index access
    // ========================================================================

    fn lower_index(
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
                    IrError::IndexOutOfBounds {
                        name: name.clone(),
                        index: usize::MAX,
                        length: elements.len(),
                        span: sp.clone(),
                    }
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

    // ========================================================================
    // Control flow
    // ========================================================================

    /// Lower `if cond { a } else { b }` as a MUX: `result = mux(cond, a, b)`.
    ///
    /// **Important**: Both branches are always fully lowered and all their
    /// constraints (assert_eq, assert, etc.) are emitted unconditionally.
    /// The MUX only selects which *value* to return. This is an inherent
    /// limitation of arithmetic circuits — there is no conditional execution.
    fn lower_if(
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
                    value: FieldElement::ZERO,
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
        Ok(v)
    }

    fn lower_for(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
        span: &Span,
    ) -> Result<SsaVar, IrError> {
        match iterable {
            ForIterable::Range { start, end } => {
                let iterations = end.saturating_sub(*start);
                if iterations > MAX_UNROLL_ITERATIONS {
                    return Err(IrError::UnsupportedOperation(
                        format!(
                            "for loop range {start}..{end} has {iterations} iterations, \
                             exceeding the maximum of {MAX_UNROLL_ITERATIONS}"
                        ),
                        to_ir_span(span),
                    ));
                }

                let mut last = None;
                for i in *start..*end {
                    let cv = self.program.fresh_var();
                    self.program.push(Instruction::Const {
                        result: cv,
                        value: FieldElement::from_u64(i),
                    });
                    self.env.insert(var.to_string(), EnvValue::Scalar(cv));
                    last = Some(self.lower_block(body)?);
                }

                self.env.remove(var);
                Ok(last.unwrap_or_else(|| {
                    let v = self.program.fresh_var();
                    self.program.push(Instruction::Const {
                        result: v,
                        value: FieldElement::ZERO,
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
                            self.env.insert(var.to_string(), EnvValue::Scalar(*elem_var));
                            last = Some(self.lower_block(body)?);
                        }
                        self.env.remove(var);
                        return Ok(last.unwrap_or_else(|| {
                            let v = self.program.fresh_var();
                            self.program.push(Instruction::Const {
                                result: v,
                                value: FieldElement::ZERO,
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

    fn lower_block(&mut self, block: &Block) -> Result<SsaVar, IrError> {
        let outer_keys: HashSet<String> = self.env.keys().cloned().collect();
        let mut last_var = None;

        for stmt in &block.stmts {
            match stmt {
                Stmt::LetDecl { name, value, .. } => {
                    self.lower_let(name, value)?;
                    last_var = None;
                }
                Stmt::Expr(expr) => {
                    last_var = Some(self.lower_expr(expr)?);
                }
                Stmt::FnDecl { name, params, body, .. } => {
                    self.fn_table.insert(
                        name.clone(),
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
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
                value: FieldElement::ZERO,
            });
            v
        }))
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    /// Square-and-multiply exponentiation in the IR.
    fn pow_by_squaring(&mut self, base: SsaVar, exp: u64) -> Result<SsaVar, IrError> {
        if exp == 0 {
            let v = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: v,
                value: FieldElement::ONE,
            });
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
                current = v;
            }
        }
        Ok(result.unwrap())
    }

    /// Look up the constant value of an SSA variable (if it was defined by a Const instruction).
    fn get_const_value(&self, var: SsaVar) -> Option<FieldElement> {
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
    fn emit_const(&mut self, value: FieldElement) -> SsaVar {
        let v = self.program.fresh_var();
        self.program.push(Instruction::Const { result: v, value });
        v
    }

    /// Resolve a call argument to either Scalar or Array.
    fn resolve_arg_value(&mut self, expr: &Expr) -> Result<EnvValue, IrError> {
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

/// Parse declaration specs like `["x", "path[3]"]` into `[(name, optional_size)]`.
fn parse_decl_specs(specs: &[&str]) -> Result<Vec<(String, Option<usize>)>, IrError> {
    let mut result = Vec::new();
    for spec in specs {
        if let Some(bracket_pos) = spec.find('[') {
            let name = spec[..bracket_pos].to_string();
            let size_str = spec[bracket_pos + 1..].trim_end_matches(']');
            let size: usize = size_str
                .parse()
                .map_err(|_| IrError::ParseError(format!("invalid array size in `{spec}`")))?;
            result.push((name, Some(size)));
        } else {
            result.push((spec.to_string(), None));
        }
    }
    Ok(result)
}

/// Try to extract a small u64 from a FieldElement.
fn field_to_u64(fe: &FieldElement) -> Option<u64> {
    let limbs = fe.to_canonical();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(limbs[0])
}
