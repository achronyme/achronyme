use std::collections::{HashMap, HashSet};

use achronyme_parser::{AchronymeParser, Rule};
use memory::FieldElement;
use pest::iterators::Pair;
use pest::Parser;

use crate::error::{IrError, SourceSpan};
use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

/// Maximum number of iterations allowed when statically unrolling a `for` loop.
/// Prevents DoS via `for i in 0..1000000` which would generate millions of IR instructions.
pub const MAX_UNROLL_ITERATIONS: u64 = 10_000;

/// Extract a source span from a pest pair.
fn span_of(pair: &Pair<Rule>) -> Option<SourceSpan> {
    let (line, col) = pair.as_span().start_pos().line_col();
    Some(SourceSpan { line, col })
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
    body_source: String,
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
                    name: elem_name,
                    visibility: Visibility::Public,
                });
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
                    name: elem_name,
                    visibility: Visibility::Witness,
                });
                v
            })
            .collect();
        self.env.insert(name.to_string(), EnvValue::Array(vars.clone()));
        vars
    }

    /// Parse and lower an Achronyme source string into an IR program.
    /// Public/witness inputs must be declared before calling this.
    pub fn lower(mut self, source: &str) -> Result<IrProgram, IrError> {
        let pairs = AchronymeParser::parse(Rule::program, source)
            .map_err(|e| IrError::ParseError(e.to_string()))?;

        let program = pairs.into_iter().next().unwrap();
        for pair in program.into_inner() {
            match pair.as_rule() {
                Rule::stmt => {
                    self.lower_stmt(pair)?;
                }
                Rule::EOI => {}
                _ => {}
            }
        }
        Ok(self.program)
    }

    /// Convenience: declare inputs and lower in one call.
    /// Names can include array syntax like `"path[3]"` to declare `path_0, path_1, path_2`.
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
    pub fn lower_self_contained(source: &str) -> Result<(Vec<String>, Vec<String>, IrProgram), IrError> {
        let pairs = AchronymeParser::parse(Rule::program, source)
            .map_err(|e| IrError::ParseError(e.to_string()))?;
        let program_pair = pairs.into_iter().next().unwrap();
        let stmts: Vec<Pair<Rule>> = program_pair
            .into_inner()
            .filter(|p| p.as_rule() == Rule::stmt)
            .collect();

        // Pass 1: collect declaration names (with optional array sizes)
        // Each entry is (name, optional_size)
        let mut pub_decls: Vec<(String, Option<usize>)> = Vec::new();
        let mut wit_decls: Vec<(String, Option<usize>)> = Vec::new();
        for stmt in &stmts {
            let inner = stmt.clone().into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::public_decl => {
                    let mut children = inner.into_inner().peekable();
                    while let Some(child) = children.next() {
                        if child.as_rule() == Rule::identifier {
                            let name = child.as_str().to_string();
                            let size = if children.peek().map(|p| p.as_rule()) == Some(Rule::array_size) {
                                let size_pair = children.next().unwrap();
                                let s = size_pair.into_inner().next().unwrap().as_str();
                                Some(s.parse::<usize>().map_err(|_| {
                                    IrError::ParseError(format!("invalid array size: {s}"))
                                })?)
                            } else {
                                None
                            };
                            pub_decls.push((name, size));
                        }
                    }
                }
                Rule::witness_decl => {
                    let mut children = inner.into_inner().peekable();
                    while let Some(child) = children.next() {
                        if child.as_rule() == Rule::identifier {
                            let name = child.as_str().to_string();
                            let size = if children.peek().map(|p| p.as_rule()) == Some(Rule::array_size) {
                                let size_pair = children.next().unwrap();
                                let s = size_pair.into_inner().next().unwrap().as_str();
                                Some(s.parse::<usize>().map_err(|_| {
                                    IrError::ParseError(format!("invalid array size: {s}"))
                                })?)
                            } else {
                                None
                            };
                            wit_decls.push((name, size));
                        }
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
        for stmt in stmts {
            let inner = stmt.clone().into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::public_decl | Rule::witness_decl => {} // already processed
                _ => {
                    lowering.lower_stmt(stmt)?;
                }
            }
        }

        Ok((pub_names, wit_names, lowering.program))
    }

    // ========================================================================
    // Statements
    // ========================================================================

    fn lower_stmt(&mut self, pair: Pair<Rule>) -> Result<Option<SsaVar>, IrError> {
        let inner = pair.into_inner().next().unwrap();
        let sp = span_of(&inner);
        match inner.as_rule() {
            Rule::public_decl => {
                self.lower_public_decl(inner)?;
                Ok(None)
            }
            Rule::witness_decl => {
                self.lower_witness_decl(inner)?;
                Ok(None)
            }
            Rule::let_decl => {
                self.lower_let(inner)?;
                Ok(None)
            }
            Rule::fn_decl => {
                self.lower_fn_decl(inner)?;
                Ok(None)
            }
            Rule::expr
            | Rule::or_expr
            | Rule::and_expr
            | Rule::cmp_expr
            | Rule::add_expr
            | Rule::mul_expr
            | Rule::pow_expr
            | Rule::prefix_expr
            | Rule::postfix_expr
            | Rule::atom => {
                let v = self.lower_expr(inner)?;
                Ok(Some(v))
            }
            Rule::mut_decl => Err(IrError::UnsupportedOperation(
                "mutable variables are not supported in circuits".into(), sp,
            )),
            Rule::print_stmt => Err(IrError::UnsupportedOperation(
                "print is not supported in circuits".into(), sp,
            )),
            Rule::assignment => Err(IrError::UnsupportedOperation(
                "assignment is not supported in circuits".into(), sp,
            )),
            Rule::break_stmt => Err(IrError::UnsupportedOperation(
                "break is not supported in circuits".into(), sp,
            )),
            Rule::continue_stmt => Err(IrError::UnsupportedOperation(
                "continue is not supported in circuits".into(), sp,
            )),
            Rule::return_stmt => Err(IrError::UnsupportedOperation(
                "return is not supported in circuits".into(), sp,
            )),
            _ => Err(IrError::UnsupportedOperation(format!(
                "{:?}", inner.as_rule()
            ), sp)),
        }
    }

    /// Lower a `public` declaration, supporting optional array sizes.
    fn lower_public_decl(&mut self, pair: Pair<Rule>) -> Result<(), IrError> {
        let mut inner = pair.into_inner();
        while let Some(child) = inner.next() {
            if child.as_rule() == Rule::identifier {
                let name = child.as_str();
                // Check for array_size following this identifier
                if let Some(next) = inner.peek() {
                    if next.as_rule() == Rule::array_size {
                        let size_pair = inner.next().unwrap();
                        let size_str = size_pair.into_inner().next().unwrap().as_str();
                        let size: usize = size_str
                            .parse()
                            .map_err(|_| IrError::ParseError(format!("invalid array size: {size_str}")))?;
                        self.declare_public_array(name, size);
                        continue;
                    }
                }
                self.declare_public(name);
            }
        }
        Ok(())
    }

    /// Lower a `witness` declaration, supporting optional array sizes.
    fn lower_witness_decl(&mut self, pair: Pair<Rule>) -> Result<(), IrError> {
        let mut inner = pair.into_inner();
        while let Some(child) = inner.next() {
            if child.as_rule() == Rule::identifier {
                let name = child.as_str();
                // Check for array_size following this identifier
                if let Some(next) = inner.peek() {
                    if next.as_rule() == Rule::array_size {
                        let size_pair = inner.next().unwrap();
                        let size_str = size_pair.into_inner().next().unwrap().as_str();
                        let size: usize = size_str
                            .parse()
                            .map_err(|_| IrError::ParseError(format!("invalid array size: {size_str}")))?;
                        self.declare_witness_array(name, size);
                        continue;
                    }
                }
                self.declare_witness(name);
            }
        }
        Ok(())
    }

    /// Lower a `fn` declaration: store in fn_table for later inlining.
    fn lower_fn_decl(&mut self, pair: Pair<Rule>) -> Result<(), IrError> {
        let mut inner = pair.into_inner();
        let name = inner.next().unwrap().as_str().to_string();

        let mut params = Vec::new();
        let mut body_pair = None;
        for child in inner {
            match child.as_rule() {
                Rule::param_list => {
                    for param in child.into_inner() {
                        if param.as_rule() == Rule::identifier {
                            params.push(param.as_str().to_string());
                        }
                    }
                }
                Rule::block => {
                    body_pair = Some(child);
                }
                _ => {}
            }
        }

        let body_source = body_pair.unwrap().as_str().to_string();
        self.fn_table.insert(name, FnDef { params, body_source });
        Ok(())
    }

    fn lower_let(&mut self, pair: Pair<Rule>) -> Result<(), IrError> {
        let mut inner = pair.into_inner();
        let name = inner.next().unwrap().as_str().to_string();
        let rhs = inner.next().unwrap();

        // Check if RHS is a bare list_literal (special array path)
        if is_list_literal(&rhs) {
            let elements = self.lower_list_elements(unwrap_to_list_literal(rhs))?;
            self.env.insert(name, EnvValue::Array(elements));
            return Ok(());
        }

        let v = self.lower_expr(rhs)?;
        // `let` is an alias — no instruction emitted, just env binding
        self.env.insert(name, EnvValue::Scalar(v));
        Ok(())
    }

    // ========================================================================
    // Expression lowering — dispatcher
    // ========================================================================

    fn lower_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        match pair.as_rule() {
            Rule::expr => {
                let inner = pair.into_inner().next().unwrap();
                self.lower_expr(inner)
            }
            Rule::or_expr => self.lower_or_expr(pair),
            Rule::and_expr => self.lower_and_expr(pair),
            Rule::cmp_expr => self.lower_cmp_expr(pair),
            Rule::add_expr => self.lower_add_expr(pair),
            Rule::mul_expr => self.lower_mul_expr(pair),
            Rule::pow_expr => self.lower_pow_expr(pair),
            Rule::prefix_expr => self.lower_prefix_expr(pair),
            Rule::postfix_expr => self.lower_postfix_expr(pair),
            Rule::atom => self.lower_atom(pair),
            _ => Err(IrError::UnsupportedOperation(format!(
                "unsupported expression rule: {:?}",
                pair.as_rule()
            ), span_of(&pair))),
        }
    }

    // ========================================================================
    // Atoms
    // ========================================================================

    fn lower_atom(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let inner = pair.into_inner().next().unwrap();
        let sp = span_of(&inner);
        match inner.as_rule() {
            Rule::number => self.lower_number(inner),
            Rule::identifier => {
                let name = inner.as_str();
                match self.env.get(name) {
                    Some(EnvValue::Scalar(v)) => Ok(*v),
                    Some(EnvValue::Array(_)) => Err(IrError::TypeMismatch {
                        expected: "scalar".into(),
                        got: "array".into(),
                        span: sp,
                    }),
                    None => Err(IrError::UndeclaredVariable(name.to_string(), sp)),
                }
            }
            Rule::expr => self.lower_expr(inner),
            Rule::if_expr => self.lower_if(inner),
            Rule::for_expr => self.lower_for(inner),
            Rule::block => self.lower_block(inner),
            Rule::while_expr | Rule::forever_expr => Err(IrError::UnboundedLoop(sp)),
            Rule::prove_expr => Err(IrError::UnsupportedOperation(
                "prove blocks cannot be nested inside circuits".into(), sp,
            )),
            Rule::fn_expr => Err(IrError::UnsupportedOperation(
                "closures are not supported in circuits".into(), sp,
            )),
            Rule::string => Err(IrError::TypeNotConstrainable("string".into(), sp)),
            Rule::true_lit => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ONE,
                });
                Ok(v)
            }
            Rule::false_lit => {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ZERO,
                });
                Ok(v)
            }
            Rule::nil_lit => Err(IrError::TypeNotConstrainable("nil".into(), sp)),
            Rule::list_literal => {
                // Arrays as standalone expressions are not scalar-valued.
                // They are only valid on the RHS of `let` (handled in lower_let).
                Err(IrError::TypeMismatch {
                    expected: "scalar".into(),
                    got: "array".into(),
                    span: sp,
                })
            }
            Rule::map_literal => Err(IrError::TypeNotConstrainable("map".into(), sp)),
            _ => Err(IrError::UnsupportedOperation(format!(
                "unsupported atom: {:?}", inner.as_rule()
            ), sp)),
        }
    }

    fn lower_number(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let s = pair.as_str();
        if s.contains('.') {
            return Err(IrError::TypeNotConstrainable(
                "decimal numbers are not supported in circuits".into(), span_of(&pair),
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
            // Emit Const(val) + Neg
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
    // Binary expressions
    // ========================================================================

    fn lower_add_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut pairs = pair.into_inner();
        let mut result = self.lower_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right = self.lower_expr(pairs.next().unwrap())?;
            let v = self.program.fresh_var();
            match op_pair.as_str() {
                "+" => {
                    self.program.push(Instruction::Add {
                        result: v,
                        lhs: result,
                        rhs: right,
                    });
                }
                "-" => {
                    self.program.push(Instruction::Sub {
                        result: v,
                        lhs: result,
                        rhs: right,
                    });
                }
                _ => {
                    return Err(IrError::UnsupportedOperation(format!(
                        "unknown additive operator: {}", op_pair.as_str()
                    ), span_of(&op_pair)));
                }
            }
            result = v;
        }
        Ok(result)
    }

    fn lower_mul_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut pairs = pair.into_inner();
        let mut result = self.lower_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right = self.lower_expr(pairs.next().unwrap())?;
            let v = self.program.fresh_var();
            match op_pair.as_str() {
                "*" => {
                    self.program.push(Instruction::Mul {
                        result: v,
                        lhs: result,
                        rhs: right,
                    });
                }
                "/" => {
                    self.program.push(Instruction::Div {
                        result: v,
                        lhs: result,
                        rhs: right,
                    });
                }
                "%" => {
                    return Err(IrError::UnsupportedOperation(
                        "modulo is not supported in circuits".into(), span_of(&op_pair),
                    ));
                }
                _ => {
                    return Err(IrError::UnsupportedOperation(format!(
                        "unknown multiplicative operator: {}", op_pair.as_str()
                    ), span_of(&op_pair)));
                }
            }
            result = v;
        }
        Ok(result)
    }

    fn lower_pow_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut pairs = pair.into_inner();
        let base = self.lower_expr(pairs.next().unwrap())?;

        if let Some(_pow_op) = pairs.next() {
            let exp_pair = pairs.next().unwrap();
            let exp_var = self.lower_expr(exp_pair)?;

            let exp_val = self.get_const_value(exp_var).ok_or_else(|| {
                IrError::UnsupportedOperation(
                    "exponent must be a constant integer in circuits".into(), None,
                )
            })?;
            let exp_u64 = field_to_u64(&exp_val).ok_or_else(|| {
                IrError::UnsupportedOperation(
                    "exponent too large for circuit compilation".into(), None,
                )
            })?;

            if pairs.next().is_some() {
                return Err(IrError::UnsupportedOperation(
                    "chained exponentiation is not supported in circuits".into(), None,
                ));
            }

            if exp_u64 == 0 {
                let v = self.program.fresh_var();
                self.program.push(Instruction::Const {
                    result: v,
                    value: FieldElement::ONE,
                });
                return Ok(v);
            }

            self.pow_by_squaring(base, exp_u64)
        } else {
            Ok(base)
        }
    }

    fn lower_prefix_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut inner = pair.into_inner();
        let mut neg_count = 0u32;
        let mut not_count = 0u32;
        let mut last = None;
        for child in inner.by_ref() {
            match child.as_rule() {
                Rule::unary_op => {
                    if child.as_str() == "-" {
                        neg_count += 1;
                    } else {
                        not_count += 1;
                    }
                }
                _ => {
                    last = Some(child);
                    break;
                }
            }
        }
        let mut result = self.lower_expr(last.unwrap())?;
        // Double negation cancels out
        if neg_count % 2 == 1 {
            let v = self.program.fresh_var();
            self.program.push(Instruction::Neg {
                result: v,
                operand: result,
            });
            result = v;
        }
        // Double NOT cancels out
        if not_count % 2 == 1 {
            let v = self.program.fresh_var();
            self.program.push(Instruction::Not {
                result: v,
                operand: result,
            });
            result = v;
        }
        Ok(result)
    }

    fn lower_postfix_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut inner = pair.into_inner();
        let atom = inner.next().unwrap();

        let maybe_op = inner.next();
        if let Some(ref op) = maybe_op {
            // --- Array indexing: arr[idx] ---
            if op.as_rule() == Rule::index_op {
                let sp = span_of(op);
                let atom_inner = atom.clone().into_inner().next().unwrap();
                if atom_inner.as_rule() == Rule::identifier {
                    let name = atom_inner.as_str();
                    match self.env.get(name).cloned() {
                        Some(EnvValue::Array(elements)) => {
                            // The index_op contains expr (bracket form) or identifier (dot form)
                            let idx_pair = op.clone().into_inner().next().unwrap();
                            let idx_var = self.lower_expr(idx_pair)?;
                            let idx_fe = self.get_const_value(idx_var).ok_or_else(|| {
                                IrError::UnsupportedOperation(
                                    "array index must be a compile-time constant".into(),
                                    sp.clone(),
                                )
                            })?;
                            let idx = field_to_u64(&idx_fe).ok_or_else(|| {
                                IrError::IndexOutOfBounds {
                                    name: name.to_string(),
                                    index: usize::MAX,
                                    length: elements.len(),
                                    span: sp.clone(),
                                }
                            })? as usize;
                            if idx >= elements.len() {
                                return Err(IrError::IndexOutOfBounds {
                                    name: name.to_string(),
                                    index: idx,
                                    length: elements.len(),
                                    span: sp,
                                });
                            }
                            return Ok(elements[idx]);
                        }
                        Some(EnvValue::Scalar(_)) => {
                            return Err(IrError::TypeMismatch {
                                expected: "array".into(),
                                got: "scalar".into(),
                                span: sp,
                            });
                        }
                        None => {
                            return Err(IrError::UndeclaredVariable(name.to_string(), sp));
                        }
                    }
                }
                return Err(IrError::UnsupportedOperation(
                    "indexing is only supported on array identifiers".into(),
                    sp,
                ));
            }

            // --- Function/builtin calls ---
            if op.as_rule() == Rule::call_op {
                let atom_inner = atom.clone().into_inner().next().unwrap();
                if atom_inner.as_rule() == Rule::identifier {
                    let name = atom_inner.as_str();
                    let sp = span_of(&atom_inner);
                    if inner.next().is_some() {
                        return Err(IrError::UnsupportedOperation(format!(
                            "chained postfix after `{name}` is not supported"
                        ), sp));
                    }
                    return match name {
                        "assert_eq" => self.lower_assert_eq(op.clone()),
                        "assert" => self.lower_assert(op.clone()),
                        "poseidon" => self.lower_poseidon(op.clone()),
                        "mux" => self.lower_mux(op.clone()),
                        "range_check" => self.lower_range_check(op.clone()),
                        "len" => self.lower_len(op.clone()),
                        "poseidon_many" => self.lower_poseidon_many(op.clone()),
                        "merkle_verify" => self.lower_merkle_verify(op.clone()),
                        _ => self.lower_user_fn_call(name, op.clone()),
                    };
                }
                return Err(IrError::UnsupportedOperation(
                    "function calls are not supported in circuits".into(), span_of(op),
                ));
            }
            return Err(IrError::UnsupportedOperation(format!(
                "unsupported postfix operation: {:?}", op.as_rule()
            ), span_of(op)));
        }

        self.lower_expr(atom)
    }

    fn lower_cmp_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut pairs = pair.into_inner();
        let mut result = self.lower_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right = self.lower_expr(pairs.next().unwrap())?;
            let v = self.program.fresh_var();
            match op_pair.as_str() {
                "==" => {
                    self.program.push(Instruction::IsEq {
                        result: v, lhs: result, rhs: right,
                    });
                }
                "!=" => {
                    self.program.push(Instruction::IsNeq {
                        result: v, lhs: result, rhs: right,
                    });
                }
                "<" => {
                    self.program.push(Instruction::IsLt {
                        result: v, lhs: result, rhs: right,
                    });
                }
                "<=" => {
                    self.program.push(Instruction::IsLe {
                        result: v, lhs: result, rhs: right,
                    });
                }
                ">" => {
                    // a > b  ≡  b < a
                    self.program.push(Instruction::IsLt {
                        result: v, lhs: right, rhs: result,
                    });
                }
                ">=" => {
                    // a >= b  ≡  b <= a
                    self.program.push(Instruction::IsLe {
                        result: v, lhs: right, rhs: result,
                    });
                }
                _ => {
                    return Err(IrError::UnsupportedOperation(format!(
                        "unknown comparison operator: {}", op_pair.as_str()
                    ), span_of(&op_pair)));
                }
            }
            result = v;
        }
        Ok(result)
    }

    // ========================================================================
    // Logical operators
    // ========================================================================

    fn lower_and_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut pairs = pair.into_inner();
        let mut result = self.lower_expr(pairs.next().unwrap())?;

        while let Some(_op) = pairs.next() {
            let right = self.lower_expr(pairs.next().unwrap())?;
            let v = self.program.fresh_var();
            self.program.push(Instruction::And {
                result: v, lhs: result, rhs: right,
            });
            result = v;
        }
        Ok(result)
    }

    fn lower_or_expr(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut pairs = pair.into_inner();
        let mut result = self.lower_expr(pairs.next().unwrap())?;

        while let Some(_op) = pairs.next() {
            let right = self.lower_expr(pairs.next().unwrap())?;
            let v = self.program.fresh_var();
            self.program.push(Instruction::Or {
                result: v, lhs: result, rhs: right,
            });
            result = v;
        }
        Ok(result)
    }

    // ========================================================================
    // Builtins
    // ========================================================================

    fn lower_assert_eq(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "assert_eq".into(),
                expected: 2,
                got: args.len(),
                span: None,
            });
        }
        let a = self.lower_expr(args[0].clone())?;
        let b = self.lower_expr(args[1].clone())?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::AssertEq {
            result: v,
            lhs: a,
            rhs: b,
        });
        Ok(v)
    }

    fn lower_assert(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 1 {
            return Err(IrError::WrongArgumentCount {
                builtin: "assert".into(),
                expected: 1,
                got: args.len(),
                span: None,
            });
        }
        let operand = self.lower_expr(args[0].clone())?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::Assert {
            result: v,
            operand,
        });
        Ok(v)
    }

    fn lower_poseidon(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "poseidon".into(),
                expected: 2,
                got: args.len(),
                span: None,
            });
        }
        let left = self.lower_expr(args[0].clone())?;
        let right = self.lower_expr(args[1].clone())?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::PoseidonHash {
            result: v,
            left,
            right,
        });
        Ok(v)
    }

    fn lower_mux(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 3 {
            return Err(IrError::WrongArgumentCount {
                builtin: "mux".into(),
                expected: 3,
                got: args.len(),
                span: None,
            });
        }
        let cond = self.lower_expr(args[0].clone())?;
        let if_true = self.lower_expr(args[1].clone())?;
        let if_false = self.lower_expr(args[2].clone())?;
        let v = self.program.fresh_var();
        self.program.push(Instruction::Mux {
            result: v,
            cond,
            if_true,
            if_false,
        });
        Ok(v)
    }

    fn lower_range_check(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 2 {
            return Err(IrError::WrongArgumentCount {
                builtin: "range_check".into(),
                expected: 2,
                got: args.len(),
                span: None,
            });
        }
        let operand = self.lower_expr(args[0].clone())?;
        let bits_var = self.lower_expr(args[1].clone())?;

        // Second argument must be a compile-time constant
        let bits_fe = self.get_const_value(bits_var).ok_or_else(|| {
            IrError::UnsupportedOperation(
                "range_check bits argument must be a constant integer".into(), None,
            )
        })?;
        let bits = field_to_u64(&bits_fe).ok_or_else(|| {
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

    fn lower_len(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let sp = span_of(&call_op);
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 1 {
            return Err(IrError::WrongArgumentCount {
                builtin: "len".into(),
                expected: 1,
                got: args.len(),
                span: sp,
            });
        }
        let arg_name = self.resolve_identifier_name(&args[0]).ok_or_else(|| {
            IrError::UnsupportedOperation(
                "len() argument must be an array identifier".into(),
                sp.clone(),
            )
        })?;
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

    fn lower_poseidon_many(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let sp = span_of(&call_op);
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.is_empty() {
            return Err(IrError::WrongArgumentCount {
                builtin: "poseidon_many".into(),
                expected: 1,
                got: 0,
                span: sp,
            });
        }
        let lowered: Vec<SsaVar> = args
            .into_iter()
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

    fn lower_merkle_verify(&mut self, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let sp = span_of(&call_op);
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 4 {
            return Err(IrError::WrongArgumentCount {
                builtin: "merkle_verify".into(),
                expected: 4,
                got: args.len(),
                span: sp.clone(),
            });
        }

        // Resolve each argument: root (scalar), leaf (scalar), path (array), indices (array)
        let root_val = self.resolve_arg_value(args[0].clone())?;
        let leaf_val = self.resolve_arg_value(args[1].clone())?;
        let path_val = self.resolve_arg_value(args[2].clone())?;
        let indices_val = self.resolve_arg_value(args[3].clone())?;

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
            // left_hash = poseidon(current, path[i])
            let left_hash = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: left_hash,
                left: current,
                right: path[i],
            });
            // right_hash = poseidon(path[i], current)
            let right_hash = self.program.fresh_var();
            self.program.push(Instruction::PoseidonHash {
                result: right_hash,
                left: path[i],
                right: current,
            });
            // current = mux(indices[i], right_hash, left_hash)
            let mux_result = self.program.fresh_var();
            self.program.push(Instruction::Mux {
                result: mux_result,
                cond: indices[i],
                if_true: right_hash,
                if_false: left_hash,
            });
            current = mux_result;
        }

        // assert_eq(current, root)
        let v = self.program.fresh_var();
        self.program.push(Instruction::AssertEq {
            result: v,
            lhs: current,
            rhs: root,
        });
        Ok(v)
    }

    /// Handle a call to a user-defined function (inline the body).
    fn lower_user_fn_call(&mut self, name: &str, call_op: Pair<Rule>) -> Result<SsaVar, IrError> {
        let sp = span_of(&call_op);

        // Look up in fn_table
        let fn_def = match self.fn_table.get(name).cloned() {
            Some(fd) => fd,
            None => {
                return Err(IrError::UnsupportedOperation(
                    format!("function `{name}` is not defined"),
                    sp,
                ));
            }
        };

        // Lower arguments
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        let arg_vars: Vec<SsaVar> = args
            .into_iter()
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

        // Re-parse and lower the function body
        let body_parsed = AchronymeParser::parse(Rule::block, &fn_def.body_source)
            .map_err(|e| IrError::ParseError(e.to_string()))?;
        let block = body_parsed
            .into_iter()
            .next()
            .ok_or_else(|| IrError::ParseError("empty function body".into()))?;
        let result = self.lower_block(block)?;

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
    // Control flow
    // ========================================================================

    /// Lower `if cond { a } else { b }` as a MUX: `result = mux(cond, a, b)`.
    ///
    /// **Important**: Both branches are always fully lowered and all their
    /// constraints (assert_eq, assert, etc.) are emitted unconditionally.
    /// The MUX only selects which *value* to return. This is an inherent
    /// limitation of arithmetic circuits — there is no conditional execution.
    fn lower_if(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut inner = pair.into_inner();

        let cond_pair = inner.next().unwrap();
        let cond = self.lower_expr(cond_pair)?;

        let then_block = inner.next().unwrap();
        let if_true = self.lower_block(then_block)?;

        let if_false = if let Some(else_part) = inner.next() {
            match else_part.as_rule() {
                Rule::block => self.lower_block(else_part)?,
                Rule::if_expr => self.lower_if(else_part)?,
                _ => self.lower_expr(else_part)?,
            }
        } else {
            // No else branch → 0
            let v = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: v,
                value: FieldElement::ZERO,
            });
            v
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

    fn lower_for(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let mut inner = pair.into_inner();
        let ident = inner.next().unwrap().as_str().to_string();
        let range_or_expr = inner.next().unwrap();

        // Check if iterating over an array identifier
        if range_or_expr.as_rule() != Rule::range_expr {
            // Try to resolve as identifier → array
            let sp = span_of(&range_or_expr);
            let iterable_name = self.resolve_identifier_name(&range_or_expr);
            if let Some(name) = iterable_name {
                if let Some(EnvValue::Array(elems)) = self.env.get(&name).cloned() {
                    let body = inner.next().unwrap();
                    let mut last = None;
                    for elem_var in &elems {
                        self.env.insert(ident.clone(), EnvValue::Scalar(*elem_var));
                        last = Some(self.lower_block(body.clone())?);
                    }
                    self.env.remove(&ident);
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
            return Err(IrError::UnsupportedOperation(
                "for loops in circuits require a literal range (e.g., 0..5) or an array".into(),
                sp,
            ));
        }

        let mut range_inner = range_or_expr.into_inner();
        let start_str = range_inner.next().unwrap().as_str();
        let end_str = range_inner.next().unwrap().as_str();

        let start: u64 = start_str
            .parse()
            .map_err(|_| IrError::ParseError(format!("invalid range start: {start_str}")))?;
        let end: u64 = end_str
            .parse()
            .map_err(|_| IrError::ParseError(format!("invalid range end: {end_str}")))?;

        let body = inner.next().unwrap();

        let iterations = end.saturating_sub(start);
        if iterations > MAX_UNROLL_ITERATIONS {
            return Err(IrError::UnsupportedOperation(
                format!(
                    "for loop range {start}..{end} has {iterations} iterations, \
                     exceeding the maximum of {MAX_UNROLL_ITERATIONS}"
                ),
                span_of(&body),
            ));
        }

        let mut last = None;
        for i in start..end {
            // Bind iterator variable to constant
            let cv = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: cv,
                value: FieldElement::from_u64(i),
            });
            self.env.insert(ident.clone(), EnvValue::Scalar(cv));
            last = Some(self.lower_block(body.clone())?);
        }

        self.env.remove(&ident);

        // Return last iteration's result, or zero if empty range
        Ok(last.unwrap_or_else(|| {
            let v = self.program.fresh_var();
            self.program.push(Instruction::Const {
                result: v,
                value: FieldElement::ZERO,
            });
            v
        }))
    }

    fn lower_block(&mut self, pair: Pair<Rule>) -> Result<SsaVar, IrError> {
        let outer_keys: std::collections::HashSet<String> =
            self.env.keys().cloned().collect();
        let mut last_var = None;
        for child in pair.into_inner() {
            match child.as_rule() {
                Rule::stmt => {
                    let inner = child.into_inner().next().unwrap();
                    match inner.as_rule() {
                        Rule::let_decl => {
                            self.lower_let(inner)?;
                            last_var = None;
                        }
                        Rule::expr
                        | Rule::or_expr
                        | Rule::and_expr
                        | Rule::cmp_expr
                        | Rule::add_expr
                        | Rule::mul_expr
                        | Rule::pow_expr
                        | Rule::prefix_expr
                        | Rule::postfix_expr
                        | Rule::atom => {
                            last_var = Some(self.lower_expr(inner)?);
                        }
                        _ => {
                            self.lower_stmt_inner(inner)?;
                            last_var = None;
                        }
                    }
                }
                _ => {}
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

    fn lower_stmt_inner(&mut self, inner: Pair<Rule>) -> Result<(), IrError> {
        let sp = span_of(&inner);
        match inner.as_rule() {
            Rule::public_decl => self.lower_public_decl(inner),
            Rule::witness_decl => self.lower_witness_decl(inner),
            Rule::fn_decl => self.lower_fn_decl(inner),
            Rule::mut_decl => Err(IrError::UnsupportedOperation(
                "mutable variables are not supported in circuits".into(), sp,
            )),
            Rule::print_stmt => Err(IrError::UnsupportedOperation(
                "print is not supported in circuits".into(), sp,
            )),
            Rule::assignment => Err(IrError::UnsupportedOperation(
                "assignment is not supported in circuits".into(), sp,
            )),
            Rule::break_stmt => Err(IrError::UnsupportedOperation(
                "break is not supported in circuits".into(), sp,
            )),
            Rule::continue_stmt => Err(IrError::UnsupportedOperation(
                "continue is not supported in circuits".into(), sp,
            )),
            Rule::return_stmt => Err(IrError::UnsupportedOperation(
                "return is not supported in circuits".into(), sp,
            )),
            _ => Err(IrError::UnsupportedOperation(format!(
                "{:?}", inner.as_rule()
            ), sp)),
        }
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

    /// Lower the elements of a list_literal pair into a Vec<SsaVar>.
    fn lower_list_elements(&mut self, pair: Pair<Rule>) -> Result<Vec<SsaVar>, IrError> {
        let sp = span_of(&pair);
        let elements: Vec<Pair<Rule>> = pair.into_inner().collect();
        if elements.is_empty() {
            return Err(IrError::UnsupportedOperation(
                "empty arrays are not allowed in circuits".into(),
                sp,
            ));
        }
        let mut vars = Vec::with_capacity(elements.len());
        for elem in elements {
            vars.push(self.lower_expr(elem)?);
        }
        Ok(vars)
    }

    /// Try to extract an identifier name from an expression pair
    /// by walking through single-child wrappers.
    fn resolve_identifier_name(&self, pair: &Pair<Rule>) -> Option<String> {
        let mut current = pair.clone();
        loop {
            match current.as_rule() {
                Rule::identifier => return Some(current.as_str().to_string()),
                Rule::expr
                | Rule::or_expr
                | Rule::and_expr
                | Rule::cmp_expr
                | Rule::add_expr
                | Rule::mul_expr
                | Rule::pow_expr
                | Rule::prefix_expr
                | Rule::postfix_expr
                | Rule::atom => {
                    let children: Vec<Pair<Rule>> = current.into_inner().collect();
                    if children.len() == 1 {
                        current = children.into_iter().next().unwrap();
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }
    }

    /// Resolve a call argument to either Scalar or Array.
    fn resolve_arg_value(&mut self, pair: Pair<Rule>) -> Result<EnvValue, IrError> {
        // Check if the argument is a bare identifier referencing an array
        if let Some(name) = self.resolve_identifier_name(&pair) {
            if let Some(ev) = self.env.get(&name) {
                return Ok(ev.clone());
            }
        }
        // Otherwise lower as scalar expression
        let v = self.lower_expr(pair)?;
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

/// Check if a pair is a list_literal wrapped in expression layers.
fn is_list_literal(pair: &Pair<Rule>) -> bool {
    let mut current = pair.clone();
    loop {
        match current.as_rule() {
            Rule::list_literal => return true,
            Rule::expr
            | Rule::or_expr
            | Rule::and_expr
            | Rule::cmp_expr
            | Rule::add_expr
            | Rule::mul_expr
            | Rule::pow_expr
            | Rule::prefix_expr
            | Rule::postfix_expr
            | Rule::atom => {
                let children: Vec<Pair<Rule>> = current.into_inner().collect();
                if children.len() == 1 {
                    current = children.into_iter().next().unwrap();
                } else {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

/// Unwrap expression wrappers to get the inner list_literal pair.
fn unwrap_to_list_literal(pair: Pair<Rule>) -> Pair<Rule> {
    let mut current = pair;
    loop {
        match current.as_rule() {
            Rule::list_literal => return current,
            _ => {
                current = current.into_inner().next().unwrap();
            }
        }
    }
}
