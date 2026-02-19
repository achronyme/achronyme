use std::collections::HashMap;

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

/// Lowers an Achronyme AST into an SSA IR program.
pub struct IrLowering {
    program: IrProgram,
    /// Maps variable names to their current SSA variable (aliasing, not copying).
    env: HashMap<String, SsaVar>,
}

impl IrLowering {
    pub fn new() -> Self {
        Self {
            program: IrProgram::new(),
            env: HashMap::new(),
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
        self.env.insert(name.to_string(), v);
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
        self.env.insert(name.to_string(), v);
        v
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
    pub fn lower_circuit(
        source: &str,
        public: &[&str],
        witness: &[&str],
    ) -> Result<IrProgram, IrError> {
        let mut lowering = IrLowering::new();
        for name in public {
            lowering.declare_public(name);
        }
        for name in witness {
            lowering.declare_witness(name);
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

        // Pass 1: collect declaration names
        let mut pub_names = Vec::new();
        let mut wit_names = Vec::new();
        for stmt in &stmts {
            let inner = stmt.clone().into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::public_decl => {
                    for child in inner.into_inner() {
                        if child.as_rule() == Rule::identifier {
                            pub_names.push(child.as_str().to_string());
                        }
                    }
                }
                Rule::witness_decl => {
                    for child in inner.into_inner() {
                        if child.as_rule() == Rule::identifier {
                            wit_names.push(child.as_str().to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        // Emit Inputs in correct order: public first, then witness
        let mut lowering = IrLowering::new();
        for name in &pub_names {
            lowering.declare_public(name);
        }
        for name in &wit_names {
            lowering.declare_witness(name);
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
                for child in inner.into_inner() {
                    if child.as_rule() == Rule::identifier {
                        self.declare_public(child.as_str());
                    }
                }
                Ok(None)
            }
            Rule::witness_decl => {
                for child in inner.into_inner() {
                    if child.as_rule() == Rule::identifier {
                        self.declare_witness(child.as_str());
                    }
                }
                Ok(None)
            }
            Rule::let_decl => {
                self.lower_let(inner)?;
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

    fn lower_let(&mut self, pair: Pair<Rule>) -> Result<(), IrError> {
        let mut inner = pair.into_inner();
        let name = inner.next().unwrap().as_str().to_string();
        let expr = inner.next().unwrap();
        let v = self.lower_expr(expr)?;
        // `let` is an alias — no instruction emitted, just env binding
        self.env.insert(name, v);
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
                self.env
                    .get(name)
                    .copied()
                    .ok_or_else(|| IrError::UndeclaredVariable(name.to_string(), sp.clone()))
            }
            Rule::expr => self.lower_expr(inner),
            Rule::if_expr => self.lower_if(inner),
            Rule::for_expr => self.lower_for(inner),
            Rule::block => self.lower_block(inner),
            Rule::while_expr | Rule::forever_expr => Err(IrError::UnboundedLoop(sp)),
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
            Rule::list_literal => Err(IrError::TypeNotConstrainable("list".into(), sp)),
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
        let val = digits
            .parse::<u64>()
            .map_err(|_| IrError::ParseError(format!("invalid integer: {s}")))?;
        let fe = FieldElement::from_u64(val);
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

        let maybe_call = inner.next();
        if let Some(ref call) = maybe_call {
            if call.as_rule() == Rule::call_op {
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
                        "assert_eq" => self.lower_assert_eq(call.clone()),
                        "assert" => self.lower_assert(call.clone()),
                        "poseidon" => self.lower_poseidon(call.clone()),
                        "mux" => self.lower_mux(call.clone()),
                        "range_check" => self.lower_range_check(call.clone()),
                        _ => Err(IrError::UnsupportedOperation(format!(
                            "function call `{name}` is not supported in circuits"
                        ), span_of(&atom_inner))),
                    };
                }
                return Err(IrError::UnsupportedOperation(
                    "function calls are not supported in circuits".into(), span_of(call),
                ));
            }
            return Err(IrError::UnsupportedOperation(format!(
                "unsupported postfix operation: {:?}", call.as_rule()
            ), span_of(call)));
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

        if range_or_expr.as_rule() != Rule::range_expr {
            return Err(IrError::UnsupportedOperation(
                "for loops in circuits require a literal range (e.g., 0..5)".into(),
                span_of(&range_or_expr),
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
            self.env.insert(ident.clone(), cv);
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
            Rule::public_decl => {
                for child in inner.into_inner() {
                    if child.as_rule() == Rule::identifier {
                        self.declare_public(child.as_str());
                    }
                }
                Ok(())
            }
            Rule::witness_decl => {
                for child in inner.into_inner() {
                    if child.as_rule() == Rule::identifier {
                        self.declare_witness(child.as_str());
                    }
                }
                Ok(())
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
}

/// Try to extract a small u64 from a FieldElement.
fn field_to_u64(fe: &FieldElement) -> Option<u64> {
    let limbs = fe.to_canonical();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(limbs[0])
}
