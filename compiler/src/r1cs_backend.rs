use constraints::poseidon::{poseidon_hash_circuit, PoseidonParams};
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use memory::FieldElement;
use std::collections::HashMap;

use achronyme_parser::{AchronymeParser, Rule};
use pest::iterators::Pair;
use pest::Parser;

use crate::r1cs_error::R1CSError;

/// Compiles an Achronyme circuit block into an R1CS constraint system.
///
/// The R1CSCompiler walks the pest AST and emits R1CS constraints instead of
/// bytecode. Each expression evaluates to a `LinearCombination`, and only
/// multiplications / materializations generate actual constraints.
pub struct R1CSCompiler {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem,
    /// Map from Achronyme variable name → R1CS wire.
    pub bindings: HashMap<String, Variable>,
    /// Map from variable name → LinearCombination (avoids materializing sums/subtractions).
    pub lc_bindings: HashMap<String, LinearCombination>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
    /// Cached Poseidon parameters. Initialized on first `poseidon()` call.
    poseidon_params: Option<PoseidonParams>,
}

impl R1CSCompiler {
    /// Create an empty R1CS compiler with a fresh constraint system.
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
            bindings: HashMap::new(),
            lc_bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
            poseidon_params: None,
        }
    }

    /// Declare a public input variable and bind it to `name`.
    ///
    /// Public inputs must be declared before witnesses to maintain the
    /// snarkjs-compatible wire layout.
    pub fn declare_public(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_input();
        self.bindings.insert(name.to_string(), var);
        self.public_inputs.push(name.to_string());
        var
    }

    /// Declare a private witness variable and bind it to `name`.
    pub fn declare_witness(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_witness();
        self.bindings.insert(name.to_string(), var);
        self.witnesses.push(name.to_string());
        var
    }

    /// Look up a previously declared variable by name.
    pub fn lookup(&self, name: &str) -> Result<Variable, R1CSError> {
        self.bindings
            .get(name)
            .copied()
            .ok_or_else(|| R1CSError::UndeclaredVariable(name.to_string()))
    }

    /// Look up a variable as a LinearCombination.
    /// First checks `lc_bindings` (for let-bound expressions), then falls back
    /// to `bindings` (for declared public/witness variables).
    pub fn lookup_lc(&self, name: &str) -> Result<LinearCombination, R1CSError> {
        if let Some(lc) = self.lc_bindings.get(name) {
            return Ok(lc.clone());
        }
        let var = self.lookup(name)?;
        Ok(LinearCombination::from_variable(var))
    }

    // ========================================================================
    // Entry point
    // ========================================================================

    /// Parse and compile an Achronyme source string into R1CS constraints.
    ///
    /// Public inputs and witnesses must be declared before calling this method.
    pub fn compile_circuit(&mut self, source: &str) -> Result<(), R1CSError> {
        let pairs = AchronymeParser::parse(Rule::program, source)
            .map_err(|e| R1CSError::ParseError(e.to_string()))?;

        let program = pairs.into_iter().next().unwrap();
        for pair in program.into_inner() {
            match pair.as_rule() {
                Rule::stmt => self.compile_stmt(pair)?,
                Rule::EOI => {}
                _ => {}
            }
        }
        Ok(())
    }

    // ========================================================================
    // Statement compilation
    // ========================================================================

    fn compile_stmt(&mut self, pair: Pair<Rule>) -> Result<(), R1CSError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::let_decl => self.compile_let(inner),
            Rule::expr => {
                // Top-level expression statement (e.g., assert_eq call)
                self.compile_expr(inner)?;
                Ok(())
            }
            Rule::cmp_expr | Rule::add_expr | Rule::mul_expr | Rule::pow_expr
            | Rule::prefix_expr | Rule::postfix_expr | Rule::atom => {
                self.compile_expr(inner)?;
                Ok(())
            }
            Rule::mut_decl => Err(R1CSError::UnsupportedOperation(
                "mutable variables are not supported in circuits".into(),
            )),
            Rule::print_stmt => Err(R1CSError::UnsupportedOperation(
                "print is not supported in circuits".into(),
            )),
            Rule::assignment => Err(R1CSError::UnsupportedOperation(
                "assignment is not supported in circuits".into(),
            )),
            Rule::break_stmt => Err(R1CSError::UnsupportedOperation(
                "break is not supported in circuits".into(),
            )),
            Rule::continue_stmt => Err(R1CSError::UnsupportedOperation(
                "continue is not supported in circuits".into(),
            )),
            Rule::return_stmt => Err(R1CSError::UnsupportedOperation(
                "return is not supported in circuits".into(),
            )),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "{:?}",
                inner.as_rule()
            ))),
        }
    }

    fn compile_let(&mut self, pair: Pair<Rule>) -> Result<(), R1CSError> {
        let mut inner = pair.into_inner();
        let name = inner.next().unwrap().as_str().to_string();
        let expr = inner.next().unwrap();
        let lc = self.compile_expr(expr)?;
        self.lc_bindings.insert(name, lc);
        Ok(())
    }

    // ========================================================================
    // Expression compilation — dispatcher
    // ========================================================================

    fn compile_expr(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError> {
        match pair.as_rule() {
            Rule::expr => {
                let inner = pair.into_inner().next().unwrap();
                self.compile_expr(inner)
            }
            Rule::cmp_expr => self.compile_cmp_expr(pair),
            Rule::add_expr => self.compile_add_expr(pair),
            Rule::mul_expr => self.compile_mul_expr(pair),
            Rule::pow_expr => self.compile_pow_expr(pair),
            Rule::prefix_expr => self.compile_prefix_expr(pair),
            Rule::postfix_expr => self.compile_postfix_expr(pair),
            Rule::atom => self.compile_atom(pair),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "unsupported expression rule: {:?}",
                pair.as_rule()
            ))),
        }
    }

    // ========================================================================
    // Atom compilation
    // ========================================================================

    fn compile_atom(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError> {
        let inner = pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::number => self.compile_number(inner),
            Rule::identifier => {
                let name = inner.as_str();
                self.lookup_lc(name)
            }
            Rule::expr => self.compile_expr(inner),
            Rule::if_expr => self.compile_if(inner),
            Rule::for_expr => {
                self.compile_for(inner)?;
                Ok(LinearCombination::zero())
            }
            Rule::block => self.compile_block(inner),
            Rule::while_expr => Err(R1CSError::UnboundedLoop),
            Rule::forever_expr => Err(R1CSError::UnboundedLoop),
            Rule::fn_expr => Err(R1CSError::UnsupportedOperation(
                "closures are not supported in circuits".into(),
            )),
            Rule::string => Err(R1CSError::TypeNotConstrainable("string".into())),
            Rule::true_lit | Rule::false_lit => {
                Err(R1CSError::TypeNotConstrainable("bool".into()))
            }
            Rule::nil_lit => Err(R1CSError::TypeNotConstrainable("nil".into())),
            Rule::list_literal => Err(R1CSError::TypeNotConstrainable("list".into())),
            Rule::map_literal => Err(R1CSError::TypeNotConstrainable("map".into())),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "unsupported atom: {:?}",
                inner.as_rule()
            ))),
        }
    }

    fn compile_number(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError> {
        let s = pair.as_str();
        // Reject decimals — field elements are integers only
        if s.contains('.') {
            return Err(R1CSError::TypeNotConstrainable(
                "decimal numbers are not supported in circuits".into(),
            ));
        }
        // Handle optional negative sign
        let (negative, digits) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };
        let val = digits
            .parse::<u64>()
            .map_err(|_| R1CSError::ParseError(format!("invalid integer: {s}")))?;
        let fe = FieldElement::from_u64(val);
        let fe = if negative { fe.neg() } else { fe };
        Ok(LinearCombination::from_constant(fe))
    }

    // ========================================================================
    // Binary expression compilation
    // ========================================================================

    fn compile_add_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut pairs = pair.into_inner();
        let mut result = self.compile_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right = self.compile_expr(pairs.next().unwrap())?;
            match op_pair.as_str() {
                "+" => result = result + right,
                "-" => result = result - right,
                _ => {
                    return Err(R1CSError::UnsupportedOperation(format!(
                        "unknown additive operator: {}",
                        op_pair.as_str()
                    )))
                }
            }
        }
        Ok(result)
    }

    fn compile_mul_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut pairs = pair.into_inner();
        let mut result = self.compile_expr(pairs.next().unwrap())?;

        while let Some(op_pair) = pairs.next() {
            let right = self.compile_expr(pairs.next().unwrap())?;
            match op_pair.as_str() {
                "*" => result = self.multiply_lcs(&result, &right),
                "/" => result = self.divide_lcs(&result, &right)?,
                "%" => {
                    return Err(R1CSError::UnsupportedOperation(
                        "modulo is not supported in circuits".into(),
                    ))
                }
                _ => {
                    return Err(R1CSError::UnsupportedOperation(format!(
                        "unknown multiplicative operator: {}",
                        op_pair.as_str()
                    )))
                }
            }
        }
        Ok(result)
    }

    fn compile_pow_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut pairs = pair.into_inner();
        let base = self.compile_expr(pairs.next().unwrap())?;

        if let Some(_pow_op) = pairs.next() {
            let exp_pair = pairs.next().unwrap();
            // The exponent must be a compile-time constant integer
            let exp_lc = self.compile_expr(exp_pair)?;
            let exp_val = exp_lc.constant_value().ok_or_else(|| {
                R1CSError::UnsupportedOperation(
                    "exponent must be a constant integer in circuits".into(),
                )
            })?;
            // Convert FieldElement to u64 for exponentiation
            let exp_u64 = field_to_u64(&exp_val).ok_or_else(|| {
                R1CSError::UnsupportedOperation(
                    "exponent too large for circuit compilation".into(),
                )
            })?;
            if exp_u64 == 0 {
                return Ok(LinearCombination::from_constant(FieldElement::ONE));
            }
            // If there are more pow ops (right-associative chaining), reject for simplicity
            if pairs.next().is_some() {
                return Err(R1CSError::UnsupportedOperation(
                    "chained exponentiation is not supported in circuits".into(),
                ));
            }
            self.pow_by_squaring(&base, exp_u64)
        } else {
            Ok(base)
        }
    }

    fn compile_prefix_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut inner = pair.into_inner();
        // Collect unary ops
        let mut neg_count = 0u32;
        let mut last = None;
        for child in inner.by_ref() {
            match child.as_rule() {
                Rule::unary_op => {
                    if child.as_str() == "-" {
                        neg_count += 1;
                    }
                }
                _ => {
                    last = Some(child);
                    break;
                }
            }
        }
        let operand = self.compile_expr(last.unwrap())?;
        if neg_count % 2 == 1 {
            // Negate: multiply by -1 (scalar, 0 constraints)
            Ok(operand * FieldElement::ONE.neg())
        } else {
            Ok(operand)
        }
    }

    fn compile_postfix_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut inner = pair.into_inner();
        let atom = inner.next().unwrap();

        // Peek ahead: if the next token is a call_op, check for builtins
        let maybe_call = inner.next();
        if let Some(ref call) = maybe_call {
            if call.as_rule() == Rule::call_op {
                // Check if atom is an identifier (builtin name)
                let atom_inner = atom.clone().into_inner().next().unwrap();
                if atom_inner.as_rule() == Rule::identifier {
                    let name = atom_inner.as_str();
                    // Reject chained postfix for all builtins
                    if inner.next().is_some() {
                        return Err(R1CSError::UnsupportedOperation(format!(
                            "chained postfix after `{name}` is not supported"
                        )));
                    }
                    return match name {
                        "assert_eq" => self.compile_assert_eq(call.clone()),
                        "poseidon" => self.compile_poseidon(call.clone()),
                        "mux" => self.compile_mux(call.clone()),
                        _ => Err(R1CSError::UnsupportedOperation(format!(
                            "function call `{name}` is not supported in circuits"
                        ))),
                    };
                }
                return Err(R1CSError::UnsupportedOperation(
                    "function calls are not supported in circuits".into(),
                ));
            }
            return Err(R1CSError::UnsupportedOperation(format!(
                "unsupported postfix operation: {:?}",
                call.as_rule()
            )));
        }

        // No postfix ops — just compile the atom
        self.compile_expr(atom)
    }

    fn compile_cmp_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut inner = pair.into_inner();
        let first = inner.next().unwrap();
        let result = self.compile_expr(first)?;

        // If there's a comparison operator, reject (comparisons aren't directly
        // representable in R1CS without range proofs)
        if inner.next().is_some() {
            return Err(R1CSError::UnsupportedOperation(
                "comparison operators are not directly supported in circuits".into(),
            ));
        }
        Ok(result)
    }

    // ========================================================================
    // Builtin compilation
    // ========================================================================

    /// Handle `assert_eq(a, b)`: enforces a == b (1 constraint).
    fn compile_assert_eq(
        &mut self,
        call_op: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 2 {
            return Err(R1CSError::WrongArgumentCount {
                builtin: "assert_eq".into(),
                expected: 2,
                got: args.len(),
            });
        }

        let a = self.compile_expr(args[0].clone())?;
        let b = self.compile_expr(args[1].clone())?;

        self.cs.enforce_equal(a, b.clone());
        Ok(b)
    }

    /// Handle `poseidon(left, right)`: Poseidon 2-to-1 hash in-circuit (~360 constraints).
    fn compile_poseidon(
        &mut self,
        call_op: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 2 {
            return Err(R1CSError::WrongArgumentCount {
                builtin: "poseidon".into(),
                expected: 2,
                got: args.len(),
            });
        }

        let left_lc = self.compile_expr(args[0].clone())?;
        let right_lc = self.compile_expr(args[1].clone())?;

        let left_var = self.materialize_lc(&left_lc);
        let right_var = self.materialize_lc(&right_lc);

        // Lazy-init Poseidon params
        if self.poseidon_params.is_none() {
            self.poseidon_params = Some(PoseidonParams::bn254_t3());
        }
        let params = self.poseidon_params.as_ref().unwrap();

        let hash_var = poseidon_hash_circuit(&mut self.cs, params, left_var, right_var);
        Ok(LinearCombination::from_variable(hash_var))
    }

    /// Handle `mux(cond, if_true, if_false)`: conditional selection (2 constraints).
    ///
    /// Generates:
    /// 1. Boolean enforcement: `cond * (1 - cond) = 0`
    /// 2. MUX: `result = cond * (if_true - if_false) + if_false`
    fn compile_mux(
        &mut self,
        call_op: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let args: Vec<Pair<Rule>> = call_op.into_inner().collect();
        if args.len() != 3 {
            return Err(R1CSError::WrongArgumentCount {
                builtin: "mux".into(),
                expected: 3,
                got: args.len(),
            });
        }

        let cond_lc = self.compile_expr(args[0].clone())?;
        let then_lc = self.compile_expr(args[1].clone())?;
        let else_lc = self.compile_expr(args[2].clone())?;

        // Boolean enforcement: cond * (1 - cond) = 0
        let one = LinearCombination::from_constant(FieldElement::ONE);
        let one_minus_cond = one - cond_lc.clone();
        self.cs
            .enforce(cond_lc.clone(), one_minus_cond, LinearCombination::zero());

        // MUX: result = cond * (then - else) + else
        let diff = then_lc - else_lc.clone();
        let selected = self.multiply_lcs(&cond_lc, &diff);
        Ok(selected + else_lc)
    }

    // ========================================================================
    // Materialization
    // ========================================================================

    /// Convert a `LinearCombination` to a `Variable`.
    ///
    /// If the LC is already a single variable with coefficient 1, returns it
    /// directly (0 constraints). Otherwise allocates a fresh witness variable
    /// and enforces equality (1 constraint).
    fn materialize_lc(&mut self, lc: &LinearCombination) -> Variable {
        if let Some(var) = lc.as_single_variable() {
            return var;
        }
        let var = self.cs.alloc_witness();
        self.cs
            .enforce_equal(lc.clone(), LinearCombination::from_variable(var));
        var
    }

    // ========================================================================
    // Control flow compilation
    // ========================================================================

    /// Compile a block `{ stmt1; stmt2; ...; expr }`.
    /// Returns the LC of the last expression, or `LC::zero()` if the block
    /// contains only statements (no trailing expression).
    fn compile_block(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError> {
        let mut last_lc = LinearCombination::zero();
        for child in pair.into_inner() {
            match child.as_rule() {
                Rule::stmt => {
                    let inner = child.into_inner().next().unwrap();
                    match inner.as_rule() {
                        Rule::let_decl => {
                            self.compile_let(inner)?;
                            last_lc = LinearCombination::zero();
                        }
                        Rule::expr
                        | Rule::cmp_expr
                        | Rule::add_expr
                        | Rule::mul_expr
                        | Rule::pow_expr
                        | Rule::prefix_expr
                        | Rule::postfix_expr
                        | Rule::atom => {
                            last_lc = self.compile_expr(inner)?;
                        }
                        _ => {
                            // Delegate to compile_stmt logic for rejections
                            self.compile_stmt_inner(inner)?;
                            last_lc = LinearCombination::zero();
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(last_lc)
    }

    /// Inner stmt compilation for rejection handling (used by compile_block).
    fn compile_stmt_inner(&mut self, inner: Pair<Rule>) -> Result<(), R1CSError> {
        match inner.as_rule() {
            Rule::mut_decl => Err(R1CSError::UnsupportedOperation(
                "mutable variables are not supported in circuits".into(),
            )),
            Rule::print_stmt => Err(R1CSError::UnsupportedOperation(
                "print is not supported in circuits".into(),
            )),
            Rule::assignment => Err(R1CSError::UnsupportedOperation(
                "assignment is not supported in circuits".into(),
            )),
            Rule::break_stmt => Err(R1CSError::UnsupportedOperation(
                "break is not supported in circuits".into(),
            )),
            Rule::continue_stmt => Err(R1CSError::UnsupportedOperation(
                "continue is not supported in circuits".into(),
            )),
            Rule::return_stmt => Err(R1CSError::UnsupportedOperation(
                "return is not supported in circuits".into(),
            )),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "{:?}",
                inner.as_rule()
            ))),
        }
    }

    /// Compile `for ident in start..end { body }` via static unrolling.
    ///
    /// The iterator variable is bound as a constant `FieldElement` on each
    /// iteration. Only literal integer ranges are accepted.
    fn compile_for(&mut self, pair: Pair<Rule>) -> Result<(), R1CSError> {
        let mut inner = pair.into_inner();
        let ident = inner.next().unwrap().as_str().to_string();
        let range_or_expr = inner.next().unwrap();

        // Must be a range_expr (integer..integer)
        if range_or_expr.as_rule() != Rule::range_expr {
            return Err(R1CSError::UnsupportedOperation(
                "for loops in circuits require a literal range (e.g., 0..5)".into(),
            ));
        }

        let mut range_inner = range_or_expr.into_inner();
        let start_str = range_inner.next().unwrap().as_str();
        let end_str = range_inner.next().unwrap().as_str();

        let start: u64 = start_str
            .parse()
            .map_err(|_| R1CSError::ParseError(format!("invalid range start: {start_str}")))?;
        let end: u64 = end_str
            .parse()
            .map_err(|_| R1CSError::ParseError(format!("invalid range end: {end_str}")))?;

        let body = inner.next().unwrap(); // block

        // Unroll: for each i in start..end, bind ident to constant i and compile body
        for i in start..end {
            let const_lc = LinearCombination::from_constant(FieldElement::from_u64(i));
            self.lc_bindings.insert(ident.clone(), const_lc);
            // Clone the body pairs for each iteration
            self.compile_block(body.clone())?;
        }

        // Clean up the iterator binding after the loop
        self.lc_bindings.remove(&ident);

        Ok(())
    }

    /// Compile `if cond { a } else { b }` as a MUX constraint.
    ///
    /// Generates:
    /// 1. Boolean enforcement: `cond * (1 - cond) = 0` (1 constraint)
    /// 2. MUX: `result = cond * (a - b) + b` (1 constraint for the multiplication)
    ///
    /// Both branches are always compiled (circuit has no runtime branching).
    /// If there is no else branch, the else value is 0.
    fn compile_if(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError> {
        let mut inner = pair.into_inner();

        // 1. Compile condition expression
        let cond_pair = inner.next().unwrap();
        let cond_lc = self.compile_expr(cond_pair)?;

        // 2. Compile "then" branch (block)
        let then_block = inner.next().unwrap();
        let then_lc = self.compile_block(then_block)?;

        // 3. Compile "else" branch (block or if_expr), or default to 0
        let else_lc = if let Some(else_part) = inner.next() {
            match else_part.as_rule() {
                Rule::block => self.compile_block(else_part)?,
                Rule::if_expr => self.compile_if(else_part)?,
                _ => self.compile_expr(else_part)?,
            }
        } else {
            LinearCombination::zero()
        };

        // 4. Boolean enforcement: cond * (1 - cond) = 0
        let one = LinearCombination::from_constant(FieldElement::ONE);
        let one_minus_cond = one - cond_lc.clone();
        self.cs.enforce(cond_lc.clone(), one_minus_cond, LinearCombination::zero());

        // 5. MUX: result = cond * (then - else) + else
        let diff = then_lc - else_lc.clone();
        let selected = self.multiply_lcs(&cond_lc, &diff);
        Ok(selected + else_lc)
    }

    // ========================================================================
    // Multiplication / Division helpers
    // ========================================================================

    /// Multiply two LCs. If either operand is a constant, uses scalar
    /// multiplication (0 constraints). Otherwise allocates a witness
    /// variable (1 constraint).
    fn multiply_lcs(&mut self, a: &LinearCombination, b: &LinearCombination) -> LinearCombination {
        // Constant * anything → scalar mul (0 constraints)
        if let Some(scalar) = a.constant_value() {
            return b.clone() * scalar;
        }
        if let Some(scalar) = b.constant_value() {
            return a.clone() * scalar;
        }
        // General case: allocate witness for product (1 constraint)
        let out = self.cs.mul_lc(a, b);
        LinearCombination::from_variable(out)
    }

    /// Divide two LCs. If denominator is constant, uses scalar inverse
    /// multiplication (0 constraints). Otherwise allocates inverse +
    /// product witnesses (2 constraints).
    fn divide_lcs(
        &mut self,
        num: &LinearCombination,
        den: &LinearCombination,
    ) -> Result<LinearCombination, R1CSError> {
        // Constant denominator → multiply by inverse (0 constraints)
        if let Some(scalar) = den.constant_value() {
            let inv = scalar.inv().ok_or_else(|| {
                R1CSError::UnsupportedOperation("division by zero".into())
            })?;
            return Ok(num.clone() * inv);
        }
        // General case: inv_lc (1 constraint) + mul_lc (1 constraint) = 2 constraints
        let den_inv = self.cs.inv_lc(den);
        let den_inv_lc = LinearCombination::from_variable(den_inv);
        let out = self.cs.mul_lc(num, &den_inv_lc);
        Ok(LinearCombination::from_variable(out))
    }

    /// Exponentiation by squaring. O(log n) constraints.
    fn pow_by_squaring(
        &mut self,
        base: &LinearCombination,
        exp: u64,
    ) -> Result<LinearCombination, R1CSError> {
        if exp == 0 {
            return Ok(LinearCombination::from_constant(FieldElement::ONE));
        }
        if exp == 1 {
            return Ok(base.clone());
        }

        // Square-and-multiply
        let mut result = LinearCombination::from_constant(FieldElement::ONE);
        let mut current = base.clone();
        let mut e = exp;

        let mut first = true;
        while e > 0 {
            if e & 1 == 1 {
                if first {
                    result = current.clone();
                    first = false;
                } else {
                    result = self.multiply_lcs(&result, &current);
                }
            }
            e >>= 1;
            if e > 0 {
                current = self.multiply_lcs(&current, &current);
            }
        }
        Ok(result)
    }
}

/// Try to extract a small u64 from a FieldElement.
/// Only works for values that fit in u64 (i.e., < 2^64).
fn field_to_u64(fe: &FieldElement) -> Option<u64> {
    let limbs = fe.to_canonical(); // [u64; 4] little-endian
    // Check that upper limbs are zero
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(limbs[0])
}
