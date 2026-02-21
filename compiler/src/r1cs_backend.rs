use constraints::poseidon::{poseidon_hash_circuit, PoseidonParams};
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use memory::FieldElement;
use std::collections::HashMap;

use achronyme_parser::{AchronymeParser, Rule};
use pest::iterators::Pair;
use pest::Parser;

use crate::r1cs_error::R1CSError;
use crate::witness_gen::{fill_poseidon_witness, WitnessOp};

/// Compiles an Achronyme circuit block into an R1CS constraint system.
///
/// The R1CSCompiler walks the pest AST and emits R1CS constraints instead of
/// bytecode. Each expression evaluates to a `LinearCombination`, and only
/// multiplications / materializations generate actual constraints.
pub struct R1CSCompiler {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem,
    /// Declared variables: maps `public`/`witness` names → allocated R1CS wire.
    /// Only contains explicitly declared circuit inputs (not `let` bindings).
    pub bindings: HashMap<String, Variable>,
    /// Expression cache: maps `let`-bound names → their LinearCombination.
    /// These are lazy — no wire is allocated until the LC is used in a
    /// multiplication or other materializing operation.
    pub lc_bindings: HashMap<String, LinearCombination>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
    /// Cached Poseidon parameters. Initialized on first `poseidon()` call.
    pub(crate) poseidon_params: Option<PoseidonParams>,
    /// Witness generation trace: records each intermediate variable allocation.
    pub witness_ops: Vec<WitnessOp>,
    /// SSA variables proven to be boolean by bool_prop analysis.
    /// Boolean enforcement constraints are skipped for these.
    proven_boolean: std::collections::HashSet<ir::types::SsaVar>,
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
            witness_ops: Vec::new(),
            proven_boolean: std::collections::HashSet::new(),
        }
    }

    /// Set the proven-boolean set from bool_prop analysis.
    /// Variables in this set skip redundant boolean enforcement constraints.
    pub fn set_proven_boolean(&mut self, set: std::collections::HashSet<ir::types::SsaVar>) {
        self.proven_boolean = set;
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
            .ok_or_else(|| R1CSError::UndeclaredVariable(name.to_string(), None))
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
            Rule::or_expr | Rule::and_expr
            | Rule::cmp_expr | Rule::add_expr | Rule::mul_expr | Rule::pow_expr
            | Rule::prefix_expr | Rule::postfix_expr | Rule::atom => {
                self.compile_expr(inner)?;
                Ok(())
            }
            Rule::mut_decl => Err(R1CSError::UnsupportedOperation(
                "mutable variables are not supported in circuits".into(),
                    None,
            )),
            Rule::print_stmt => Err(R1CSError::UnsupportedOperation(
                "print is not supported in circuits".into(),
                    None,
            )),
            Rule::assignment => Err(R1CSError::UnsupportedOperation(
                "assignment is not supported in circuits".into(),
                    None,
            )),
            Rule::break_stmt => Err(R1CSError::UnsupportedOperation(
                "break is not supported in circuits".into(),
                    None,
            )),
            Rule::continue_stmt => Err(R1CSError::UnsupportedOperation(
                "continue is not supported in circuits".into(),
                    None,
            )),
            Rule::return_stmt => Err(R1CSError::UnsupportedOperation(
                "return is not supported in circuits".into(),
                    None,
            )),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "{:?}",
                inner.as_rule()
            ), None)),
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
            Rule::or_expr => self.compile_or_expr(pair),
            Rule::and_expr => self.compile_and_expr(pair),
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
            ), None)),
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
            Rule::while_expr => Err(R1CSError::UnboundedLoop(None)),
            Rule::forever_expr => Err(R1CSError::UnboundedLoop(None)),
            Rule::fn_expr => Err(R1CSError::UnsupportedOperation(
                "closures are not supported in circuits".into(),
                    None,
            )),
            Rule::string => Err(R1CSError::TypeNotConstrainable("string".into(), None)),
            Rule::true_lit => Ok(LinearCombination::from_constant(FieldElement::ONE)),
            Rule::false_lit => Ok(LinearCombination::from_constant(FieldElement::ZERO)),
            Rule::nil_lit => Err(R1CSError::TypeNotConstrainable("nil".into(), None)),
            Rule::list_literal => Err(R1CSError::TypeNotConstrainable("list".into(), None)),
            Rule::map_literal => Err(R1CSError::TypeNotConstrainable("map".into(), None)),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "unsupported atom: {:?}",
                inner.as_rule()
            ), None)),
        }
    }

    fn compile_number(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError> {
        let s = pair.as_str();
        // Reject decimals — field elements are integers only
        if s.contains('.') {
            return Err(R1CSError::TypeNotConstrainable(
                "decimal numbers are not supported in circuits".into(),
                None,
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
                    ), None))
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
                    None,
                    ))
                }
                _ => {
                    return Err(R1CSError::UnsupportedOperation(format!(
                        "unknown multiplicative operator: {}",
                        op_pair.as_str()
                    ), None))
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
                    None,
                )
            })?;
            // Convert FieldElement to u64 for exponentiation
            let exp_u64 = field_to_u64(&exp_val).ok_or_else(|| {
                R1CSError::UnsupportedOperation(
                    "exponent too large for circuit compilation".into(),
                    None,
                )
            })?;
            if exp_u64 == 0 {
                return Ok(LinearCombination::from_constant(FieldElement::ONE));
            }
            // If there are more pow ops (right-associative chaining), reject for simplicity
            if pairs.next().is_some() {
                return Err(R1CSError::UnsupportedOperation(
                    "chained exponentiation is not supported in circuits".into(),
                    None,
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
        let mut ops: Vec<&str> = Vec::new();
        let mut last = None;
        for child in inner.by_ref() {
            match child.as_rule() {
                Rule::unary_op => {
                    ops.push(if child.as_str() == "-" { "-" } else { "!" });
                }
                _ => {
                    last = Some(child);
                    break;
                }
            }
        }
        let mut result = self.compile_expr(last.unwrap())?;
        for op in ops.into_iter().rev() {
            match op {
                "-" => {
                    result = result * FieldElement::ONE.neg();
                }
                "!" => {
                    // Boolean enforcement: result * (1 - result) = 0
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    self.cs.enforce(
                        result.clone(),
                        one.clone() - result.clone(),
                        LinearCombination::zero(),
                    );
                    result = one - result;
                }
                _ => unreachable!(),
            }
        }
        Ok(result)
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
                        ), None));
                    }
                    return match name {
                        "assert_eq" => self.compile_assert_eq(call.clone()),
                        "poseidon" => self.compile_poseidon(call.clone()),
                        "mux" => self.compile_mux(call.clone()),
                        _ => Err(R1CSError::UnsupportedOperation(format!(
                            "function call `{name}` is not supported in circuits"
                        ), None)),
                    };
                }
                return Err(R1CSError::UnsupportedOperation(
                    "function calls are not supported in circuits".into(),
                    None,
                ));
            }
            return Err(R1CSError::UnsupportedOperation(format!(
                "unsupported postfix operation: {:?}",
                call.as_rule()
            ), None));
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
                    None,
            ));
        }
        Ok(result)
    }

    fn compile_and_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let one = LinearCombination::from_constant(FieldElement::ONE);
        let mut pairs = pair.into_inner();
        let mut result = self.compile_expr(pairs.next().unwrap())?;
        while let Some(_op) = pairs.next() {
            let right = self.compile_expr(pairs.next().unwrap())?;
            // Boolean enforcement: result * (1 - result) = 0
            self.cs.enforce(
                result.clone(),
                one.clone() - result.clone(),
                LinearCombination::zero(),
            );
            // Boolean enforcement: right * (1 - right) = 0
            self.cs.enforce(
                right.clone(),
                one.clone() - right.clone(),
                LinearCombination::zero(),
            );
            result = self.multiply_lcs(&result, &right);
        }
        Ok(result)
    }

    fn compile_or_expr(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let one = LinearCombination::from_constant(FieldElement::ONE);
        let mut pairs = pair.into_inner();
        let mut result = self.compile_expr(pairs.next().unwrap())?;
        while let Some(_op) = pairs.next() {
            let right = self.compile_expr(pairs.next().unwrap())?;
            // Boolean enforcement: result * (1 - result) = 0
            self.cs.enforce(
                result.clone(),
                one.clone() - result.clone(),
                LinearCombination::zero(),
            );
            // Boolean enforcement: right * (1 - right) = 0
            self.cs.enforce(
                right.clone(),
                one.clone() - right.clone(),
                LinearCombination::zero(),
            );
            // a || b = a + b - a*b
            let product = self.multiply_lcs(&result, &right);
            result = result + right - product;
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
                span: None,
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
                span: None,
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

        let internal_start = self.cs.num_variables();
        let hash_var = poseidon_hash_circuit(&mut self.cs, params, left_var, right_var);
        let internal_count = self.cs.num_variables() - internal_start;

        self.witness_ops.push(WitnessOp::PoseidonHash {
            left: left_var,
            right: right_var,
            output: hash_var,
            internal_start,
            internal_count,
        });

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
                span: None,
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
        self.witness_ops.push(WitnessOp::AssignLC {
            target: var,
            lc: lc.clone(),
        });
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
        // Track which keys existed before the block. New bindings introduced
        // inside the block are removed on exit (block scoping). Rebindings of
        // existing variables persist — this enables accumulation across for-loop
        // iterations (e.g., `let acc = acc + x`).
        let outer_keys: std::collections::HashSet<String> =
            self.lc_bindings.keys().cloned().collect();
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
                        | Rule::or_expr
                        | Rule::and_expr
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
        // Remove new bindings, keep rebindings of existing vars
        self.lc_bindings.retain(|k, _| outer_keys.contains(k));
        Ok(last_lc)
    }

    /// Inner stmt compilation for rejection handling (used by compile_block).
    fn compile_stmt_inner(&mut self, inner: Pair<Rule>) -> Result<(), R1CSError> {
        match inner.as_rule() {
            Rule::mut_decl => Err(R1CSError::UnsupportedOperation(
                "mutable variables are not supported in circuits".into(),
                    None,
            )),
            Rule::print_stmt => Err(R1CSError::UnsupportedOperation(
                "print is not supported in circuits".into(),
                    None,
            )),
            Rule::assignment => Err(R1CSError::UnsupportedOperation(
                "assignment is not supported in circuits".into(),
                    None,
            )),
            Rule::break_stmt => Err(R1CSError::UnsupportedOperation(
                "break is not supported in circuits".into(),
                    None,
            )),
            Rule::continue_stmt => Err(R1CSError::UnsupportedOperation(
                "continue is not supported in circuits".into(),
                    None,
            )),
            Rule::return_stmt => Err(R1CSError::UnsupportedOperation(
                "return is not supported in circuits".into(),
                    None,
            )),
            _ => Err(R1CSError::UnsupportedOperation(format!(
                "{:?}",
                inner.as_rule()
            ), None)),
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
                    None,
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

        let iterations = end.saturating_sub(start);
        if iterations > ir::lower::MAX_UNROLL_ITERATIONS {
            return Err(R1CSError::UnsupportedOperation(
                format!(
                    "for loop range {start}..{end} has {iterations} iterations, \
                     exceeding the maximum of {}",
                    ir::lower::MAX_UNROLL_ITERATIONS,
                ),
                None,
            ));
        }

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
    /// **Important**: Both branches are always compiled and all their constraints
    /// are emitted unconditionally. The MUX only selects which *value* to return.
    /// This is an inherent limitation of arithmetic circuits.
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
    ///
    /// Note: WitnessOp::Multiply clones both LCs because witness generation
    /// needs to evaluate arbitrary linear combinations (not just single
    /// variables). This is unavoidable when LCs are multi-term (e.g. `3*x + 5*y`).
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
        self.witness_ops.push(WitnessOp::Multiply {
            target: out,
            a: a.clone(),
            b: b.clone(),
        });
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
                R1CSError::UnsupportedOperation("division by zero".into(), None)
            })?;
            return Ok(num.clone() * inv);
        }
        // General case: inv_lc (1 constraint) + mul_lc (1 constraint) = 2 constraints
        let den_inv = self.cs.inv_lc(den);
        self.witness_ops.push(WitnessOp::Inverse {
            target: den_inv,
            operand: den.clone(),
        });
        let den_inv_lc = LinearCombination::from_variable(den_inv);
        let out = self.cs.mul_lc(num, &den_inv_lc);
        self.witness_ops.push(WitnessOp::Multiply {
            target: out,
            a: num.clone(),
            b: den_inv_lc,
        });
        Ok(LinearCombination::from_variable(out))
    }

    /// Enforce that `val` fits in `num_bits` bits: `val ∈ [0, 2^num_bits)`.
    /// Decomposes into `num_bits` boolean-enforced bits and checks sum == val.
    fn enforce_n_range(&mut self, val: &LinearCombination, num_bits: u32) {
        let mut sum = LinearCombination::zero();
        for i in 0..num_bits {
            let bit_var = self.cs.alloc_witness();
            self.cs.enforce(
                LinearCombination::from_variable(bit_var),
                LinearCombination::from_constant(FieldElement::ONE)
                    - LinearCombination::from_variable(bit_var),
                LinearCombination::zero(),
            );
            let coeff = compute_power_of_two(i);
            sum = sum + LinearCombination::from_variable(bit_var) * coeff;
            self.witness_ops.push(WitnessOp::BitExtract {
                target: bit_var,
                source: val.clone(),
                bit_index: i,
            });
        }
        self.cs.enforce_equal(val.clone(), sum);
    }

    /// Enforce that `val` fits in 252 bits: `val ∈ [0, 2^252)`.
    fn enforce_252_range(&mut self, val: &LinearCombination) {
        self.enforce_n_range(val, 252);
    }

    /// Compile an IsLt check via `num_bits`-bit decomposition.
    /// Input: an LC representing `diff = b - a + offset`.
    /// Returns an LC that is 1 if a < b, 0 otherwise (bit `num_bits - 1`).
    fn compile_is_lt_via_bits(&mut self, diff: &LinearCombination, num_bits: u32) -> LinearCombination {
        let mut sum = LinearCombination::zero();
        let mut top_bit_lc = LinearCombination::zero();
        let top_index = num_bits - 1;

        for i in 0..num_bits {
            let bit_var = self.cs.alloc_witness();
            // b_i * (1 - b_i) = 0
            self.cs.enforce(
                LinearCombination::from_variable(bit_var),
                LinearCombination::from_constant(FieldElement::ONE)
                    - LinearCombination::from_variable(bit_var),
                LinearCombination::zero(),
            );
            let coeff = compute_power_of_two(i);
            sum = sum + LinearCombination::from_variable(bit_var) * coeff;
            self.witness_ops.push(WitnessOp::BitExtract {
                target: bit_var,
                source: diff.clone(),
                bit_index: i,
            });
            if i == top_index {
                top_bit_lc = LinearCombination::from_variable(bit_var);
            }
        }
        self.cs.enforce_equal(diff.clone(), sum);
        top_bit_lc
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

// ============================================================================
// IR → R1CS Lowering
// ============================================================================

use ir::types::{IrProgram, SsaVar, Instruction as IrInstruction, Visibility as IrVisibility};

impl R1CSCompiler {
    /// Compile an SSA IR program into R1CS constraints.
    ///
    /// This coexists with `compile_circuit()` — both methods build on the same
    /// `ConstraintSystem` and helper methods (`multiply_lcs`, `divide_lcs`, etc).
    pub fn compile_ir(&mut self, program: &IrProgram) -> Result<(), R1CSError> {
        // Lookup cache: SSA variable → its LinearCombination. Used for O(1)
        // lookups only — never iterated, so HashMap ordering is irrelevant.
        let mut lc_map: HashMap<SsaVar, LinearCombination> = HashMap::new();
        // Track proven bit-width bounds from RangeCheck for IsLt/IsLe optimization
        let mut range_bounds: HashMap<SsaVar, u32> = HashMap::new();

        // Helper closure to look up SSA variables with proper error messages
        let lookup = |map: &HashMap<SsaVar, LinearCombination>, var: &SsaVar| -> Result<LinearCombination, R1CSError> {
            map.get(var).cloned().ok_or_else(|| {
                R1CSError::UnsupportedOperation(
                    format!("undefined SSA variable {:?}", var),
                    None,
                )
            })
        };

        for inst in &program.instructions {
            match inst {
                IrInstruction::Const { result, value } => {
                    lc_map.insert(*result, LinearCombination::from_constant(*value));
                }
                IrInstruction::Input {
                    result,
                    name,
                    visibility,
                } => {
                    let var = match visibility {
                        IrVisibility::Public => {
                            let v = self.cs.alloc_input();
                            self.bindings.insert(name.clone(), v);
                            self.public_inputs.push(name.clone());
                            v
                        }
                        IrVisibility::Witness => {
                            let v = self.cs.alloc_witness();
                            self.bindings.insert(name.clone(), v);
                            self.witnesses.push(name.clone());
                            v
                        }
                    };
                    lc_map.insert(*result, LinearCombination::from_variable(var));
                }
                IrInstruction::Add { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    lc_map.insert(*result, a + b);
                }
                IrInstruction::Sub { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    lc_map.insert(*result, a - b);
                }
                IrInstruction::Neg { result, operand } => {
                    let lc = lookup(&lc_map, operand)?;
                    lc_map.insert(*result, lc * FieldElement::ONE.neg());
                }
                IrInstruction::Mul { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let out = self.multiply_lcs(&a, &b);
                    lc_map.insert(*result, out);
                }
                IrInstruction::Div { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let out = self.divide_lcs(&a, &b)?;
                    lc_map.insert(*result, out);
                }
                IrInstruction::Mux {
                    result,
                    cond,
                    if_true,
                    if_false,
                } => {
                    let cond_lc = lookup(&lc_map, cond)?;
                    let then_lc = lookup(&lc_map, if_true)?;
                    let else_lc = lookup(&lc_map, if_false)?;

                    // Skip boolean enforcement if cond is proven boolean
                    if !self.proven_boolean.contains(cond) {
                        let one = LinearCombination::from_constant(FieldElement::ONE);
                        let one_minus_cond = one - cond_lc.clone();
                        self.cs.enforce(
                            cond_lc.clone(),
                            one_minus_cond,
                            LinearCombination::zero(),
                        );
                    }

                    // MUX: result = cond * (then - else) + else
                    let diff = then_lc - else_lc.clone();
                    let selected = self.multiply_lcs(&cond_lc, &diff);
                    lc_map.insert(*result, selected + else_lc);
                }
                IrInstruction::AssertEq { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    self.cs.enforce_equal(a, b.clone());
                    lc_map.insert(*result, b);
                }
                IrInstruction::RangeCheck {
                    result,
                    operand,
                    bits,
                } => {
                    let lc = lookup(&lc_map, operand)?;
                    // Boolean decomposition: x = sum(b_i * 2^i), each b_i boolean
                    // Cost: bits boolean constraints + 1 sum equality = bits+1 total
                    let mut sum = LinearCombination::zero();
                    for i in 0..*bits {
                        let bit_var = self.cs.alloc_witness();
                        // b_i * (1 - b_i) = 0  (enforces b_i ∈ {0, 1})
                        self.cs.enforce(
                            LinearCombination::from_variable(bit_var),
                            LinearCombination::from_constant(FieldElement::ONE)
                                - LinearCombination::from_variable(bit_var),
                            LinearCombination::zero(),
                        );
                        let coeff = compute_power_of_two(i as u32);
                        sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                        self.witness_ops.push(WitnessOp::BitExtract {
                            target: bit_var,
                            source: lc.clone(),
                            bit_index: i,
                        });
                    }
                    self.cs.enforce_equal(lc.clone(), sum);
                    // Record proven bound for IsLt/IsLe optimization
                    range_bounds.insert(*operand, *bits);
                    lc_map.insert(*result, lc);
                }
                IrInstruction::Not { result, operand } => {
                    let op_lc = lookup(&lc_map, operand)?;
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    // Skip boolean enforcement if operand is proven boolean
                    if !self.proven_boolean.contains(operand) {
                        self.cs.enforce(
                            op_lc.clone(),
                            one.clone() - op_lc.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    // result = 1 - op
                    lc_map.insert(*result, one - op_lc);
                }
                IrInstruction::And { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    if !self.proven_boolean.contains(lhs) {
                        self.cs.enforce(
                            a.clone(),
                            one.clone() - a.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    if !self.proven_boolean.contains(rhs) {
                        self.cs.enforce(
                            b.clone(),
                            one - b.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    // result = a * b
                    let out = self.multiply_lcs(&a, &b);
                    lc_map.insert(*result, out);
                }
                IrInstruction::Or { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    if !self.proven_boolean.contains(lhs) {
                        self.cs.enforce(
                            a.clone(),
                            one.clone() - a.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    if !self.proven_boolean.contains(rhs) {
                        self.cs.enforce(
                            b.clone(),
                            one - b.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    // result = a + b - a*b
                    let product = self.multiply_lcs(&a, &b);
                    lc_map.insert(*result, a + b - product);
                }
                IrInstruction::IsEq { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let diff = a - b;
                    // IsZero gadget: alloc inv + eq_result
                    // enforce: diff * inv = 1 - eq_result
                    // enforce: diff * eq_result = 0
                    let inv_var = self.cs.alloc_witness();
                    let eq_var = self.cs.alloc_witness();
                    self.witness_ops.push(WitnessOp::IsZero {
                        diff: diff.clone(),
                        target_inv: inv_var,
                        target_result: eq_var,
                    });
                    let inv_lc = LinearCombination::from_variable(inv_var);
                    let eq_lc = LinearCombination::from_variable(eq_var);
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    self.cs.enforce(diff.clone(), inv_lc, one - eq_lc.clone());
                    self.cs.enforce(diff, eq_lc.clone(), LinearCombination::zero());
                    lc_map.insert(*result, eq_lc);
                }
                IrInstruction::IsNeq { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let diff = a - b;
                    // IsZero gadget then negate
                    let inv_var = self.cs.alloc_witness();
                    let eq_var = self.cs.alloc_witness();
                    self.witness_ops.push(WitnessOp::IsZero {
                        diff: diff.clone(),
                        target_inv: inv_var,
                        target_result: eq_var,
                    });
                    let inv_lc = LinearCombination::from_variable(inv_var);
                    let eq_lc = LinearCombination::from_variable(eq_var);
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    self.cs.enforce(diff.clone(), inv_lc, one.clone() - eq_lc.clone());
                    self.cs.enforce(diff, eq_lc.clone(), LinearCombination::zero());
                    // neq = 1 - eq
                    lc_map.insert(*result, one - eq_lc);
                }
                IrInstruction::IsLt { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let bound_a = range_bounds.get(lhs).copied();
                    let bound_b = range_bounds.get(rhs).copied();

                    let effective_bits = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => ba.max(bb),
                        _ => {
                            if bound_a.is_none() { self.enforce_252_range(&a); }
                            if bound_b.is_none() { self.enforce_252_range(&b); }
                            252
                        }
                    };

                    let offset = compute_power_of_two(effective_bits).sub(&FieldElement::ONE);
                    let diff = b - a + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                    lc_map.insert(*result, lt_lc);
                }
                IrInstruction::IsLe { result, lhs, rhs } => {
                    // a <= b  ≡  !(b < a)  ≡  1 - IsLt(b, a)
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let bound_a = range_bounds.get(lhs).copied();
                    let bound_b = range_bounds.get(rhs).copied();

                    let effective_bits = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => ba.max(bb),
                        _ => {
                            if bound_a.is_none() { self.enforce_252_range(&a); }
                            if bound_b.is_none() { self.enforce_252_range(&b); }
                            252
                        }
                    };

                    let offset = compute_power_of_two(effective_bits).sub(&FieldElement::ONE);
                    let diff = a - b + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    lc_map.insert(*result, one - lt_lc);
                }
                IrInstruction::Assert { result, operand } => {
                    let op_lc = lookup(&lc_map, operand)?;
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    // Skip boolean enforcement if operand is proven boolean
                    if !self.proven_boolean.contains(operand) {
                        self.cs.enforce(
                            op_lc.clone(),
                            one.clone() - op_lc.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    // Enforce op == 1
                    self.cs.enforce_equal(op_lc.clone(), one);
                    lc_map.insert(*result, op_lc);
                }
                IrInstruction::PoseidonHash {
                    result,
                    left,
                    right,
                } => {
                    let left_lc = lookup(&lc_map, left)?;
                    let right_lc = lookup(&lc_map, right)?;

                    let left_var = self.materialize_lc(&left_lc);
                    let right_var = self.materialize_lc(&right_lc);

                    if self.poseidon_params.is_none() {
                        self.poseidon_params =
                            Some(constraints::poseidon::PoseidonParams::bn254_t3());
                    }
                    let params = self.poseidon_params.as_ref().unwrap();

                    let internal_start = self.cs.num_variables();
                    let hash_var = constraints::poseidon::poseidon_hash_circuit(
                        &mut self.cs,
                        params,
                        left_var,
                        right_var,
                    );
                    let internal_count = self.cs.num_variables() - internal_start;

                    self.witness_ops.push(WitnessOp::PoseidonHash {
                        left: left_var,
                        right: right_var,
                        output: hash_var,
                        internal_start,
                        internal_count,
                    });

                    lc_map.insert(*result, LinearCombination::from_variable(hash_var));
                }
            }
        }

        Ok(())
    }

    /// Compile an SSA IR program and generate a witness in a single pass.
    ///
    /// Three-pass design (intentional):
    /// 1. **Evaluate**: runs IR with concrete inputs for early validation — catches
    ///    assertion failures, division by zero, and missing inputs *before* emitting
    ///    any constraints. This avoids wasting work on invalid witnesses.
    /// 2. **Compile**: lowers IR → R1CS constraints (same as `compile_ir`), populating
    ///    `witness_ops` as a side-effect.
    /// 3. **Witness**: builds the witness vector by replaying `witness_ops` with
    ///    concrete input values. This is separate from compilation because constraint
    ///    generation must complete before the full witness layout is known.
    pub fn compile_ir_with_witness(
        &mut self,
        program: &IrProgram,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<Vec<FieldElement>, R1CSError> {
        // 1. Evaluate IR — early validation
        let _ssa_values = ir::eval::evaluate(program, inputs)
            .map_err(|e| R1CSError::EvalError(format!("{e}")))?;

        // 2. Compile constraints (populates witness_ops)
        self.compile_ir(program)?;

        // 3. Build witness vector
        let mut witness = vec![FieldElement::ZERO; self.cs.num_variables()];
        witness[0] = FieldElement::ONE;

        // 3a. Fill inputs
        for name in &self.public_inputs {
            witness[self.bindings[name].index()] = inputs[name];
        }
        for name in &self.witnesses {
            witness[self.bindings[name].index()] = inputs[name];
        }

        // 3b. Replay witness ops
        for op in &self.witness_ops {
            match op {
                WitnessOp::AssignLC { target, lc } => {
                    witness[target.index()] = lc.evaluate(&witness);
                }
                WitnessOp::Multiply { target, a, b } => {
                    witness[target.index()] = a.evaluate(&witness).mul(&b.evaluate(&witness));
                }
                WitnessOp::Inverse { target, operand } => {
                    let val = operand.evaluate(&witness);
                    witness[target.index()] = val.inv().ok_or_else(|| {
                        R1CSError::EvalError(format!(
                            "division by zero at wire {}",
                            target.index()
                        ))
                    })?;
                }
                WitnessOp::BitExtract {
                    target,
                    source,
                    bit_index,
                } => {
                    let val = source.evaluate(&witness);
                    let limbs = val.to_canonical();
                    let li = (*bit_index / 64) as usize;
                    let bp = *bit_index % 64;
                    let bit = if li < 4 { (limbs[li] >> bp) & 1 } else { 0 };
                    witness[target.index()] = FieldElement::from_u64(bit);
                }
                WitnessOp::IsZero {
                    diff,
                    target_inv,
                    target_result,
                } => {
                    let d = diff.evaluate(&witness);
                    if d.is_zero() {
                        witness[target_inv.index()] = FieldElement::ZERO;
                        witness[target_result.index()] = FieldElement::ONE;
                    } else {
                        witness[target_inv.index()] = d.inv().ok_or_else(|| {
                            R1CSError::EvalError("IsZero inverse failed".into())
                        })?;
                        witness[target_result.index()] = FieldElement::ZERO;
                    }
                }
                WitnessOp::PoseidonHash {
                    left,
                    right,
                    internal_start,
                    internal_count,
                    ..
                } => {
                    let params = self.poseidon_params.as_ref().ok_or_else(|| {
                        R1CSError::EvalError("poseidon params not initialized".into())
                    })?;
                    fill_poseidon_witness(
                        &mut witness,
                        params,
                        *left,
                        *right,
                        *internal_start,
                        *internal_count,
                    )
                    .map_err(|e| R1CSError::EvalError(format!("{e}")))?;
                }
            }
        }

        Ok(witness)
    }
}

/// Pre-computed table of 2^0 .. 2^252 as FieldElements.
/// Initialized once on first access, O(253) total instead of O(n) per call.
static POWERS_OF_TWO: std::sync::LazyLock<[FieldElement; 253]> = std::sync::LazyLock::new(|| {
    let mut table = [FieldElement::ZERO; 253];
    table[0] = FieldElement::ONE;
    for i in 1..253 {
        table[i] = table[i - 1].add(&table[i - 1]);
    }
    table
});

/// Look up 2^n from the pre-computed table.
fn compute_power_of_two(n: u32) -> FieldElement {
    POWERS_OF_TWO[n as usize]
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
