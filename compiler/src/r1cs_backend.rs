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
                    match name {
                        "assert_eq" => {
                            if inner.next().is_some() {
                                return Err(R1CSError::UnsupportedOperation(
                                    "chained postfix after assert_eq is not supported".into(),
                                ));
                            }
                            return self.compile_assert_eq(call.clone());
                        }
                        _ => {
                            return Err(R1CSError::UnsupportedOperation(format!(
                                "function call `{name}` is not supported in circuits"
                            )));
                        }
                    }
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
    // Postfix: assert_eq builtin
    // ========================================================================

    /// Handle assert_eq(a, b): enforces a == b (1 constraint).
    fn compile_assert_eq(
        &mut self,
        call_op: Pair<Rule>,
    ) -> Result<LinearCombination, R1CSError> {
        let mut args = call_op.into_inner();
        let a_pair = args
            .next()
            .ok_or_else(|| R1CSError::ParseError("assert_eq requires 2 arguments".into()))?;
        let b_pair = args
            .next()
            .ok_or_else(|| R1CSError::ParseError("assert_eq requires 2 arguments".into()))?;

        let a = self.compile_expr(a_pair)?;
        let b = self.compile_expr(b_pair)?;

        self.cs.enforce_equal(a, b.clone());

        // Return the second operand as the result (for chaining)
        Ok(b)
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_compiler_is_empty() {
        let rc = R1CSCompiler::new();
        assert_eq!(rc.cs.num_variables(), 1); // only ONE wire
        assert_eq!(rc.cs.num_pub_inputs(), 0);
        assert_eq!(rc.cs.num_constraints(), 0);
        assert!(rc.bindings.is_empty());
        assert!(rc.public_inputs.is_empty());
        assert!(rc.witnesses.is_empty());
    }

    #[test]
    fn test_declare_public() {
        let mut rc = R1CSCompiler::new();
        let var = rc.declare_public("root");

        assert_eq!(var.index(), 1); // first public after ONE
        assert_eq!(rc.cs.num_pub_inputs(), 1);
        assert_eq!(rc.public_inputs, vec!["root"]);
        assert_eq!(rc.lookup("root").unwrap(), var);
    }

    #[test]
    fn test_declare_witness() {
        let mut rc = R1CSCompiler::new();
        // Declare a public first to test ordering
        let pub_var = rc.declare_public("out");
        let wit_var = rc.declare_witness("secret");

        assert_eq!(pub_var.index(), 1);
        assert_eq!(wit_var.index(), 2);
        assert_eq!(rc.witnesses, vec!["secret"]);
        assert_eq!(rc.lookup("secret").unwrap(), wit_var);
    }

    #[test]
    fn test_declare_multiple() {
        let mut rc = R1CSCompiler::new();
        let a = rc.declare_public("a");
        let b = rc.declare_public("b");
        let c = rc.declare_witness("c");
        let d = rc.declare_witness("d");

        assert_eq!(a.index(), 1);
        assert_eq!(b.index(), 2);
        assert_eq!(c.index(), 3);
        assert_eq!(d.index(), 4);
        assert_eq!(rc.cs.num_variables(), 5);
        assert_eq!(rc.cs.num_pub_inputs(), 2);
        assert_eq!(rc.public_inputs, vec!["a", "b"]);
        assert_eq!(rc.witnesses, vec!["c", "d"]);
    }

    #[test]
    fn test_lookup_undeclared() {
        let rc = R1CSCompiler::new();
        let err = rc.lookup("nonexistent").unwrap_err();
        match err {
            R1CSError::UndeclaredVariable(name) => assert_eq!(name, "nonexistent"),
            _ => panic!("expected UndeclaredVariable"),
        }
    }

    #[test]
    fn test_lookup_returns_correct_variable() {
        let mut rc = R1CSCompiler::new();
        let x = rc.declare_witness("x");
        let y = rc.declare_witness("y");

        assert_eq!(rc.lookup("x").unwrap(), x);
        assert_eq!(rc.lookup("y").unwrap(), y);
        assert!(rc.lookup("z").is_err());
    }

    #[test]
    fn test_rebinding_overwrites() {
        let mut rc = R1CSCompiler::new();
        let v1 = rc.declare_witness("x");
        let v2 = rc.declare_witness("x"); // rebind same name

        // The binding should point to the latest variable
        assert_eq!(rc.lookup("x").unwrap(), v2);
        assert_ne!(v1, v2);
    }

    // ====================================================================
    // Phase 1: Expression compilation tests
    // ====================================================================

    #[test]
    fn test_r1cs_compile_number() {
        let mut rc = R1CSCompiler::new();
        rc.compile_circuit("42").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_compile_negative_number() {
        let mut rc = R1CSCompiler::new();
        rc.compile_circuit("-7").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_compile_identifier() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("x");
        rc.compile_circuit("x").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_reject_string() {
        let mut rc = R1CSCompiler::new();
        let err = rc.compile_circuit("\"hello\"").unwrap_err();
        assert!(matches!(err, R1CSError::TypeNotConstrainable(_)));
    }

    #[test]
    fn test_r1cs_reject_bool() {
        let mut rc = R1CSCompiler::new();
        let err = rc.compile_circuit("true").unwrap_err();
        assert!(matches!(err, R1CSError::TypeNotConstrainable(_)));
    }

    #[test]
    fn test_r1cs_reject_nil() {
        let mut rc = R1CSCompiler::new();
        let err = rc.compile_circuit("nil").unwrap_err();
        assert!(matches!(err, R1CSError::TypeNotConstrainable(_)));
    }

    #[test]
    fn test_r1cs_reject_decimal() {
        let mut rc = R1CSCompiler::new();
        let err = rc.compile_circuit("3.14").unwrap_err();
        assert!(matches!(err, R1CSError::TypeNotConstrainable(_)));
    }

    #[test]
    fn test_r1cs_addition_free() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        rc.compile_circuit("a + b").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0, "addition should generate 0 constraints");
    }

    #[test]
    fn test_r1cs_subtraction_free() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        rc.compile_circuit("a - b").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_mul_by_constant_free() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.compile_circuit("a * 3").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0, "multiplication by constant should be free");
    }

    #[test]
    fn test_r1cs_mul_variables_one_constraint() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        rc.compile_circuit("a * b").unwrap();
        assert_eq!(rc.cs.num_constraints(), 1, "variable * variable should be 1 constraint");
    }

    #[test]
    fn test_r1cs_div_constant_free() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.compile_circuit("a / 7").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0, "division by constant should be free");
    }

    #[test]
    fn test_r1cs_div_variables_two_constraints() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        rc.compile_circuit("a / b").unwrap();
        assert_eq!(rc.cs.num_constraints(), 2, "a / b should generate 2 constraints");
    }

    #[test]
    fn test_r1cs_pow_literal() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("x");
        rc.compile_circuit("x ^ 3").unwrap();
        // x^3 = x * x * x: first x*x (1 constraint), then result * x (1 constraint) = 2
        assert_eq!(rc.cs.num_constraints(), 2, "x^3 should generate 2 constraints");
    }

    #[test]
    fn test_r1cs_pow_variable_rejected() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("x");
        rc.declare_witness("n");
        let err = rc.compile_circuit("x ^ n").unwrap_err();
        assert!(matches!(err, R1CSError::UnsupportedOperation(_)));
    }

    #[test]
    fn test_r1cs_pow_zero() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("x");
        rc.compile_circuit("x ^ 0").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_pow_one() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("x");
        rc.compile_circuit("x ^ 1").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_let_binding() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        // let sum = a + b (0 constraints, just stores LC)
        // sum * 2 (0 constraints, scalar mul)
        rc.compile_circuit("let sum = a + b; sum * 2").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_negation_free() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("x");
        rc.compile_circuit("-x").unwrap();
        assert_eq!(rc.cs.num_constraints(), 0);
    }

    #[test]
    fn test_r1cs_complex_expression_constraint_count() {
        // a * b + c * d should be 2 constraints (one for each mul)
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        rc.declare_witness("c");
        rc.declare_witness("d");
        rc.compile_circuit("a * b + c * d").unwrap();
        assert_eq!(rc.cs.num_constraints(), 2);
    }

    #[test]
    fn test_r1cs_assert_eq_one_constraint() {
        let mut rc = R1CSCompiler::new();
        rc.declare_witness("a");
        rc.declare_witness("b");
        rc.compile_circuit("assert_eq(a, b)").unwrap();
        assert_eq!(rc.cs.num_constraints(), 1);
    }

    #[test]
    fn test_r1cs_reject_mut() {
        let mut rc = R1CSCompiler::new();
        let err = rc.compile_circuit("mut x = 5").unwrap_err();
        assert!(matches!(err, R1CSError::UnsupportedOperation(_)));
    }

    #[test]
    fn test_r1cs_reject_print() {
        let mut rc = R1CSCompiler::new();
        let err = rc.compile_circuit("print(42)").unwrap_err();
        assert!(matches!(err, R1CSError::UnsupportedOperation(_)));
    }

    // ====================================================================
    // Integration tests: full circuit with verification
    // ====================================================================

    #[test]
    fn test_r1cs_integration_simple_multiply() {
        // Circuit: prove a * b == c
        let mut rc = R1CSCompiler::new();
        rc.declare_public("c");
        rc.declare_witness("a");
        rc.declare_witness("b");

        rc.compile_circuit("let product = a * b; assert_eq(product, c)").unwrap();

        // a * b generates 1 constraint (product wire), assert_eq generates 1
        assert_eq!(rc.cs.num_constraints(), 2);

        // Build witness: ONE=1, c=42, a=6, b=7, product=42
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(42), // c (public)
            FieldElement::from_u64(6),  // a
            FieldElement::from_u64(7),  // b
            FieldElement::from_u64(42), // product (intermediate)
        ];
        assert!(rc.cs.verify(&witness).is_ok());

        // Wrong witness should fail
        let bad_witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(43), // c (wrong)
            FieldElement::from_u64(6),
            FieldElement::from_u64(7),
            FieldElement::from_u64(42),
        ];
        assert!(rc.cs.verify(&bad_witness).is_err());
    }

    #[test]
    fn test_r1cs_integration_quadratic() {
        // Circuit: prove x^2 + x + 5 == out
        let mut rc = R1CSCompiler::new();
        rc.declare_public("out");
        rc.declare_witness("x");

        rc.compile_circuit("let result = x ^ 2 + x + 5; assert_eq(result, out)")
            .unwrap();

        // x^2 = 1 constraint, assert_eq = 1 constraint
        assert_eq!(rc.cs.num_constraints(), 2);

        // x = 5: x^2 + x + 5 = 25 + 5 + 5 = 35
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(35), // out
            FieldElement::from_u64(5),  // x
            FieldElement::from_u64(25), // x^2 (intermediate)
        ];
        assert!(rc.cs.verify(&witness).is_ok());

        // x = 3: x^2 + x + 5 = 9 + 3 + 5 = 17, but out = 35 → fail
        let bad_witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(35), // out (expects 35 but circuit computes 17)
            FieldElement::from_u64(3),  // x
            FieldElement::from_u64(9),  // x^2
        ];
        assert!(rc.cs.verify(&bad_witness).is_err());
    }

    #[test]
    fn test_r1cs_integration_scalar_operations() {
        // Circuit: prove 3*a + 2*b == out (0 mul constraints, 1 assert_eq)
        let mut rc = R1CSCompiler::new();
        rc.declare_public("out");
        rc.declare_witness("a");
        rc.declare_witness("b");

        rc.compile_circuit("assert_eq(3 * a + 2 * b, out)").unwrap();

        // Only the assert_eq generates a constraint
        assert_eq!(rc.cs.num_constraints(), 1);

        // a=4, b=5: 3*4 + 2*5 = 12 + 10 = 22
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(22), // out
            FieldElement::from_u64(4),  // a
            FieldElement::from_u64(5),  // b
        ];
        assert!(rc.cs.verify(&witness).is_ok());
    }

    #[test]
    fn test_r1cs_integration_let_chain() {
        // Circuit: let x2 = x * x; let x3 = x2 * x; assert_eq(x3, out)
        let mut rc = R1CSCompiler::new();
        rc.declare_public("out");
        rc.declare_witness("x");

        rc.compile_circuit(
            "let x2 = x * x; let x3 = x2 * x; assert_eq(x3, out)"
        ).unwrap();

        // x*x = 1 constraint, x2*x = 1 constraint, assert_eq = 1 constraint
        assert_eq!(rc.cs.num_constraints(), 3);

        // x = 3: x^3 = 27
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(27), // out
            FieldElement::from_u64(3),  // x
            FieldElement::from_u64(9),  // x2
            FieldElement::from_u64(27), // x3
        ];
        assert!(rc.cs.verify(&witness).is_ok());
    }
}
