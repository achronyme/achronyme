/// R1CS Constraint System for ZK Proofs
///
/// An R1CS (Rank-1 Constraint System) represents computation as a set of
/// constraints of the form: A · B = C, where A, B, C are linear combinations
/// of variables (wires).
///
/// Wire layout (snarkjs-compatible):
///   Index 0     = ONE (constant wire, always 1)
///   1..=n_pub   = public inputs (instance)
///   n_pub+1..   = private inputs + intermediate (witness)

use memory::FieldElement;

// ============================================================================
// Variable (Wire reference)
// ============================================================================

/// A reference to a wire in the constraint system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Variable(pub(crate) usize);

impl Variable {
    /// The constant-one wire (index 0 by R1CS convention).
    pub const ONE: Variable = Variable(0);

    /// Raw index for serialization.
    #[inline]
    pub fn index(&self) -> usize {
        self.0
    }
}

// ============================================================================
// LinearCombination
// ============================================================================

/// A linear combination: Σ(coefficient_i * variable_i)
///
/// Stored as sparse (variable, coefficient) pairs.
#[derive(Debug, Clone, Default)]
pub struct LinearCombination {
    pub terms: Vec<(Variable, FieldElement)>,
}

impl LinearCombination {
    pub fn zero() -> Self {
        Self { terms: vec![] }
    }

    /// Create LC from a single variable with coefficient 1.
    pub fn from_variable(var: Variable) -> Self {
        Self {
            terms: vec![(var, FieldElement::ONE)],
        }
    }

    /// Create LC from a constant field element: coeff * ONE.
    pub fn from_constant(coeff: FieldElement) -> Self {
        if coeff.is_zero() {
            return Self::zero();
        }
        Self {
            terms: vec![(Variable::ONE, coeff)],
        }
    }

    /// Add a (coefficient * variable) term.
    pub fn add_term(&mut self, var: Variable, coeff: FieldElement) {
        self.terms.push((var, coeff));
    }

    /// Returns true if this LC only references `Variable::ONE` (i.e., it's a pure constant).
    pub fn is_constant(&self) -> bool {
        self.terms.iter().all(|(var, _)| *var == Variable::ONE)
    }

    /// If this LC is a pure constant (only `Variable::ONE` terms), return the scalar value.
    /// Returns `None` if any non-ONE variable is present.
    pub fn constant_value(&self) -> Option<FieldElement> {
        if !self.is_constant() {
            return None;
        }
        let mut sum = FieldElement::ZERO;
        for (_, coeff) in &self.terms {
            sum = sum.add(coeff);
        }
        Some(sum)
    }

    /// If this LC is exactly `1 * var` where `var` is not the constant-one wire,
    /// return that variable. Otherwise return `None`.
    ///
    /// This enables zero-cost materialization when an LC already represents
    /// a single circuit variable.
    pub fn as_single_variable(&self) -> Option<Variable> {
        if self.terms.len() == 1 {
            let (var, coeff) = &self.terms[0];
            if *var != Variable::ONE && *coeff == FieldElement::ONE {
                return Some(*var);
            }
        }
        None
    }

    /// Evaluate the LC given a full witness assignment.
    /// witness[i] = value of variable i.
    pub fn evaluate(&self, witness: &[FieldElement]) -> FieldElement {
        let mut sum = FieldElement::ZERO;
        for (var, coeff) in &self.terms {
            let val = witness[var.0];
            sum = sum.add(&coeff.mul(&val));
        }
        sum
    }
}

// ============================================================================
// Arithmetic on LinearCombinations
// ============================================================================

impl std::ops::Add for LinearCombination {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.terms.extend(rhs.terms);
        self
    }
}

impl std::ops::Sub for LinearCombination {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        for (var, coeff) in rhs.terms {
            self.terms.push((var, coeff.neg()));
        }
        self
    }
}

/// Scalar multiplication: coeff * LC
impl std::ops::Mul<FieldElement> for LinearCombination {
    type Output = Self;
    fn mul(mut self, scalar: FieldElement) -> Self {
        for (_, coeff) in &mut self.terms {
            *coeff = coeff.mul(&scalar);
        }
        self
    }
}

// ============================================================================
// R1CS Constraint
// ============================================================================

/// A single R1CS constraint: A · B = C
///
/// Where A, B, C are linear combinations of variables, and ·
/// means "the dot product of the LC's evaluation with the witness
/// vector, then multiplied together".
#[derive(Debug, Clone)]
pub struct Constraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

// ============================================================================
// ConstraintSystem
// ============================================================================

/// The main R1CS constraint system.
///
/// Manages variable allocation, constraint collection, and
/// witness verification.
pub struct ConstraintSystem {
    /// Total number of variables (including ONE at index 0).
    num_variables: usize,
    /// Number of public input variables (indices 1..=num_pub_inputs).
    num_pub_inputs: usize,
    /// All constraints: each is (A, B, C) with A * B = C.
    constraints: Vec<Constraint>,
}

impl ConstraintSystem {
    pub fn new() -> Self {
        Self {
            // Variable 0 = ONE (constant wire)
            num_variables: 1,
            num_pub_inputs: 0,
            constraints: Vec::new(),
        }
    }

    // --- Variable allocation ---

    /// Allocate a public input variable.
    /// Public inputs must be allocated before any private/auxiliary variables.
    pub fn alloc_input(&mut self) -> Variable {
        let idx = self.num_variables;
        self.num_variables += 1;
        self.num_pub_inputs += 1;
        Variable(idx)
    }

    /// Allocate a private (witness) or intermediate variable.
    pub fn alloc_witness(&mut self) -> Variable {
        let idx = self.num_variables;
        self.num_variables += 1;
        Variable(idx)
    }

    // --- Constraint enforcement ---

    /// Add a constraint: A * B = C
    pub fn enforce(
        &mut self,
        a: LinearCombination,
        b: LinearCombination,
        c: LinearCombination,
    ) {
        self.constraints.push(Constraint { a, b, c });
    }

    /// Convenience: enforce that lc = 0 (i.e., 0 * 0 = lc is wrong,
    /// so we do lc * ONE = 0 → enforce(lc, ONE, zero)).
    /// Actually: enforce(lc, 1, 0) doesn't work.
    /// Correct encoding: enforce(lc, ONE, zero_lc) means lc * 1 = 0.
    /// Wait — that constrains lc to be zero. Let me think.
    /// enforce(A, B, C) means A*B = C.
    /// To constrain x = y: enforce(x, 1, y) → x*1 = y.
    pub fn enforce_equal(&mut self, x: LinearCombination, y: LinearCombination) {
        // x * 1 = y  →  x = y
        self.enforce(x, LinearCombination::from_variable(Variable::ONE), y);
    }

    // --- Queries ---

    /// Total number of variables (including ONE).
    pub fn num_variables(&self) -> usize {
        self.num_variables
    }

    /// Number of public inputs.
    pub fn num_pub_inputs(&self) -> usize {
        self.num_pub_inputs
    }

    /// Number of constraints.
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Access constraints for serialization or verification.
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    // --- Verification ---

    /// Verify that a witness satisfies all constraints.
    ///
    /// witness[0] must be ONE (FieldElement::ONE).
    /// witness[1..=num_pub_inputs] = public inputs.
    /// witness[num_pub_inputs+1..] = private/intermediate values.
    ///
    /// Returns Ok(()) if all constraints satisfied, or the index
    /// of the first failing constraint.
    pub fn verify(&self, witness: &[FieldElement]) -> Result<(), usize> {
        if witness.len() != self.num_variables {
            return Err(usize::MAX);
        }
        // witness[0] must be 1
        if witness[0] != FieldElement::ONE {
            return Err(usize::MAX);
        }

        for (i, constraint) in self.constraints.iter().enumerate() {
            let a_val = constraint.a.evaluate(witness);
            let b_val = constraint.b.evaluate(witness);
            let c_val = constraint.c.evaluate(witness);

            // Check: A * B == C
            let ab = a_val.mul(&b_val);
            if ab != c_val {
                return Err(i);
            }
        }

        Ok(())
    }
}

// ============================================================================
// Builder helpers (syntactic sugar for circuit construction)
// ============================================================================

impl ConstraintSystem {
    /// Allocate a witness variable and constrain it to be the product of two LCs.
    /// Returns the new variable (= a * b in the field).
    pub fn mul_lc(
        &mut self,
        a: &LinearCombination,
        b: &LinearCombination,
    ) -> Variable {
        let out = self.alloc_witness();
        self.enforce(
            a.clone(),
            b.clone(),
            LinearCombination::from_variable(out),
        );
        out
    }

    /// Constrain: out = a + b (linear, no new constraint needed if we track LCs).
    /// This just returns the sum LC. Only use enforce if a multiplication is involved.
    pub fn add_lc(
        &self,
        a: &LinearCombination,
        b: &LinearCombination,
    ) -> LinearCombination {
        a.clone() + b.clone()
    }

    /// Allocate a witness variable constrained to be the inverse of x.
    /// Enforces: x * x_inv = 1
    /// Returns x_inv variable. Caller must assign the correct witness value.
    pub fn inv_lc(&mut self, x: &LinearCombination) -> Variable {
        let x_inv = self.alloc_witness();
        self.enforce(
            x.clone(),
            LinearCombination::from_variable(x_inv),
            LinearCombination::from_constant(FieldElement::ONE),
        );
        x_inv
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use memory::FieldElement;

    #[test]
    fn test_simple_multiplication_constraint() {
        // Circuit: prove knowledge of a, b such that a * b = c (public)
        let mut cs = ConstraintSystem::new();

        // Public output
        let c = cs.alloc_input(); // index 1

        // Private inputs
        let a = cs.alloc_witness(); // index 2
        let b = cs.alloc_witness(); // index 3

        // Constraint: a * b = c
        cs.enforce(
            LinearCombination::from_variable(a),
            LinearCombination::from_variable(b),
            LinearCombination::from_variable(c),
        );

        assert_eq!(cs.num_variables(), 4); // ONE, c, a, b
        assert_eq!(cs.num_pub_inputs(), 1); // c
        assert_eq!(cs.num_constraints(), 1);

        // Witness: ONE=1, c=42, a=6, b=7
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(42), // c
            FieldElement::from_u64(6),  // a
            FieldElement::from_u64(7),  // b
        ];

        assert!(cs.verify(&witness).is_ok());
    }

    #[test]
    fn test_failing_constraint() {
        let mut cs = ConstraintSystem::new();
        let c = cs.alloc_input();
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();

        cs.enforce(
            LinearCombination::from_variable(a),
            LinearCombination::from_variable(b),
            LinearCombination::from_variable(c),
        );

        // Wrong witness: 6 * 7 != 43
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(43), // wrong c
            FieldElement::from_u64(6),
            FieldElement::from_u64(7),
        ];

        assert_eq!(cs.verify(&witness), Err(0));
    }

    #[test]
    fn test_linear_combination_evaluate() {
        // LC: 3*x + 5*y
        let x = Variable(1);
        let y = Variable(2);

        let mut lc = LinearCombination::zero();
        lc.add_term(x, FieldElement::from_u64(3));
        lc.add_term(y, FieldElement::from_u64(5));

        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(10), // x = 10
            FieldElement::from_u64(4),  // y = 4
        ];

        // 3*10 + 5*4 = 50
        assert_eq!(lc.evaluate(&witness), FieldElement::from_u64(50));
    }

    #[test]
    fn test_enforce_equal() {
        let mut cs = ConstraintSystem::new();
        let x = cs.alloc_witness(); // index 1
        let y = cs.alloc_witness(); // index 2

        // x = y
        cs.enforce_equal(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
        );

        // Satisfying: x=7, y=7
        let good = vec![
            FieldElement::ONE,
            FieldElement::from_u64(7),
            FieldElement::from_u64(7),
        ];
        assert!(cs.verify(&good).is_ok());

        // Failing: x=7, y=8
        let bad = vec![
            FieldElement::ONE,
            FieldElement::from_u64(7),
            FieldElement::from_u64(8),
        ];
        assert!(cs.verify(&bad).is_err());
    }

    #[test]
    fn test_quadratic_expression() {
        // Circuit: prove knowledge of x such that x^2 + x + 5 = 35 (public)
        // x = 5 is the solution
        let mut cs = ConstraintSystem::new();

        let out = cs.alloc_input(); // public: 35
        let x = cs.alloc_witness(); // private: 5
        let x_sq = cs.alloc_witness(); // intermediate: x^2 = 25

        // Constraint 1: x * x = x_sq
        cs.enforce(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(x_sq),
        );

        // Constraint 2: (x_sq + x + 5) * 1 = out
        // i.e. x_sq + x + 5*ONE = out
        let mut lhs = LinearCombination::zero();
        lhs.add_term(x_sq, FieldElement::ONE);
        lhs.add_term(x, FieldElement::ONE);
        lhs.add_term(Variable::ONE, FieldElement::from_u64(5));

        cs.enforce_equal(lhs, LinearCombination::from_variable(out));

        assert_eq!(cs.num_constraints(), 2);

        // Witness: ONE=1, out=35, x=5, x_sq=25
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(35),
            FieldElement::from_u64(5),
            FieldElement::from_u64(25),
        ];

        assert!(cs.verify(&witness).is_ok());
    }

    #[test]
    fn test_mul_lc_helper() {
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();

        let product_var = cs.mul_lc(
            &LinearCombination::from_variable(a),
            &LinearCombination::from_variable(b),
        );

        // product_var should be index 3 (ONE=0, a=1, b=2, product=3)
        assert_eq!(product_var.index(), 3);
        assert_eq!(cs.num_constraints(), 1);

        // Verify: a=6, b=7, product=42
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(6),
            FieldElement::from_u64(7),
            FieldElement::from_u64(42),
        ];
        assert!(cs.verify(&witness).is_ok());
    }

    #[test]
    fn test_constant_lc_is_constant() {
        let lc = LinearCombination::from_constant(FieldElement::from_u64(42));
        assert!(lc.is_constant());
        assert_eq!(lc.constant_value(), Some(FieldElement::from_u64(42)));
    }

    #[test]
    fn test_zero_lc_is_constant() {
        let lc = LinearCombination::zero();
        assert!(lc.is_constant());
        assert_eq!(lc.constant_value(), Some(FieldElement::ZERO));
    }

    #[test]
    fn test_variable_lc_not_constant() {
        let lc = LinearCombination::from_variable(Variable(1));
        assert!(!lc.is_constant());
        assert_eq!(lc.constant_value(), None);
    }

    #[test]
    fn test_mixed_lc_not_constant() {
        let mut lc = LinearCombination::from_constant(FieldElement::from_u64(5));
        lc.add_term(Variable(1), FieldElement::ONE);
        assert!(!lc.is_constant());
        assert_eq!(lc.constant_value(), None);
    }

    #[test]
    fn test_constant_sum() {
        // Adding two constants should still be constant
        let a = LinearCombination::from_constant(FieldElement::from_u64(3));
        let b = LinearCombination::from_constant(FieldElement::from_u64(7));
        let sum = a + b;
        assert!(sum.is_constant());
        assert_eq!(sum.constant_value(), Some(FieldElement::from_u64(10)));
    }

    #[test]
    fn test_lc_arithmetic() {
        let x = Variable(1);
        let y = Variable(2);

        let lc_x = LinearCombination::from_variable(x);
        let lc_y = LinearCombination::from_variable(y);

        // x + y
        let sum = lc_x.clone() + lc_y.clone();
        assert_eq!(sum.terms.len(), 2);

        // x - y
        let diff = lc_x.clone() - lc_y.clone();
        assert_eq!(diff.terms.len(), 2);

        // 3 * x
        let scaled = lc_x * FieldElement::from_u64(3);
        assert_eq!(scaled.terms.len(), 1);
        assert_eq!(scaled.terms[0].1, FieldElement::from_u64(3));
    }
}
