use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::{ConstraintError, LinearCombination, Variable};

/// A single R1CS constraint: A * B = C
///
/// Where A, B, C are linear combinations of variables, and * means "the dot
/// product of the LC's evaluation with the witness vector, then multiplied
/// together".
#[derive(Debug, Clone)]
pub struct Constraint<F: FieldBackend = Bn254Fr> {
    pub a: LinearCombination<F>,
    pub b: LinearCombination<F>,
    pub c: LinearCombination<F>,
}

impl<F: FieldBackend> Constraint<F> {
    /// Build a constraint `A * B = C`. `a`, `b`, `c` are linear
    /// combinations evaluated against the witness vector. The three
    /// LCs carry no ordering invariant between them; equality of two
    /// `Constraint`s is not structural - canonicalize via
    /// `LinearCombination::simplify()` before comparing if needed.
    pub fn new(a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) -> Self {
        Self { a, b, c }
    }
}

/// The main R1CS constraint system.
///
/// Manages variable allocation, constraint collection, and
/// witness verification.
///
/// ```
/// use constraints::{ConstraintSystem, LinearCombination, Variable};
/// use memory::FieldElement;
///
/// let mut cs = ConstraintSystem::new();
/// let c = cs.alloc_input();   // public output
/// let a = cs.alloc_witness(); // private input
/// let b = cs.alloc_witness(); // private input
///
/// // Constraint: a * b = c
/// cs.enforce(
///     LinearCombination::from_variable(a),
///     LinearCombination::from_variable(b),
///     LinearCombination::from_variable(c),
///);
///
/// assert_eq!(cs.num_constraints(), 1);
///
/// // Witness: ONE=1, c=42, a=6, b=7
/// let witness = vec![
///     FieldElement::ONE,
///     FieldElement::from_u64(42),
///     FieldElement::from_u64(6),
///     FieldElement::from_u64(7),
/// ];
/// assert!(cs.verify(&witness).is_ok());
/// ```
#[derive(Clone)]
pub struct ConstraintSystem<F: FieldBackend = Bn254Fr> {
    /// Total number of variables (including ONE at index 0).
    num_variables: usize,
    /// Number of public input variables (indices 1..=num_pub_inputs).
    num_pub_inputs: usize,
    /// All constraints: each is (A, B, C) with A * B = C.
    constraints: Vec<Constraint<F>>,
    /// Logical number of emitted constraints. Normally this matches
    /// `constraints.len()`. In compile-only count mode, rows are not retained
    /// but this counter keeps progress and size reporting exact.
    constraint_count: usize,
    /// Whether emitted rows are retained in `constraints`.
    retain_constraints: bool,
    /// Incremental linear-collapse state. `None` (default) means
    /// constraints are stored verbatim. `Some` routes every [`enforce`]
    /// through the collapser, which folds linear constraints into a
    /// substitution map at emission time so `constraints` holds only the
    /// post-elimination survivors. Opt-in via
    /// [`enable_incremental_collapse`]; the default path is unchanged.
    ///
    /// [`enforce`]: ConstraintSystem::enforce
    /// [`enable_incremental_collapse`]: ConstraintSystem::enable_incremental_collapse
    collapse: Option<crate::r1cs_optimize::IncrementalCollapse<F>>,
}

impl<F: FieldBackend> Default for ConstraintSystem<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> ConstraintSystem<F> {
    pub fn new() -> Self {
        Self {
            // Variable 0 = ONE (constant wire)
            num_variables: 1,
            num_pub_inputs: 0,
            constraints: Vec::new(),
            constraint_count: 0,
            retain_constraints: true,
            collapse: None,
        }
    }

    /// Enable incremental linear collapse: subsequent [`enforce`] calls fold
    /// linear constraints into a substitution map at emission time instead of
    /// storing them, so `constraints` only ever holds post-elimination
    /// survivors. Off by default. Must be enabled BEFORE emission begins and
    /// AFTER public inputs are allocated (the protected set snapshots
    /// `num_pub_inputs`). Eliminated wires are recovered from the
    /// substitution map at witness time - see
    /// [`take_collapse_substitution_map`].
    ///
    /// [`enforce`]: ConstraintSystem::enforce
    /// [`take_collapse_substitution_map`]: ConstraintSystem::take_collapse_substitution_map
    pub fn enable_incremental_collapse(&mut self) {
        self.collapse = Some(crate::r1cs_optimize::IncrementalCollapse::new(
            self.num_pub_inputs,
        ));
    }

    /// Enable count-only incremental linear collapse.
    ///
    /// This folds eligible linear rows during emission but intentionally
    /// discards the substitution map. It is only valid after row retention is
    /// disabled for compile-only sizing/counting; callers cannot serialize,
    /// optimize, prove, verify, or reconstruct eliminated witnesses.
    pub fn enable_incremental_collapse_count_only(&mut self) {
        assert!(
            !self.retain_constraints,
            "count-only collapse requires disabled constraint retention"
        );
        self.collapse = Some(crate::r1cs_optimize::IncrementalCollapse::new_count_only(
            self.num_pub_inputs,
        ));
    }

    /// Whether incremental collapse is active.
    pub fn incremental_collapse_enabled(&self) -> bool {
        self.collapse.is_some()
    }

    /// Take the substitution map accumulated by incremental collapse,
    /// disabling further collapse. Returns `None` if collapse was never
    /// enabled. The map (eliminated `Variable.index()` -> replacement
    /// `LinearCombination`) is consumed by witness generation to reconstruct
    /// eliminated wires, exactly as the batch optimizer's map is.
    pub fn take_collapse_substitution_map(
        &mut self,
    ) -> Option<crate::r1cs_optimize::SubstitutionMap<F>> {
        self.collapse.take().map(|c| c.into_substitution_map())
    }

    /// Disable row retention while preserving the emitted constraint count.
    ///
    /// This is intended for compile-only passes that need exact sizing and
    /// allocator behavior for wires but do not serialize, optimize, verify, or
    /// prove against the in-memory rows.
    pub fn disable_constraint_retention(&mut self) {
        self.retain_constraints = false;
        self.constraints.clear();
    }

    /// Whether emitted rows are retained for serialization, optimization,
    /// verification, and proving.
    pub fn constraint_retention_enabled(&self) -> bool {
        self.retain_constraints
    }

    /// Count a known non-linear multiplication row in compile-only,
    /// count-only-collapse mode without allocating a transient
    /// [`Constraint`]. Returns `None` outside that exact mode.
    ///
    /// This is valid only when the caller has already established that
    /// both multiplicands are non-constant, so the row cannot be
    /// absorbed by linear collapse and would be retained only as a
    /// counted survivor.
    pub fn try_count_only_non_linear_mul(&mut self) -> Option<Variable> {
        if self.retain_constraints
            || !self
                .collapse
                .as_ref()
                .is_some_and(|collapse| collapse.is_count_only())
        {
            return None;
        }
        let out = self.alloc_witness();
        self.constraint_count += 1;
        Some(out)
    }

    /// Allocate a public input variable.
    /// Public inputs must be allocated before any private/auxiliary variables.
    pub fn alloc_input(&mut self) -> Variable {
        let idx = self.num_variables;
        self.num_variables += 1;
        self.num_pub_inputs += 1;
        // Keep the collapser's protected set tracking the full public range
        // even when inputs are allocated after collapse is enabled.
        if let Some(collapse) = self.collapse.as_mut() {
            collapse.protect(idx);
        }
        Variable(idx)
    }

    /// Allocate a private (witness) or intermediate variable.
    pub fn alloc_witness(&mut self) -> Variable {
        let idx = self.num_variables;
        self.num_variables += 1;
        Variable(idx)
    }

    /// Add a constraint: A * B = C
    pub fn enforce(
        &mut self,
        a: LinearCombination<F>,
        b: LinearCombination<F>,
        c: LinearCombination<F>,
    ) {
        let constraint = Constraint { a, b, c };
        match self.collapse.take() {
            // Default path: store verbatim, byte-identical to before.
            None => self.record_constraint(constraint),
            // Collapse path: fold the constraint, store only survivors.
            // Take/restore avoids borrowing `collapse` and `constraints`
            // simultaneously.
            Some(mut collapse) => {
                if let Some(survivor) = collapse.fold(constraint) {
                    self.record_constraint(survivor);
                }
                self.collapse = Some(collapse);
            }
        }
    }

    fn record_constraint(&mut self, constraint: Constraint<F>) {
        self.constraint_count += 1;
        if self.retain_constraints {
            self.constraints.push(constraint);
        }
    }

    /// Convenience: constrain x = y via x * 1 = y.
    pub fn enforce_equal(&mut self, x: LinearCombination<F>, y: LinearCombination<F>) {
        self.enforce(x, LinearCombination::from_variable(Variable::ONE), y);
    }

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
        self.constraint_count
    }

    /// Access constraints for serialization or verification.
    ///
    /// In compile-only count mode this slice is empty even though
    /// [`Self::num_constraints`] keeps reporting the logical emitted count.
    pub fn constraints(&self) -> &[Constraint<F>] {
        &self.constraints
    }

    /// Run linear constraint elimination on this constraint system.
    ///
    /// Identifies constraints where one side is a constant (i.e., linear
    /// constraints like `1 * LC = wire`) and substitutes the wire with the
    /// LC, eliminating the constraint. Runs to fixpoint.
    ///
    /// Returns the substitution map (needed for witness generation fixup)
    /// and optimization statistics.
    pub fn optimize_linear(
        &mut self,
    ) -> (
        crate::r1cs_optimize::SubstitutionMap<F>,
        crate::r1cs_optimize::R1CSOptimizeResult,
    ) {
        assert!(
            self.retain_constraints,
            "cannot optimize constraints after row retention has been disabled"
        );
        let result =
            crate::r1cs_optimize::optimize_linear(&mut self.constraints, self.num_pub_inputs);
        self.constraint_count = self.constraints.len();
        result
    }

    /// Run O2 constraint simplification on this constraint system.
    ///
    /// First runs O1 (linear constraint elimination) to fixpoint, then
    /// iteratively deduces new linear constraints from quadratic constraints
    /// via Gaussian elimination on the monomial matrix. Matches circom `--O2`.
    pub fn optimize_o2(
        &mut self,
    ) -> (
        crate::r1cs_optimize::SubstitutionMap<F>,
        crate::r1cs_optimize::R1CSOptimizeResult,
    ) {
        assert!(
            self.retain_constraints,
            "cannot optimize constraints after row retention has been disabled"
        );
        let result = crate::r1cs_optimize::optimize_o2(&mut self.constraints, self.num_pub_inputs);
        self.constraint_count = self.constraints.len();
        result
    }

    /// Sparse-row variant of `optimize_o2`.
    ///
    /// Partitions constraints into connected components (Union-Find on
    /// shared quadratic monomials) and runs Gaussian elimination on each
    /// cluster independently using `BTreeMap`-row representation. This
    /// avoids the dense `k x q` monomial matrix that OOMs on bit-heavy
    /// circuits (SHA-256, Keccak) where both dimensions reach 60k+.
    pub fn optimize_o2_sparse(
        &mut self,
    ) -> (
        crate::r1cs_optimize::SubstitutionMap<F>,
        crate::r1cs_optimize::R1CSOptimizeResult,
    ) {
        assert!(
            self.retain_constraints,
            "cannot optimize constraints after row retention has been disabled"
        );
        let result =
            crate::r1cs_optimize::optimize_o2_sparse(&mut self.constraints, self.num_pub_inputs);
        self.constraint_count = self.constraints.len();
        result
    }

    /// Verify that a witness satisfies all constraints.
    ///
    /// witness[0] must be ONE (the multiplicative identity).
    /// witness[1..=num_pub_inputs] = public inputs.
    /// witness[num_pub_inputs+1..] = private/intermediate values.
    ///
    /// Returns Ok(()) if all constraints satisfied, or the index
    /// of the first failing constraint.
    pub fn verify(&self, witness: &[FieldElement<F>]) -> Result<(), ConstraintError> {
        if witness.len() != self.num_variables {
            return Err(ConstraintError::WitnessLengthMismatch {
                expected: self.num_variables,
                got: witness.len(),
            });
        }
        // witness[0] must be 1
        if witness[0] != FieldElement::<F>::one() {
            return Err(ConstraintError::BadConstantWire);
        }

        for (i, constraint) in self.constraints.iter().enumerate() {
            let a_val = constraint.a.evaluate(witness)?;
            let b_val = constraint.b.evaluate(witness)?;
            let c_val = constraint.c.evaluate(witness)?;

            // Check: A * B == C
            let ab = a_val.mul(&b_val);
            if ab != c_val {
                return Err(ConstraintError::ConstraintUnsatisfied(i));
            }
        }

        Ok(())
    }

    /// Allocate a witness variable and constrain it to be the product of two LCs.
    /// Returns the new variable (= a * b in the field).
    ///
    /// ```
    /// use constraints::{ConstraintSystem, LinearCombination};
    /// use memory::FieldElement;
    ///
    /// let mut cs = ConstraintSystem::new();
    /// let a = cs.alloc_witness();
    /// let b = cs.alloc_witness();
    /// let product = cs.mul_lc(
    ///     &LinearCombination::from_variable(a),
    ///     &LinearCombination::from_variable(b),
    ///);
    /// assert_eq!(cs.num_constraints(), 1);
    ///
    /// // Verify: a=6, b=7, product=42
    /// let witness = vec![
    ///     FieldElement::ONE,
    ///     FieldElement::from_u64(6),
    ///     FieldElement::from_u64(7),
    ///     FieldElement::from_u64(42),
    /// ];
    /// assert!(cs.verify(&witness).is_ok());
    /// ```
    pub fn mul_lc(&mut self, a: &LinearCombination<F>, b: &LinearCombination<F>) -> Variable {
        let out = self.alloc_witness();
        self.enforce(a.clone(), b.clone(), LinearCombination::from_variable(out));
        out
    }

    /// Constrain: out = a + b (linear, no new constraint needed if we track LCs).
    /// This just returns the sum LC. Only use enforce if a multiplication is involved.
    pub fn add_lc(
        &self,
        a: &LinearCombination<F>,
        b: &LinearCombination<F>,
    ) -> LinearCombination<F> {
        a.clone() + b.clone()
    }

    /// Allocate a witness variable constrained to be the inverse of x.
    /// Enforces: x * x_inv = 1
    /// Returns x_inv variable. Caller must assign the correct witness value.
    pub fn inv_lc(&mut self, x: &LinearCombination<F>) -> Variable {
        let x_inv = self.alloc_witness();
        self.enforce(
            x.clone(),
            LinearCombination::from_variable(x_inv),
            LinearCombination::from_constant(FieldElement::<F>::one()),
        );
        x_inv
    }
}
