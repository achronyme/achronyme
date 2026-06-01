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
use std::fmt;

use memory::{Bn254Fr, FieldBackend, FieldElement};

// ============================================================================
// Error types
// ============================================================================

/// Errors from R1CS evaluation and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintError {
    /// A variable index in a linear combination exceeds the witness length.
    VariableOutOfBounds { variable: usize, witness_len: usize },
    /// Witness vector length doesn't match the constraint system.
    WitnessLengthMismatch { expected: usize, got: usize },
    /// `witness[0]` is not the ONE constant.
    BadConstantWire,
    /// Constraint at the given index is not satisfied (A * B != C).
    ConstraintUnsatisfied(usize),
}

impl fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstraintError::VariableOutOfBounds {
                variable,
                witness_len,
            } => write!(
                f,
                "variable index {variable} out of bounds (witness length {witness_len})"
            ),
            ConstraintError::WitnessLengthMismatch { expected, got } => {
                write!(f, "witness length {got} != expected {expected}")
            }
            ConstraintError::BadConstantWire => write!(f, "witness[0] is not ONE"),
            ConstraintError::ConstraintUnsatisfied(idx) => {
                write!(f, "constraint {idx} unsatisfied")
            }
        }
    }
}

impl std::error::Error for ConstraintError {}

// ============================================================================
// Variable (Wire reference)
// ============================================================================

/// A reference to a wire in the constraint system.
///
/// ```
/// use constraints::Variable;
///
/// assert_eq!(Variable::ONE.index(), 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Variable(pub usize);

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

/// A linear combination: Σ(coefficient_i * variable_i).
///
/// Stored as sparse (variable, coefficient) pairs. Generic over `F: FieldBackend`;
/// bare `LinearCombination` defaults to BN254 for backward compatibility.
///
/// ```
/// use constraints::{Variable, LinearCombination};
/// use memory::FieldElement;
///
/// let lc_var: LinearCombination = LinearCombination::from_variable(Variable(1));
/// assert_eq!(lc_var.terms().len(), 1);
///
/// let lc_const: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(42));
/// assert!(lc_const.is_constant());
/// assert_eq!(lc_const.constant_value(), Some(FieldElement::from_u64(42)));
/// ```
/// Sparse linear combination over R1CS wires.
///
/// **Invariant (post-[`Self::simplify`]):** each [`Variable`] appears at
/// most once, no term carries a zero coefficient, and terms are sorted
/// by variable index. The `+` / `-` / `*` operators preserve semantic
/// equality but do NOT canonicalize — call [`Self::simplify`] before
/// structurally comparing two `LinearCombination`s.
///
/// The `terms` field is crate-private to prevent downstream callers
/// from bypassing [`Self::add_term`] and corrupting the sparse-form
/// invariant. Use [`Self::terms`] for read access and
/// [`Self::into_terms`] to consume.
#[derive(Debug, Clone)]
pub struct LinearCombination<F: FieldBackend = Bn254Fr> {
    pub(crate) terms: Vec<(Variable, FieldElement<F>)>,
}

impl<F: FieldBackend> Default for LinearCombination<F> {
    fn default() -> Self {
        Self { terms: vec![] }
    }
}

impl<F: FieldBackend> LinearCombination<F> {
    pub fn zero() -> Self {
        Self { terms: vec![] }
    }

    /// Create LC from a single variable with coefficient 1.
    pub fn from_variable(var: Variable) -> Self {
        Self {
            terms: vec![(var, FieldElement::<F>::one())],
        }
    }

    /// Create LC from a constant field element: coeff * ONE.
    pub fn from_constant(coeff: FieldElement<F>) -> Self {
        if coeff.is_zero() {
            return Self::zero();
        }
        Self {
            terms: vec![(Variable::ONE, coeff)],
        }
    }

    /// Add a (coefficient * variable) term.
    pub fn add_term(&mut self, var: Variable, coeff: FieldElement<F>) {
        self.terms.push((var, coeff));
    }

    /// Read-only view of the term list. Prefer this over the public
    /// `terms` field when you only need to iterate — it decouples
    /// callers from the storage representation and will keep working
    /// after the field becomes `pub(crate)` in the post-cleanup
    /// encapsulation pass.
    pub fn terms(&self) -> &[(Variable, FieldElement<F>)] {
        &self.terms
    }

    /// Consume the LC and return its term list. Useful for callers
    /// that want to take ownership (serialization, format conversion).
    pub fn into_terms(self) -> Vec<(Variable, FieldElement<F>)> {
        self.terms
    }

    /// Trim the term vec's capacity to its length.
    ///
    /// Incremental `add_term` calls leave the underlying `Vec`'s
    /// capacity at the next power-of-two doubling step, which can be
    /// up to ~2x the active term count. For LCs that are stored
    /// long-lived after construction (most notably the per-SSA-var
    /// cache held by the R1CS compiler), the doubling tail dominates
    /// the heap footprint because the active term count is small
    /// (typically 1) while capacity rounds up. Callers should invoke
    /// this once the LC is final and will no longer be appended to.
    pub fn shrink_to_fit(&mut self) {
        self.terms.shrink_to_fit();
    }

    /// Current allocated capacity of the term vec, in element slots.
    /// Hidden because production code branching on capacity is a
    /// representation leak; the pin tests use it to assert the
    /// post-shrink invariant `capacity == len`.
    #[doc(hidden)]
    pub fn terms_capacity(&self) -> usize {
        self.terms.capacity()
    }

    /// Merge duplicate variable terms and remove zero coefficients.
    ///
    /// E.g. `x - x` simplifies to the empty LC (constant zero),
    /// `3x + 5x` simplifies to `8x`.
    ///
    /// ```
    /// use constraints::{Variable, LinearCombination};
    ///
    /// let x = Variable(1);
    /// let lc: LinearCombination = LinearCombination::from_variable(x)
    ///     - LinearCombination::from_variable(x);
    /// assert!(lc.is_constant());
    /// ```
    pub fn simplify(&self) -> Self {
        let mut result = self.clone();
        result.simplify_in_place();
        result
    }

    /// In-place version of [`Self::simplify`]: merges duplicate variable
    /// terms and drops zero coefficients without allocating a temporary
    /// `BTreeMap`. Sorts the terms vector by variable index, then runs a
    /// single linear scan that merges adjacent duplicates and writes
    /// non-zero results back via two cursors (read / write).
    ///
    /// **Why this exists:** the optimizer's hot path
    /// (`apply_substitution`, `solve_cluster_linear`) calls `simplify`
    /// many times per constraint per round. Allocating a `BTreeMap`
    /// per call dominated allocator time on bit-heavy circuits.
    /// Sorting an existing `Vec` is allocation-free; the merge scan
    /// runs in-place; total allocations per call drop to zero
    /// (assuming the caller already owns a `LinearCombination`).
    pub fn simplify_in_place(&mut self) {
        if self.terms.len() <= 1 {
            // Single zero-coeff term still needs scrubbing.
            if let Some((_, coeff)) = self.terms.first() {
                if coeff.is_zero() {
                    self.terms.clear();
                }
            }
            return;
        }
        // Sort by variable index so duplicates are adjacent.
        self.terms.sort_unstable_by_key(|(var, _)| var.0);

        // Two-cursor merge. `write` is the next free slot, `read` walks
        // the input. Adjacent same-variable terms accumulate into the
        // current `cur_coeff`; non-zero results land at `write`.
        let n = self.terms.len();
        let mut write = 0usize;
        let mut read = 0usize;
        while read < n {
            let (cur_var, mut cur_coeff) = self.terms[read];
            read += 1;
            while read < n && self.terms[read].0 .0 == cur_var.0 {
                cur_coeff = cur_coeff.add(&self.terms[read].1);
                read += 1;
            }
            if !cur_coeff.is_zero() {
                self.terms[write] = (cur_var, cur_coeff);
                write += 1;
            }
        }
        self.terms.truncate(write);
    }

    /// Returns true if this LC only references `Variable::ONE` (i.e., it's a pure constant).
    pub fn is_constant(&self) -> bool {
        match self.terms.as_slice() {
            [] => return true,
            [(var, _)] => return *var == Variable::ONE,
            _ => {}
        }
        self.simplify()
            .terms
            .iter()
            .all(|(var, _)| *var == Variable::ONE)
    }

    /// If this LC is a pure constant (only `Variable::ONE` terms), return the scalar value.
    /// Returns `None` if any non-ONE variable is present.
    pub fn constant_value(&self) -> Option<FieldElement<F>> {
        match self.terms.as_slice() {
            [] => return Some(FieldElement::<F>::zero()),
            [(var, coeff)] => {
                return if *var == Variable::ONE {
                    Some(*coeff)
                } else {
                    None
                };
            }
            _ => {}
        }
        let simplified = self.simplify();
        if !simplified
            .terms
            .iter()
            .all(|(var, _)| *var == Variable::ONE)
        {
            return None;
        }
        let mut sum = FieldElement::<F>::zero();
        for (_, coeff) in &simplified.terms {
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
        if let [(var, coeff)] = self.terms.as_slice() {
            if *var != Variable::ONE && *coeff == FieldElement::<F>::one() {
                return Some(*var);
            }
            return None;
        }
        let simplified = self.simplify();
        if simplified.terms.len() == 1 {
            let (var, coeff) = &simplified.terms[0];
            if *var != Variable::ONE && *coeff == FieldElement::<F>::one() {
                return Some(*var);
            }
        }
        None
    }

    /// Evaluate the LC given a full witness assignment.
    /// witness[i] = value of variable i.
    pub fn evaluate(
        &self,
        witness: &[FieldElement<F>],
    ) -> Result<FieldElement<F>, ConstraintError> {
        let mut sum = FieldElement::<F>::zero();
        for (var, coeff) in &self.terms {
            let val = witness
                .get(var.0)
                .ok_or(ConstraintError::VariableOutOfBounds {
                    variable: var.0,
                    witness_len: witness.len(),
                })?;
            sum = sum.add(&coeff.mul(val));
        }
        Ok(sum)
    }
}

// ============================================================================
// Arithmetic on LinearCombinations
// ============================================================================

impl<F: FieldBackend> std::ops::Add for LinearCombination<F> {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self.terms.extend(rhs.terms);
        self
    }
}

impl<F: FieldBackend> std::ops::Sub for LinearCombination<F> {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        for (var, coeff) in rhs.terms {
            self.terms.push((var, coeff.neg()));
        }
        self
    }
}

/// Scalar multiplication: coeff * LC
impl<F: FieldBackend> std::ops::Mul<FieldElement<F>> for LinearCombination<F> {
    type Output = Self;
    fn mul(mut self, scalar: FieldElement<F>) -> Self {
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
pub struct Constraint<F: FieldBackend = Bn254Fr> {
    pub a: LinearCombination<F>,
    pub b: LinearCombination<F>,
    pub c: LinearCombination<F>,
}

impl<F: FieldBackend> Constraint<F> {
    /// Build a constraint `A · B = C`. `a`, `b`, `c` are linear
    /// combinations evaluated against the witness vector. The three
    /// LCs carry no ordering invariant between them; equality of two
    /// `Constraint`s is not structural — canonicalize via
    /// `LinearCombination::simplify()` before comparing if needed.
    pub fn new(a: LinearCombination<F>, b: LinearCombination<F>, c: LinearCombination<F>) -> Self {
        Self { a, b, c }
    }
}

// ============================================================================
// ConstraintSystem
// ============================================================================

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
    /// substitution map at witness time — see
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
    /// enabled. The map (eliminated `Variable.index()` → replacement
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

    // --- Variable allocation ---

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

    // --- Constraint enforcement ---

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

    // --- Verification ---

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
}

// ============================================================================
// Builder helpers (syntactic sugar for circuit construction)
// ============================================================================

impl<F: FieldBackend> ConstraintSystem<F> {
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
        let mut cs: ConstraintSystem = ConstraintSystem::new();

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

        assert_eq!(
            cs.verify(&witness),
            Err(ConstraintError::ConstraintUnsatisfied(0))
        );
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
        assert_eq!(lc.evaluate(&witness).unwrap(), FieldElement::from_u64(50));
    }

    #[test]
    fn linear_combination_fast_shape_queries_match_simplified_semantics() {
        let zero: LinearCombination = LinearCombination::zero();
        assert!(zero.is_constant());
        assert_eq!(zero.constant_value(), Some(FieldElement::zero()));
        assert_eq!(zero.as_single_variable(), None);

        let one: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(7));
        assert!(one.is_constant());
        assert_eq!(one.constant_value(), Some(FieldElement::from_u64(7)));
        assert_eq!(one.as_single_variable(), None);

        let x: LinearCombination = LinearCombination::from_variable(Variable(3));
        assert!(!x.is_constant());
        assert_eq!(x.constant_value(), None);
        assert_eq!(x.as_single_variable(), Some(Variable(3)));

        let cancelled: LinearCombination = LinearCombination::from_variable(Variable(3))
            - LinearCombination::from_variable(Variable(3));
        assert!(cancelled.is_constant());
        assert_eq!(cancelled.constant_value(), Some(FieldElement::zero()));
        assert_eq!(cancelled.as_single_variable(), None);
    }

    #[test]
    fn test_evaluate_oob_returns_error() {
        let x = Variable(10); // index 10, way out of bounds
        let mut lc = LinearCombination::zero();
        lc.add_term(x, FieldElement::ONE);
        let witness = vec![FieldElement::ONE]; // only 1 element
        assert_eq!(
            lc.evaluate(&witness),
            Err(ConstraintError::VariableOutOfBounds {
                variable: 10,
                witness_len: 1,
            })
        );
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
    fn count_mode_reports_constraints_without_retaining_rows() {
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        let z = cs.alloc_witness();
        cs.disable_constraint_retention();

        cs.enforce(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(y),
            LinearCombination::from_variable(z),
        );
        cs.enforce_equal(
            LinearCombination::from_variable(x),
            LinearCombination::from_variable(z),
        );

        assert_eq!(cs.num_constraints(), 2);
        assert!(cs.constraints().is_empty());
        assert!(!cs.constraint_retention_enabled());
        assert_eq!(cs.num_variables(), 4);
    }

    #[test]
    fn count_only_non_linear_mul_fast_path_counts_one_row() {
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        cs.disable_constraint_retention();
        cs.enable_incremental_collapse_count_only();

        let out = cs
            .try_count_only_non_linear_mul()
            .expect("count-only non-linear fast path active");

        assert_eq!(out, Variable(1));
        assert_eq!(cs.num_variables(), 2);
        assert_eq!(cs.num_constraints(), 1);
        assert!(cs.constraints().is_empty());
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
        let lc: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(42));
        assert!(lc.is_constant());
        assert_eq!(lc.constant_value(), Some(FieldElement::from_u64(42)));
    }

    #[test]
    fn test_zero_lc_is_constant() {
        let lc: LinearCombination = LinearCombination::zero();
        assert!(lc.is_constant());
        assert_eq!(lc.constant_value(), Some(FieldElement::ZERO));
    }

    #[test]
    fn test_variable_lc_not_constant() {
        let lc: LinearCombination = LinearCombination::from_variable(Variable(1));
        assert!(!lc.is_constant());
        assert_eq!(lc.constant_value(), None);
    }

    #[test]
    fn test_mixed_lc_not_constant() {
        let mut lc: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(5));
        lc.add_term(Variable(1), FieldElement::ONE);
        assert!(!lc.is_constant());
        assert_eq!(lc.constant_value(), None);
    }

    #[test]
    fn test_constant_sum() {
        // Adding two constants should still be constant
        let a: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(3));
        let b: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(7));
        let sum = a + b;
        assert!(sum.is_constant());
        assert_eq!(sum.constant_value(), Some(FieldElement::from_u64(10)));
    }

    #[test]
    fn test_lc_arithmetic() {
        let x = Variable(1);
        let y = Variable(2);

        let lc_x: LinearCombination = LinearCombination::from_variable(x);
        let lc_y: LinearCombination = LinearCombination::from_variable(y);

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

    // M3: simplify() tests

    #[test]
    fn test_lc_simplify_cancels_vars() {
        // x - x should simplify to constant zero
        let x = Variable(1);
        let lc: LinearCombination =
            LinearCombination::from_variable(x) - LinearCombination::from_variable(x);
        assert!(lc.is_constant());
        assert_eq!(lc.constant_value(), Some(FieldElement::ZERO));
    }

    #[test]
    fn test_lc_simplify_merges_same_var() {
        // 3x + 5x → 8x (not single variable since coeff != 1)
        let x = Variable(1);
        let a: LinearCombination = LinearCombination::from_variable(x) * FieldElement::from_u64(3);
        let b: LinearCombination = LinearCombination::from_variable(x) * FieldElement::from_u64(5);
        let sum = a + b;
        let simplified = sum.simplify();
        assert_eq!(simplified.terms.len(), 1);
        assert_eq!(simplified.terms[0].1, FieldElement::from_u64(8));
        assert!(sum.as_single_variable().is_none()); // coeff is 8, not 1
    }

    #[test]
    fn test_lc_as_single_variable_after_cancellation() {
        // 2x - x → x (single variable)
        let x = Variable(1);
        let two_x: LinearCombination =
            LinearCombination::from_variable(x) * FieldElement::from_u64(2);
        let one_x: LinearCombination = LinearCombination::from_variable(x);
        let diff = two_x - one_x;
        assert_eq!(diff.as_single_variable(), Some(x));
    }

    #[test]
    fn test_lc_constant_with_cancellation() {
        // (5*ONE + 3x) - 3x → constant 5
        let x = Variable(1);
        let mut a: LinearCombination = LinearCombination::from_constant(FieldElement::from_u64(5));
        a.add_term(x, FieldElement::from_u64(3));
        let b = LinearCombination::from_variable(x) * FieldElement::from_u64(3);
        let diff = a - b;
        assert!(diff.is_constant());
        assert_eq!(diff.constant_value(), Some(FieldElement::from_u64(5)));
    }
}
