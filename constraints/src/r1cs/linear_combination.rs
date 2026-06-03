use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::ConstraintError;

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

/// A linear combination: sum(coefficient_i * variable_i).
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
/// equality but do NOT canonicalize - call [`Self::simplify`] before
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
    /// `terms` field when you only need to iterate - it decouples
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
