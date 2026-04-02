use constraints::r1cs::{LinearCombination, Variable};
use memory::{FieldBackend, FieldElement};

use crate::r1cs_backend::R1CSCompiler;
use crate::r1cs_error::R1CSError;
use crate::witness_gen::WitnessOp;

/// Compute 2^n as a field element for any backend.
///
/// O(n) via repeated doubling. For BN254, prefer [`compute_power_of_two`]
/// which uses a cached table — this function is for generic code paths.
pub(crate) fn power_of_two_generic<F: FieldBackend>(n: u32) -> FieldElement<F> {
    let mut result = FieldElement::<F>::one();
    let two = FieldElement::<F>::from_u64(2);
    for _ in 0..n {
        result = result.mul(&two);
    }
    result
}

/// R1CS gadget methods: reusable constraint-generation helpers.
impl<F: FieldBackend> R1CSCompiler<F> {
    /// Convert a `LinearCombination` to a `Variable`.
    ///
    /// If the LC is already a single variable with coefficient 1, returns it
    /// directly (0 constraints). Otherwise allocates a fresh witness variable
    /// and enforces equality (1 constraint).
    pub(crate) fn materialize_lc(&mut self, lc: &LinearCombination<F>) -> Variable {
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

    /// Multiply two LCs. If either operand is a constant, uses scalar
    /// multiplication (0 constraints). Otherwise allocates a witness
    /// variable (1 constraint).
    ///
    /// Note: WitnessOp::Multiply clones both LCs because witness generation
    /// needs to evaluate arbitrary linear combinations (not just single
    /// variables). This is unavoidable when LCs are multi-term (e.g. `3*x + 5*y`).
    pub(crate) fn multiply_lcs(
        &mut self,
        a: &LinearCombination<F>,
        b: &LinearCombination<F>,
    ) -> LinearCombination<F> {
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
    pub(crate) fn divide_lcs(
        &mut self,
        num: &LinearCombination<F>,
        den: &LinearCombination<F>,
    ) -> Result<LinearCombination<F>, R1CSError> {
        // Constant denominator → multiply by inverse (0 constraints)
        if let Some(scalar) = den.constant_value() {
            let inv = scalar
                .inv()
                .ok_or_else(|| R1CSError::UnsupportedOperation("division by zero".into(), None))?;
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
    pub(crate) fn enforce_n_range(&mut self, val: &LinearCombination<F>, num_bits: u32) {
        let mut sum = LinearCombination::zero();
        for i in 0..num_bits {
            let bit_var = self.cs.alloc_witness();
            self.cs.enforce(
                LinearCombination::from_variable(bit_var),
                LinearCombination::from_constant(FieldElement::<F>::one())
                    - LinearCombination::from_variable(bit_var),
                LinearCombination::zero(),
            );
            let coeff = power_of_two_generic::<F>(i);
            sum = sum + LinearCombination::from_variable(bit_var) * coeff;
            self.witness_ops.push(WitnessOp::BitExtract {
                target: bit_var,
                source: val.clone(),
                bit_index: i,
            });
        }
        self.cs.enforce_equal(val.clone(), sum);
    }

    /// Default range bit width: `modulus_bit_size - 2`.
    /// BN254 → 252, BLS12-381 → 253.
    pub(crate) fn default_range_bits(&self) -> u32 {
        self.prime_id.modulus_bit_size() - 2
    }

    /// Enforce that `val` fits in the default range for the active prime field.
    pub(crate) fn enforce_default_range(&mut self, val: &LinearCombination<F>) {
        let bits = self.default_range_bits();
        self.enforce_n_range(val, bits);
    }

    /// Compile an IsLt check via `num_bits`-bit decomposition.
    /// Input: an LC representing `diff = b - a + offset`.
    /// Returns an LC that is 1 if a < b, 0 otherwise (bit `num_bits - 1`).
    pub(crate) fn compile_is_lt_via_bits(
        &mut self,
        diff: &LinearCombination<F>,
        num_bits: u32,
    ) -> LinearCombination<F> {
        let mut sum = LinearCombination::zero();
        let mut top_bit_lc = LinearCombination::zero();
        let top_index = num_bits - 1;

        for i in 0..num_bits {
            let bit_var = self.cs.alloc_witness();
            // b_i * (1 - b_i) = 0
            self.cs.enforce(
                LinearCombination::from_variable(bit_var),
                LinearCombination::from_constant(FieldElement::<F>::one())
                    - LinearCombination::from_variable(bit_var),
                LinearCombination::zero(),
            );
            let coeff = power_of_two_generic::<F>(i);
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
}
