/// Witness builder for R1CS constraint systems.
///
/// Manages the assignment of values to circuit variables during
/// witness generation (the "prover" side of computation).

use memory::FieldElement;
use crate::r1cs::{ConstraintSystem, Variable};

/// Mutable witness vector builder.
pub struct WitnessBuilder {
    /// Values assigned to each variable. Index 0 = ONE.
    values: Vec<FieldElement>,
}

impl WitnessBuilder {
    /// Create a new witness builder sized for the given constraint system.
    pub fn new(cs: &ConstraintSystem) -> Self {
        let mut values = vec![FieldElement::ZERO; cs.num_variables()];
        values[0] = FieldElement::ONE; // Wire 0 = constant 1
        Self { values }
    }

    /// Set the value of a variable.
    pub fn set(&mut self, var: Variable, val: FieldElement) {
        self.values[var.index()] = val;
    }

    /// Get the value of a variable.
    pub fn get(&self, var: Variable) -> FieldElement {
        self.values[var.index()]
    }

    /// Consume and return the witness vector for verification.
    pub fn build(self) -> Vec<FieldElement> {
        self.values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{ConstraintSystem, LinearCombination};

    #[test]
    fn test_witness_builder_roundtrip() {
        // Circuit: a * b = c
        let mut cs = ConstraintSystem::new();
        let c = cs.alloc_input();
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();

        cs.enforce(
            LinearCombination::from_variable(a),
            LinearCombination::from_variable(b),
            LinearCombination::from_variable(c),
        );

        // Build witness
        let mut wb = WitnessBuilder::new(&cs);
        wb.set(a, FieldElement::from_u64(6));
        wb.set(b, FieldElement::from_u64(7));
        wb.set(c, FieldElement::from_u64(42));

        let witness = wb.build();
        assert!(cs.verify(&witness).is_ok());
    }
}
