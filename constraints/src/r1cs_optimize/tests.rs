use crate::r1cs::{LinearCombination, Variable};
use memory::{FieldBackend, FieldElement};

/// Helper: build a constraint system, optimize it, and verify.
pub(crate) fn make_lc_var<F: FieldBackend>(var: Variable) -> LinearCombination<F> {
    LinearCombination::from_variable(var)
}

pub(crate) fn make_lc_const<F: FieldBackend>(val: u64) -> LinearCombination<F> {
    LinearCombination::from_constant(FieldElement::from_u64(val))
}

mod cluster_gauss;
mod cluster_partition;
mod edge_cases;
mod linear_basics;
mod sparse;
