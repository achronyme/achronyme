/// R1CS Constraint System for ZK Proofs
///
/// An R1CS (Rank-1 Constraint System) represents computation as a set of
/// constraints of the form: A * B = C, where A, B, C are linear combinations
/// of variables (wires).
///
/// Wire layout (snarkjs-compatible):
///   Index 0     = ONE (constant wire, always 1)
///   1..=n_pub   = public inputs (instance)
///   n_pub+1..   = private inputs + intermediate (witness)
mod error;
mod linear_combination;
mod system;

pub use error::ConstraintError;
pub use linear_combination::{LinearCombination, Variable};
pub use system::{Constraint, ConstraintSystem};

#[cfg(test)]
mod tests;
