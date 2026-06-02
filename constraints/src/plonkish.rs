/// Plonkish Constraint System
///
/// A Plonkish system represents computation using:
/// - **Arithmetic gates**: s_arith * (a * b + c - d) = 0
/// - **Lookup tables**: proving a value belongs to a precomputed table
/// - **Copy constraints**: enforcing equality between cells
///
/// This provides more efficient circuits than R1CS for many operations,
/// especially range checks (O(1) lookup vs O(bits) boolean decomposition).
mod assignments;
mod error;
mod expression;
mod system;
mod types;

#[cfg(test)]
mod tests;

pub use assignments::Assignments;
pub use error::PlonkishError;
pub use expression::Expression;
pub use system::PlonkishSystem;
pub use types::{CellRef, Column, ColumnKind, CopyConstraint, Gate, Lookup, LookupTable};
