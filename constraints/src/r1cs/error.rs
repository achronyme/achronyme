use std::fmt;

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
