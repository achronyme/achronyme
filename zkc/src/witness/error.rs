use std::fmt;

// ============================================================================
// WitnessError
// ============================================================================

/// Errors that can occur during witness generation.
#[derive(Debug)]
pub enum WitnessError {
    /// A required input variable was not provided.
    MissingInput(String),
    /// Division by zero encountered during witness computation.
    DivisionByZero { variable_index: usize },
    /// The embedded Artik witness program failed to decode, validate,
    /// or execute. `reason` is the stringified underlying error.
    ArtikCallFailed {
        /// First output wire, for locating the failure in bug reports.
        primary_output: usize,
        reason: String,
    },
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::MissingInput(name) => {
                write!(f, "missing input for variable `{name}`")
            }
            WitnessError::DivisionByZero { variable_index } => {
                write!(
                    f,
                    "division by zero computing witness variable {variable_index}"
                )
            }
            WitnessError::ArtikCallFailed {
                primary_output,
                reason,
            } => write!(
                f,
                "Artik witness call failed at wire {primary_output}: {reason}"
            ),
        }
    }
}

impl std::error::Error for WitnessError {}
