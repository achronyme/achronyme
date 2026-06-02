use std::fmt;

use super::{CellRef, Column};

// ============================================================================

#[derive(Debug)]
pub enum PlonkishError {
    GateNotSatisfied {
        gate: String,
        row: usize,
    },
    CopyConstraintViolation {
        left: CellRef,
        right: CellRef,
    },
    LookupFailed {
        lookup: String,
        row: usize,
    },
    RotationOutOfBounds {
        column: Column,
        row: usize,
        rotation: i32,
        num_rows: usize,
    },
    MissingInput(String),
}

impl fmt::Display for PlonkishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlonkishError::GateNotSatisfied { gate, row } => {
                write!(f, "gate `{gate}` not satisfied at row {row}")
            }
            PlonkishError::CopyConstraintViolation { left, right } => {
                write!(
                    f,
                    "copy constraint violated: ({:?}, row {}) != ({:?}, row {})",
                    left.column, left.row, right.column, right.row
                )
            }
            PlonkishError::LookupFailed { lookup, row } => {
                write!(f, "lookup `{lookup}` failed at row {row}")
            }
            PlonkishError::RotationOutOfBounds {
                column,
                row,
                rotation,
                num_rows,
            } => {
                write!(
                    f,
                    "rotation out of bounds: column {:?}[{}] with rotation {} exceeds {} rows",
                    column, row, rotation, num_rows
                )
            }
            PlonkishError::MissingInput(name) => {
                write!(f, "missing input for variable `{name}`")
            }
        }
    }
}

impl std::error::Error for PlonkishError {}
