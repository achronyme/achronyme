use std::fmt;

/// Broad category of constraint cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintCategory {
    /// Mul, Div
    Arithmetic,
    /// AssertEq, Assert
    Assertion,
    /// RangeCheck
    RangeCheck,
    /// PoseidonHash
    Hash,
    /// IsEq, IsNeq, IsLt, IsLe, IsLtBounded, IsLeBounded
    Comparison,
    /// And, Or, Not
    Boolean,
    /// Mux
    Selection,
}

impl fmt::Display for ConstraintCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arithmetic => write!(f, "Arithmetic"),
            Self::Assertion => write!(f, "Assertions"),
            Self::RangeCheck => write!(f, "Range checks"),
            Self::Hash => write!(f, "Hashes"),
            Self::Comparison => write!(f, "Comparisons"),
            Self::Boolean => write!(f, "Boolean ops"),
            Self::Selection => write!(f, "Selections"),
        }
    }
}

/// Display order priority (lower = shown first, i.e. highest priority).
impl ConstraintCategory {
    pub(super) fn display_order(self) -> u8 {
        match self {
            Self::Hash => 0,
            Self::Comparison => 1,
            Self::RangeCheck => 2,
            Self::Arithmetic => 3,
            Self::Assertion => 4,
            Self::Boolean => 5,
            Self::Selection => 6,
        }
    }
}
