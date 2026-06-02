/// An SSA variable — defined exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaVar(pub u64);

/// Whether a circuit input is public (instance) or private (witness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Witness,
}

impl std::fmt::Display for SsaVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%{}", self.0)
    }
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Witness => write!(f, "witness"),
        }
    }
}
