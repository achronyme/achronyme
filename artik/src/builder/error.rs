/// Errors that can arise from misuse of the builder API. All of them
/// indicate a bug in the lifting pass; none are expected on correct
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// A label was referenced by
    /// [`ProgramBuilder::jump_to`](crate::builder::ProgramBuilder::jump_to)
    /// or
    /// [`ProgramBuilder::jump_if_to`](crate::builder::ProgramBuilder::jump_if_to)
    /// but never had
    /// [`ProgramBuilder::place`](crate::builder::ProgramBuilder::place)
    /// called on it.
    UnplacedLabel(u32),
    /// A pending-jump slot resolved to an instruction that was not a
    /// Jump or JumpIf — indicates the builder's internal state was
    /// corrupted (should be unreachable).
    NonJumpAtPatchSite(u32),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnplacedLabel(id) => write!(f, "Artik builder label {id} was never placed"),
            Self::NonJumpAtPatchSite(idx) => {
                write!(f, "Artik builder patch site {idx} is not a jump")
            }
        }
    }
}

impl std::error::Error for BuilderError {}
