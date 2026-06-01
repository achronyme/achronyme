use super::Frame;

/// What the dispatcher does next in the outer loop.
pub(super) enum Step {
    Next,
    JumpToIndex(usize),
    PushFrame(Frame),
    /// Tail-call: the caller is in tail position (its only remaining
    /// instruction is `Return`) with no outputs to forward, so the
    /// callee *replaces* the caller frame instead of growing the
    /// stack. A linear template chain (the walker emits one
    /// `InstantiateTemplate(next); Return` per split) thus runs in
    /// O(1) frames instead of one frame per chain link.
    TailCall(Frame),
    PopFrame,
    Halt,
}
