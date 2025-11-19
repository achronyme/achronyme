//! Compilation context types

/// Loop context for break/continue
#[derive(Debug)]
pub(crate) struct LoopContext {
    /// Start of loop (for continue)
    pub(crate) start: usize,

    /// Break jump targets (to be patched)
    pub(crate) breaks: Vec<usize>,
}
