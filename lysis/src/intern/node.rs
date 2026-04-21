//! `NodeId` — handle into the node table produced by [`crate::execute`].
//!
//! Phase 1 uses a plain counter; Phase 2 replaces the counter with a
//! hash-consing interner. The handle shape does not change between
//! phases so downstream code can start consuming `NodeId` today.

use std::num::NonZeroU32;

/// Opaque 32-bit handle for an emitted IR node.
///
/// `NonZeroU32` means `Option<NodeId>` is the same size as `NodeId`,
/// which we rely on in the register file (`Vec<Option<NodeId>>`).
/// Node 0 is reserved as a sentinel; real nodes start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(NonZeroU32);

impl NodeId {
    /// The minimum real `NodeId` — `1` one-based, index `0`. Useful
    /// as a placeholder when the real id is assigned elsewhere (e.g.,
    /// the `result` slot of a pure instruction handed to
    /// `IrSink::intern_pure`, which the sink overwrites).
    pub const PLACEHOLDER: Self = NodeId(match NonZeroU32::new(1) {
        Some(n) => n,
        None => unreachable!(),
    });

    /// Construct from a 1-based index. `NodeId::from_one_based(1)` is
    /// the first real node.
    #[inline]
    pub const fn from_one_based(idx: u32) -> Option<Self> {
        match NonZeroU32::new(idx) {
            Some(n) => Some(NodeId(n)),
            None => None,
        }
    }

    /// Construct from a 0-based index into a `Vec<InstructionKind>`.
    /// Maps `0 -> NodeId(1)`, `1 -> NodeId(2)`, etc.
    #[inline]
    pub fn from_zero_based(idx: usize) -> Self {
        // Saturating +1 at u32::MAX is unreachable in practice — programs
        // that emit 4 billion nodes exhaust memory long before.
        let one_based = u32::try_from(idx)
            .expect("node index overflows u32")
            .checked_add(1)
            .expect("node index + 1 overflows u32");
        NodeId(NonZeroU32::new(one_based).expect("one-based idx is non-zero"))
    }

    /// Zero-based index into the emission `Vec`.
    #[inline]
    pub fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }

    /// One-based raw value (matches the `Display` formatting).
    #[inline]
    pub fn raw(self) -> u32 {
        self.0.get()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%{}", self.index())
    }
}

/// Simple zero-based counter used by Phase 1's stub sink. Replaced by
/// the hash-consing interner in Phase 2.
#[derive(Debug, Default)]
pub struct NodeIdGen {
    next: u32,
}

impl NodeIdGen {
    /// Reset to zero.
    pub fn reset(&mut self) {
        self.next = 0;
    }

    /// Produce the next fresh `NodeId`.
    pub fn fresh(&mut self) -> NodeId {
        let id = NodeId::from_zero_based(self.next as usize);
        self.next += 1;
        id
    }

    /// Number of ids already handed out.
    pub fn count(&self) -> u32 {
        self.next
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_based_matches_one_based() {
        let id = NodeId::from_zero_based(0);
        assert_eq!(id.index(), 0);
        assert_eq!(id.raw(), 1);
    }

    #[test]
    fn gen_starts_at_zero_and_increments() {
        let mut g = NodeIdGen::default();
        assert_eq!(g.fresh().index(), 0);
        assert_eq!(g.fresh().index(), 1);
        assert_eq!(g.fresh().index(), 2);
        assert_eq!(g.count(), 3);
    }

    #[test]
    fn option_node_id_is_pointer_sized() {
        assert_eq!(
            std::mem::size_of::<Option<NodeId>>(),
            std::mem::size_of::<NodeId>()
        );
    }

    #[test]
    fn display_uses_percent_notation() {
        let id = NodeId::from_zero_based(42);
        assert_eq!(format!("{id}"), "%42");
    }
}
