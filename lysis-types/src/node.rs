//! `NodeId` — handle into the node table produced by [`crate::execute`].
//!
//! The handle shape is shared by both backends: the counter-based
//! `StubSink` and the hash-consing `InterningSink`. Downstream code
//! consumes `NodeId` without caring which sink minted it.

use std::num::NonZeroU64;

/// Opaque 64-bit handle for an emitted IR node.
///
/// `NonZeroU64` means `Option<NodeId>` is the same size as `NodeId`,
/// which we rely on in the register file (`Vec<Option<NodeId>>`).
/// Node 0 is reserved as a sentinel; real nodes start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(NonZeroU64);

impl NodeId {
    /// The minimum real `NodeId` — `1` one-based, index `0`. Useful
    /// as a placeholder when the real id is assigned elsewhere (e.g.,
    /// the `result` slot of a pure instruction handed to
    /// `IrSink::intern_pure`, which the sink overwrites).
    pub const PLACEHOLDER: Self = NodeId(match NonZeroU64::new(1) {
        Some(n) => n,
        None => unreachable!(),
    });

    /// Construct from a 1-based index. `NodeId::from_one_based(1)` is
    /// the first real node.
    #[inline]
    pub const fn from_one_based(idx: u64) -> Option<Self> {
        match NonZeroU64::new(idx) {
            Some(n) => Some(NodeId(n)),
            None => None,
        }
    }

    /// Construct from a 0-based index into a `Vec<InstructionKind>`.
    /// Maps `0 -> NodeId(1)`, `1 -> NodeId(2)`, etc.
    #[inline]
    pub fn from_zero_based(idx: usize) -> Self {
        let one_based = u64::try_from(idx)
            .expect("node index overflows u64")
            .checked_add(1)
            .expect("node index + 1 overflows u64");
        NodeId(NonZeroU64::new(one_based).expect("one-based idx is non-zero"))
    }

    /// Zero-based index into the emission `Vec`.
    #[inline]
    pub fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }

    /// One-based raw value (matches the `Display` formatting).
    #[inline]
    pub fn raw(self) -> u64 {
        self.0.get()
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "%{}", self.index())
    }
}

/// Simple zero-based counter used by `StubSink`. The hash-consing
/// `InterningSink` mints its own ids and ignores this generator.
#[derive(Debug, Default)]
pub struct NodeIdGen {
    next: u64,
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
    pub fn count(&self) -> u64 {
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

    // must stay in this file — accesses private `NodeIdGen.next`.
    #[test]
    fn fresh_node_id_advances_past_u32_max() {
        let mut g = NodeIdGen {
            next: (u32::MAX as u64) - 5,
        };
        for _ in 0..4 {
            let _ = g.fresh();
        }
        let id = g.fresh();
        assert_eq!(id.raw(), u32::MAX as u64);
        let past = g.fresh();
        assert_eq!(past.raw(), (u32::MAX as u64) + 1);
    }
}
