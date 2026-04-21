//! Span-list policy for hash-consed nodes (RFC §5.5).
//!
//! A single interned `NodeId` often represents code that appeared in
//! many source locations — the 64 round bodies of SHA-256 collapse
//! to a handful of distinct nodes, each pointing back at dozens of
//! source-line ranges. The `SpanList` carries that many-to-one
//! relation so diagnostics ("this constraint, seen at lines X, Y, Z")
//! stay faithful to the un-deduplicated program.
//!
//! ## Cap
//!
//! Keeping every span forever would let pathological circuits grow
//! a node's span list into the millions — a megabyte per node on
//! a circuit with enough duplication. The cap is **16**: once the
//! list hits 16, further pushes increment `overflow_count` but
//! discard the span itself. Diagnostics can still say "and N more
//! sources" without holding the concrete ranges.
//!
//! 16 is a heuristic pick: empirically, a SHA-256(64) round body
//! has ~400 duplicated sub-nodes, and 16 is enough to show the
//! first few occurrences (which are usually the most informative
//! for "where did this first get introduced") while capping memory
//! at `16 × 8 bytes + counter = 136 bytes` per spanned node.

use smallvec::SmallVec;

/// Byte-offset range in a source program. `start` inclusive, `end`
/// exclusive. `UNKNOWN` is a placeholder used when the emitter has
/// not yet been wired to a source location (Phase 1-2 executor
/// emits everything with `UNKNOWN`; Phase 3 frontend fills real
/// spans as it lowers ProveIR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanRange {
    pub start: u32,
    pub end: u32,
}

impl SpanRange {
    /// Sentinel used while the executor does not carry source
    /// positions. Distinguishable from any real range because
    /// `start > end` (empty + inverted).
    pub const UNKNOWN: Self = SpanRange {
        start: u32::MAX,
        end: 0,
    };

    #[inline]
    pub fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }

    /// `true` if this is the placeholder sentinel.
    #[inline]
    pub fn is_unknown(self) -> bool {
        self == Self::UNKNOWN
    }
}

/// Maximum number of concrete spans retained per node before
/// [`SpanList::push_capped`] starts counting overflow instead of
/// storing.
pub const SPAN_LIST_CAP: usize = 16;

/// Inline-1 vector of spans for a single interned node. The first
/// span is stored inline (no heap alloc); subsequent spans spill
/// into a heap-allocated buffer; past [`SPAN_LIST_CAP`] they only
/// bump `overflow_count`.
#[derive(Debug, Clone, Default)]
pub struct SpanList {
    spans: SmallVec<[SpanRange; 1]>,
    overflow_count: u32,
}

impl SpanList {
    /// Empty list. No allocations until first push.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from a single initial span.
    #[inline]
    pub fn with_span(span: SpanRange) -> Self {
        let mut v = SmallVec::new();
        v.push(span);
        Self {
            spans: v,
            overflow_count: 0,
        }
    }

    /// Append `span` unless the list is already at the cap, in
    /// which case bump `overflow_count`. `UNKNOWN` spans do **not**
    /// accumulate — if the only span seen so far is `UNKNOWN` and
    /// a real one arrives, the real one replaces it; otherwise
    /// `UNKNOWN` is ignored after the first one. This keeps the
    /// list useful when the executor starts adding spans later.
    pub fn push_capped(&mut self, span: SpanRange) {
        if span.is_unknown() {
            // Don't let repeated UNKNOWN spans fill the budget.
            if self.spans.is_empty() {
                self.spans.push(span);
            }
            return;
        }
        // Replace a lone UNKNOWN with the first real span.
        if self.spans.len() == 1 && self.spans[0].is_unknown() {
            self.spans[0] = span;
            return;
        }
        if self.spans.len() >= SPAN_LIST_CAP {
            self.overflow_count = self.overflow_count.saturating_add(1);
        } else {
            self.spans.push(span);
        }
    }

    /// Retained spans in insertion order.
    #[inline]
    pub fn spans(&self) -> &[SpanRange] {
        &self.spans
    }

    /// Number of pushes that were dropped because the cap was hit.
    #[inline]
    pub fn overflow_count(&self) -> u32 {
        self.overflow_count
    }

    /// Total spans seen (retained + dropped).
    #[inline]
    pub fn total_seen(&self) -> u32 {
        self.spans.len() as u32 + self.overflow_count
    }

    /// `true` if nothing has been pushed yet.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(start: u32, end: u32) -> SpanRange {
        SpanRange::new(start, end)
    }

    #[test]
    fn unknown_is_recognizable() {
        assert!(SpanRange::UNKNOWN.is_unknown());
        assert!(!s(0, 10).is_unknown());
    }

    #[test]
    fn first_real_span_stored_inline() {
        let mut list = SpanList::new();
        list.push_capped(s(0, 5));
        assert_eq!(list.spans().len(), 1);
        assert_eq!(list.overflow_count(), 0);
    }

    #[test]
    fn fifteen_pushes_all_retained() {
        let mut list = SpanList::new();
        for i in 0..15 {
            list.push_capped(s(i, i + 1));
        }
        assert_eq!(list.spans().len(), 15);
        assert_eq!(list.overflow_count(), 0);
    }

    #[test]
    fn exactly_sixteen_retains_all_no_overflow() {
        let mut list = SpanList::new();
        for i in 0..SPAN_LIST_CAP as u32 {
            list.push_capped(s(i, i + 1));
        }
        assert_eq!(list.spans().len(), SPAN_LIST_CAP);
        assert_eq!(list.overflow_count(), 0);
    }

    #[test]
    fn over_cap_increments_overflow() {
        let mut list = SpanList::new();
        for i in 0..20u32 {
            list.push_capped(s(i, i + 1));
        }
        assert_eq!(list.spans().len(), SPAN_LIST_CAP);
        assert_eq!(list.overflow_count(), 4);
        assert_eq!(list.total_seen(), 20);
    }

    #[test]
    fn unknown_does_not_accumulate() {
        let mut list = SpanList::new();
        for _ in 0..10 {
            list.push_capped(SpanRange::UNKNOWN);
        }
        assert_eq!(list.spans().len(), 1);
        assert!(list.spans()[0].is_unknown());
    }

    #[test]
    fn real_span_replaces_lone_unknown() {
        let mut list = SpanList::new();
        list.push_capped(SpanRange::UNKNOWN);
        list.push_capped(s(5, 10));
        assert_eq!(list.spans().len(), 1);
        assert_eq!(list.spans()[0], s(5, 10));
    }

    #[test]
    fn real_span_appends_after_other_real_spans() {
        let mut list = SpanList::new();
        list.push_capped(s(0, 5));
        list.push_capped(s(10, 15));
        assert_eq!(list.spans(), &[s(0, 5), s(10, 15)]);
    }

    #[test]
    fn unknown_after_real_is_ignored() {
        let mut list = SpanList::new();
        list.push_capped(s(0, 5));
        list.push_capped(SpanRange::UNKNOWN);
        assert_eq!(list.spans(), &[s(0, 5)]);
    }

    #[test]
    fn with_span_populates_initial() {
        let list = SpanList::with_span(s(42, 43));
        assert_eq!(list.spans(), &[s(42, 43)]);
    }

    #[test]
    fn empty_list_reports_empty() {
        let list = SpanList::new();
        assert!(list.is_empty());
        assert_eq!(list.total_seen(), 0);
    }
}
