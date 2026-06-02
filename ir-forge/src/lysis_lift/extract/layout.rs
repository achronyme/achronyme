use std::collections::BTreeSet;

use rustc_hash::FxHashSet as HashSet;

use memory::FieldBackend;

use super::super::symbolic::{SlotId, SymbolicNode, SymbolicTree};
use super::error::{ExtractError, MAX_FRAME_SIZE};
use ir_core::SsaVar;

/// One entry in the capture list: either a probe slot (loop-var-
/// derived at call time) or an outer-scope `SsaVar` passed through
/// from the caller's frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind {
    Slot(SlotId),
    OuterRef(SsaVar),
}

/// Ordered list of captures a template expects. The i-th entry
/// corresponds to `LoadCapture i` in the template body.
///
/// Slots come first (one entry per [`SlotId`] in ascending order)
/// followed by unique [`OuterRef`] captures in first-appearance
/// order inside the skeleton.
#[derive(Debug, Clone, Default)]
pub struct CaptureLayout {
    pub entries: Vec<CaptureKind>,
}

impl CaptureLayout {
    /// Number of captures the template declares as `n_params`.
    pub fn n_params(&self) -> u8 {
        self.entries.len() as u8
    }

    /// Number of entries. Convenience alias.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when there are no captures at all (body is fully
    /// closed).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the capture index that a specific [`SlotId`] occupies,
    /// if it's part of the layout.
    pub fn slot_index(&self, sid: SlotId) -> Option<u8> {
        self.entries
            .iter()
            .position(|c| matches!(c, CaptureKind::Slot(s) if *s == sid))
            .map(|i| i as u8)
    }

    /// Find the capture index that a specific outer-ref [`SsaVar`]
    /// occupies, if it's part of the layout.
    pub fn outer_ref_index(&self, var: SsaVar) -> Option<u8> {
        self.entries
            .iter()
            .position(|c| matches!(c, CaptureKind::OuterRef(v) if *v == var))
            .map(|i| i as u8)
    }
}

/// Build the deterministic capture layout for a skeleton given the
/// set of slots BTA flagged as captures.
///
/// Scans the skeleton node pool once to collect unique `OuterRef`s
/// in first-appearance order.
pub fn build_capture_layout<F: FieldBackend>(
    skeleton: &SymbolicTree<F>,
    slot_captures: &BTreeSet<SlotId>,
) -> CaptureLayout {
    let mut entries: Vec<CaptureKind> = slot_captures
        .iter()
        .copied()
        .map(CaptureKind::Slot)
        .collect();
    let mut seen: HashSet<SsaVar> = HashSet::default();
    for node in &skeleton.nodes {
        if let SymbolicNode::OuterRef(v) = node {
            if seen.insert(*v) {
                entries.push(CaptureKind::OuterRef(*v));
            }
        }
    }
    CaptureLayout { entries }
}

/// Count how many registers the body needs under bump allocation.
///
/// Captures live in slots `r0..r{n_params-1}`. Every pool node that
/// produces a new value during emission bumps a fresh slot:
///
/// - Literal `Const`, `Input`, `Op`, and `TemplateCall` nodes
///   produce one register each (for this version — `TemplateCall`
///   multi-output wiring lives in the walker, which alloc'es more
///   regs outside this count).
/// - Slot-tagged `Const` nodes map to `LoadCapture i` — they
///   already occupy a capture slot, so they don't bump.
/// - `OuterRef` nodes likewise map to `LoadCapture i`.
/// - `NestedLoop` markers are sentinels, ignored.
pub fn compute_frame_size<F: FieldBackend>(
    skeleton: &SymbolicTree<F>,
    layout: &CaptureLayout,
) -> Result<u8, ExtractError> {
    let n_params = u32::from(layout.n_params());
    let producing = skeleton
        .nodes
        .iter()
        .filter(|n| {
            !matches!(
                n,
                SymbolicNode::Const {
                    from_slot: Some(_),
                    ..
                } | SymbolicNode::OuterRef(_)
                    | SymbolicNode::NestedLoop
            )
        })
        .count() as u32;
    let total = n_params + producing;
    if total > MAX_FRAME_SIZE {
        return Err(ExtractError::FrameOverflow { requested: total });
    }
    Ok(total as u8)
}
