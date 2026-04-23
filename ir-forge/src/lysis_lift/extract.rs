//! Template extraction (lambda-lifting) — RFC §6.2.
//!
//! Takes a [`SymbolicTree`] that BTA classified as
//! [`BindingTime::Uniform`] and produces a [`TemplateSpec`] the
//! walker can emit as `DefineTemplate` bytecode plus one
//! `InstantiateTemplate` (or `LoopRolled`) per call site.
//!
//! ## What this module does now
//!
//! - Resolves the **capture layout**: slot captures (from probe
//!   bindings) come first, followed by unique `OuterRef` captures
//!   in first-appearance order. Both share the single `u8`
//!   `LoadCapture` index space that the bytecode uses.
//! - Computes a **conservative `frame_size`** by counting the nodes
//!   that will occupy a register during emission. Captures live in
//!   `r0..r{n_params-1}`; everything else bumps a fresh slot.
//! - Allocates fresh [`TemplateId`]s via a
//!   [`TemplateRegistry`] that also stores the skeleton for the
//!   walker's later bytecode-emission pass.
//!
//! ## What lives in a later iteration
//!
//! - **Canonical bytecode hash-based dedup**: RFC §6.2 mentions
//!   deduplicating two templates whose emitted bytecode is byte-
//!   identical. Phase 3 allocates a fresh id for every extraction
//!   instead; Phase 4 will hash the emitted bytecode and merge
//!   matches. This is a size-not-correctness optimization — a pair
//!   of redundant templates just costs extra metadata, they don't
//!   produce wrong constraints.
//! - **True liveness-based frame sizing**: we over-allocate today
//!   (one slot per producing node). Phase 4 does linear-scan
//!   liveness.

use std::collections::{BTreeSet, HashMap, HashSet};

use memory::FieldBackend;

use super::symbolic::{SlotId, SymbolicNode, SymbolicTree};
use crate::TemplateId;
use ir_core::SsaVar;

/// Maximum legal frame size — matches
/// [`lysis::lower::MAX_FRAME_SIZE`]. Restated here to keep this
/// module reasoning directly about the bound without importing
/// `lysis` just for one constant.
pub const MAX_FRAME_SIZE: u32 = 255;

/// Errors raised during template extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractError {
    /// The proposed template needs more registers than `u8` can
    /// address.
    FrameOverflow { requested: u32 },
    /// The template id space is exhausted (more than `u16::MAX`
    /// distinct templates in one program). Unreachable in practice.
    TemplateSpaceExhausted,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameOverflow { requested } => write!(
                f,
                "template needs {requested} registers, max {MAX_FRAME_SIZE}"
            ),
            Self::TemplateSpaceExhausted => {
                f.write_str("template id space exhausted (> 65535 distinct templates)")
            }
        }
    }
}

impl std::error::Error for ExtractError {}

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
    let mut seen: HashSet<SsaVar> = HashSet::new();
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

/// Metadata for one registered template. The walker later walks the
/// `skeleton` to emit the actual bytecode body when assembling the
/// final `Program`.
#[derive(Debug, Clone)]
pub struct TemplateSpec<F: FieldBackend> {
    pub id: TemplateId,
    pub frame_size: u8,
    pub layout: CaptureLayout,
    pub skeleton: SymbolicTree<F>,
}

impl<F: FieldBackend> TemplateSpec<F> {
    pub fn n_params(&self) -> u8 {
        self.layout.n_params()
    }
}

/// Registry that hands out fresh [`TemplateId`]s and stores the
/// skeleton + metadata for each.
///
/// Phase 3 has no structural dedup — every `extract_template` call
/// allocates a fresh id. Phase 4 will add canonical-bytecode dedup
/// as an optimization (see module docs).
#[derive(Debug, Clone)]
pub struct TemplateRegistry<F: FieldBackend> {
    specs: HashMap<TemplateId, TemplateSpec<F>>,
    next_id: u32,
}

impl<F: FieldBackend> Default for TemplateRegistry<F> {
    fn default() -> Self {
        Self {
            specs: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<F: FieldBackend> TemplateRegistry<F> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of templates registered so far.
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// `true` when nothing has been registered.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Look up a registered template by id.
    pub fn get(&self, id: TemplateId) -> Option<&TemplateSpec<F>> {
        self.specs.get(&id)
    }

    /// Iterate templates in id order. Deterministic: the walker uses
    /// this to emit `DefineTemplate` in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = (&TemplateId, &TemplateSpec<F>)> {
        let mut pairs: Vec<_> = self.specs.iter().collect();
        pairs.sort_by_key(|(id, _)| id.0);
        pairs.into_iter()
    }

    fn allocate_fresh(&mut self) -> Result<TemplateId, ExtractError> {
        if self.next_id > u32::from(u16::MAX) {
            return Err(ExtractError::TemplateSpaceExhausted);
        }
        let id = TemplateId(self.next_id as u16);
        self.next_id += 1;
        Ok(id)
    }
}

/// Register a new template from a BTA-classified uniform skeleton.
///
/// Returns the allocated [`TemplateSpec`]; the registry retains a
/// copy keyed by `id`.
pub fn extract_template<F: FieldBackend>(
    skeleton: &SymbolicTree<F>,
    slot_captures: &BTreeSet<SlotId>,
    registry: &mut TemplateRegistry<F>,
) -> Result<TemplateSpec<F>, ExtractError> {
    let layout = build_capture_layout(skeleton, slot_captures);
    let frame_size = compute_frame_size(skeleton, &layout)?;
    let id = registry.allocate_fresh()?;
    let spec = TemplateSpec {
        id,
        frame_size,
        layout,
        skeleton: skeleton.clone(),
    };
    registry.specs.insert(id, spec.clone());
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::lysis_lift::bta::{classify, BindingTime};
    use crate::ExtendedInstruction;
    use ir_core::Instruction;

    fn fe(n: i64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n as u64, 0, 0, 0])
    }

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    // -----------------------------------------------------------------
    // CaptureLayout
    // -----------------------------------------------------------------

    #[test]
    fn capture_layout_empty_when_tree_empty() {
        let t = SymbolicTree::<Bn254Fr>::new();
        let captures = BTreeSet::new();
        let layout = build_capture_layout(&t, &captures);
        assert!(layout.is_empty());
        assert_eq!(layout.n_params(), 0);
    }

    #[test]
    fn capture_layout_orders_slots_then_outer_refs() {
        // Skeleton with mixed slot consts + outer refs.
        let mut t = SymbolicTree::<Bn254Fr>::new();
        t.push(SymbolicNode::Const {
            value: fe(0),
            from_slot: Some(SlotId(0)),
        });
        t.push(SymbolicNode::OuterRef(ssa(50)));
        t.push(SymbolicNode::OuterRef(ssa(40)));
        t.push(SymbolicNode::OuterRef(ssa(50))); // dup
        t.n_slots = 1;

        let mut caps = BTreeSet::new();
        caps.insert(SlotId(0));

        let layout = build_capture_layout(&t, &caps);
        assert_eq!(layout.entries.len(), 3);
        assert!(matches!(layout.entries[0], CaptureKind::Slot(SlotId(0))));
        assert!(matches!(layout.entries[1], CaptureKind::OuterRef(v) if v == ssa(50)));
        assert!(matches!(layout.entries[2], CaptureKind::OuterRef(v) if v == ssa(40)));
    }

    #[test]
    fn capture_layout_is_deterministic() {
        let mut t = SymbolicTree::<Bn254Fr>::new();
        t.push(SymbolicNode::OuterRef(ssa(99)));
        t.push(SymbolicNode::OuterRef(ssa(88)));

        let caps = BTreeSet::new();
        let l1 = build_capture_layout(&t, &caps);
        let l2 = build_capture_layout(&t, &caps);
        assert_eq!(l1.entries.len(), l2.entries.len());
        for (a, b) in l1.entries.iter().zip(l2.entries.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn slot_index_and_outer_ref_index_lookups() {
        let mut t = SymbolicTree::<Bn254Fr>::new();
        t.push(SymbolicNode::Const {
            value: fe(0),
            from_slot: Some(SlotId(2)),
        });
        t.push(SymbolicNode::OuterRef(ssa(7)));
        t.n_slots = 1;
        let mut caps = BTreeSet::new();
        caps.insert(SlotId(2));

        let layout = build_capture_layout(&t, &caps);
        assert_eq!(layout.slot_index(SlotId(2)), Some(0));
        assert_eq!(layout.slot_index(SlotId(99)), None);
        assert_eq!(layout.outer_ref_index(ssa(7)), Some(1));
        assert_eq!(layout.outer_ref_index(ssa(99)), None);
    }

    // -----------------------------------------------------------------
    // compute_frame_size
    // -----------------------------------------------------------------

    #[test]
    fn frame_size_empty_tree_equals_n_params() {
        let t = SymbolicTree::<Bn254Fr>::new();
        let layout = CaptureLayout::default();
        assert_eq!(compute_frame_size(&t, &layout).unwrap(), 0);
    }

    #[test]
    fn frame_size_excludes_slot_and_outer_ref() {
        let mut t = SymbolicTree::<Bn254Fr>::new();
        t.push(SymbolicNode::Const {
            value: fe(0),
            from_slot: Some(SlotId(0)),
        });
        t.push(SymbolicNode::OuterRef(ssa(10)));
        t.push(SymbolicNode::Const {
            value: fe(5),
            from_slot: None,
        }); // literal — counts
        t.n_slots = 1;

        let mut caps = BTreeSet::new();
        caps.insert(SlotId(0));
        let layout = build_capture_layout(&t, &caps);

        // n_params = 1 slot + 1 outer = 2; producing = 1 literal.
        assert_eq!(layout.n_params(), 2);
        assert_eq!(compute_frame_size(&t, &layout).unwrap(), 3);
    }

    #[test]
    fn frame_size_overflow_rejected() {
        let mut t = SymbolicTree::<Bn254Fr>::new();
        for _ in 0..256 {
            t.push(SymbolicNode::Const {
                value: fe(0),
                from_slot: None,
            });
        }
        let layout = CaptureLayout::default();
        assert!(matches!(
            compute_frame_size(&t, &layout),
            Err(ExtractError::FrameOverflow { .. })
        ));
    }

    #[test]
    fn nested_loop_marker_is_not_counted() {
        let mut t = SymbolicTree::<Bn254Fr>::new();
        t.push(SymbolicNode::NestedLoop);
        let layout = CaptureLayout::default();
        assert_eq!(compute_frame_size(&t, &layout).unwrap(), 0);
    }

    // -----------------------------------------------------------------
    // TemplateRegistry
    // -----------------------------------------------------------------

    #[test]
    fn registry_allocates_unique_ids() {
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let a = reg.allocate_fresh().unwrap();
        let b = reg.allocate_fresh().unwrap();
        let c = reg.allocate_fresh().unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(a.0, 0);
        assert_eq!(b.0, 1);
        assert_eq!(c.0, 2);
    }

    #[test]
    fn registry_iter_is_sorted_by_id() {
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let skel = SymbolicTree::<Bn254Fr>::new();
        let caps = BTreeSet::new();
        let a = extract_template(&skel, &caps, &mut reg).unwrap();
        let b = extract_template(&skel, &caps, &mut reg).unwrap();
        let c = extract_template(&skel, &caps, &mut reg).unwrap();
        let ids: Vec<_> = reg.iter().map(|(id, _)| id.0).collect();
        assert_eq!(ids, vec![a.id.0, b.id.0, c.id.0]);
    }

    // -----------------------------------------------------------------
    // extract_template — end-to-end from BTA output
    // -----------------------------------------------------------------

    #[test]
    fn extract_produces_spec_matching_layout() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()];
        let c = classify(ssa(0), &body, 0, 5, fe);
        let (skeleton, captures) = match c.binding_time {
            BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
            BindingTime::DataDependent => panic!("expected Uniform"),
        };
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let spec = extract_template(&skeleton, &captures, &mut reg).unwrap();

        assert_eq!(spec.n_params(), 1);
        assert_eq!(spec.layout.entries[0], CaptureKind::Slot(SlotId(0)));
        // Body tree: slot Const + Op(Mul). frame_size = 1 (n_params) + 1 (Op producing) = 2.
        assert_eq!(spec.frame_size, 2);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn extract_preserves_skeleton() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Add {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(99), // outer ref
        }
        .into()];
        let c = classify(ssa(0), &body, 0, 3, fe);
        let (skeleton, captures) = match c.binding_time {
            BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
            _ => panic!(),
        };
        let orig_len = skeleton.nodes.len();
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let spec = extract_template(&skeleton, &captures, &mut reg).unwrap();
        assert_eq!(spec.skeleton.nodes.len(), orig_len);

        // Layout: slot 0 first, then outer ref ssa(99).
        assert_eq!(spec.n_params(), 2);
        assert!(matches!(
            spec.layout.entries[0],
            CaptureKind::Slot(SlotId(0))
        ));
        assert!(matches!(spec.layout.entries[1], CaptureKind::OuterRef(v) if v == ssa(99)));
    }

    #[test]
    fn two_independent_extractions_get_different_ids() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()];
        let c1 = classify(ssa(0), &body, 0, 5, fe);
        let c2 = classify(ssa(0), &body, 0, 5, fe);
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let (s1, k1) = match c1.binding_time {
            BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
            _ => panic!(),
        };
        let (s2, k2) = match c2.binding_time {
            BindingTime::Uniform { skeleton, captures } => (skeleton, captures),
            _ => panic!(),
        };
        let a = extract_template(&s1, &k1, &mut reg).unwrap();
        let b = extract_template(&s2, &k2, &mut reg).unwrap();
        // Phase 3 doesn't dedup — even identical bodies get distinct ids.
        assert_ne!(a.id, b.id);
        assert_eq!(reg.len(), 2);
    }
}
