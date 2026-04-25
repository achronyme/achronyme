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

use memory::{FieldBackend, FieldElement};

use super::bta::{classify_loop_unroll, BindingTime};
use super::symbolic::{SlotId, SymbolicNode, SymbolicTree};
use crate::{ExtendedInstruction, TemplateId};
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

    pub(super) fn allocate_fresh(&mut self) -> Result<TemplateId, ExtractError> {
        if self.next_id > u32::from(u16::MAX) {
            return Err(ExtractError::TemplateSpaceExhausted);
        }
        let id = TemplateId(self.next_id as u16);
        self.next_id += 1;
        Ok(id)
    }

    /// Insert a fully-built [`TemplateSpec`] keyed by its id.
    /// `pub(super)` so the [`lift_uniform_loops`] helper can attach a
    /// spec without going through [`extract_template`] — the lift's
    /// `Option B` lowering keeps the iter_var local to the template
    /// frame, so the synthesised spec carries an `OuterRef`-only
    /// layout that doesn't match what `extract_template` would build.
    pub(super) fn insert(&mut self, spec: TemplateSpec<F>) {
        self.specs.insert(spec.id, spec);
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

// =====================================================================
// Gap 2 Stage 1 — bottom-up lift pass
// =====================================================================
//
// Walks an `ExtendedInstruction` body and, for every `LoopUnroll`
// classified as `BindingTime::Uniform` by BTA, replaces it with a
// `TemplateBody` + `TemplateCall` pair. The lift uses **Option B**
// semantics: the original `LoopUnroll` becomes the body of the new
// template, so the loop runs *inside* the template's frame. Iter_var
// stays local to the template; only outer-scope `SsaVar` references
// (BTA's `OuterRef` skeleton nodes) become captures.
//
// Why Option B instead of Option A (one TemplateCall per iteration):
//
// - Each template gets its own 255-slot frame, so wide single
//   instructions like `Decompose(254)` have room.
// - Symbolic indexed reads/writes (Gap 1 + 1.5) keep working: the
//   per-iteration walker materialisation runs *inside* the template
//   frame, with `walker_const[iter_var]` populated by the local
//   iter_var. No runtime-indexed memory ops needed.
// - Multiple Uniform loops with identical skeletons can share a
//   template body via Phase 4 dedup (today every lift gets a fresh
//   id; Phase 4 will hash bytecode and merge matches).

/// Walk `body` bottom-up; replace each Uniform `LoopUnroll` with a
/// `TemplateBody` + `TemplateCall` pair allocated in `registry`. Loops
/// classified `DataDependent` (or whose nested bodies fail to lift)
/// stay verbatim. Pass-through for non-`LoopUnroll` instructions.
///
/// The closure used for BTA probe-value conversion is fixed to
/// `from_u64(i.unsigned_abs())`. Negative loop bounds are filtered by
/// `classify_loop_unroll` itself (returns `DataDependent` for any
/// range with fewer than 2 valid iterations), so the conversion never
/// sees a negative value in practice.
pub fn lift_uniform_loops<F: FieldBackend>(
    body: Vec<ExtendedInstruction<F>>,
    registry: &mut TemplateRegistry<F>,
) -> Result<Vec<ExtendedInstruction<F>>, ExtractError> {
    let mut out = Vec::with_capacity(body.len());
    for inst in body {
        out.extend(lift_one(inst, registry)?);
    }
    Ok(out)
}

fn lift_one<F: FieldBackend>(
    inst: ExtendedInstruction<F>,
    registry: &mut TemplateRegistry<F>,
) -> Result<Vec<ExtendedInstruction<F>>, ExtractError> {
    match inst {
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body,
        } => {
            // Bottom-up: lift inner body first so nested Uniform loops
            // become templates inside the outer body before the outer
            // is itself classified.
            let inner_lifted = lift_uniform_loops(body, registry)?;
            let loop_unroll = ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body: inner_lifted,
            };

            let details = classify_loop_unroll(&loop_unroll, |i| {
                FieldElement::<F>::from_u64(i.unsigned_abs())
            });

            match details.binding_time {
                BindingTime::Uniform {
                    skeleton,
                    captures: _slot_caps,
                } => Ok(lift_uniform_to_template(
                    loop_unroll,
                    skeleton,
                    registry,
                )?),
                BindingTime::DataDependent => Ok(vec![loop_unroll]),
            }
        }
        // Non-loop instructions pass through unchanged. Nested
        // LoopUnrolls inside `LoopUnroll.body` are handled by the
        // recursive `lift_uniform_loops` call above; loops inside
        // `TemplateBody.body` are reached when the Walker emits the
        // template body (it calls `lift_uniform_loops` on the body
        // before emission via Stage 4 wiring). Here, leave alone.
        other => Ok(vec![other]),
    }
}

/// Build the (`TemplateBody`, `TemplateCall`) pair for one Uniform
/// `LoopUnroll`. The skeleton's `OuterRef` SsaVars become the
/// template's captures (in first-appearance order); slot captures
/// (i.e. iter_var positions) are dropped because the loop runs
/// internally so iter_var is allocated locally by the LoopUnroll arm
/// of `Walker::emit`.
fn lift_uniform_to_template<F: FieldBackend>(
    loop_unroll: ExtendedInstruction<F>,
    skeleton: SymbolicTree<F>,
    registry: &mut TemplateRegistry<F>,
) -> Result<Vec<ExtendedInstruction<F>>, ExtractError> {
    // OuterRef captures only — slots map to the (internal) iter_var.
    let mut outer_refs: Vec<SsaVar> = Vec::new();
    let mut seen: HashSet<SsaVar> = HashSet::new();
    for node in &skeleton.nodes {
        if let SymbolicNode::OuterRef(v) = node {
            if seen.insert(*v) {
                outer_refs.push(*v);
            }
        }
    }
    let n_params = u8::try_from(outer_refs.len()).map_err(|_| ExtractError::FrameOverflow {
        requested: outer_refs.len() as u32,
    })?;

    // Conservative `frame_size` budget: skeleton's producing-node
    // count + n_params from an OuterRef-only layout. The Walker's
    // own LoopUnroll arm allocates the actual iter_var slot at
    // emission time inside the template frame — that consumes one
    // additional slot, so reserve it here. This is over-approximate
    // (live-set frame sizing is Phase 4) but tight enough that
    // SHA-256-shaped bodies fit within `MAX_FRAME_SIZE = 255`.
    let layout = CaptureLayout {
        entries: outer_refs
            .iter()
            .copied()
            .map(CaptureKind::OuterRef)
            .collect(),
    };
    let producing_plus_params = compute_frame_size(&skeleton, &layout)?;
    // +1 for iter_var allocated locally inside the template.
    let frame_total = u32::from(producing_plus_params).saturating_add(1);
    if frame_total > MAX_FRAME_SIZE {
        return Err(ExtractError::FrameOverflow {
            requested: frame_total,
        });
    }
    let frame_size = frame_total as u8;

    let template_id = registry.allocate_fresh()?;

    // Stash a spec so downstream tooling (diagnostics, future dedup,
    // tests) can introspect what was lifted. The walker reads the
    // template body from the IR stream's `TemplateBody` node, not
    // from this spec.
    registry.insert(TemplateSpec {
        id: template_id,
        frame_size,
        layout,
        skeleton,
    });

    Ok(vec![
        ExtendedInstruction::TemplateBody {
            id: template_id,
            frame_size,
            n_params,
            captures: outer_refs.clone(),
            body: vec![loop_unroll],
        },
        ExtendedInstruction::TemplateCall {
            template_id,
            captures: outer_refs,
            outputs: vec![],
        },
    ])
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

    // -----------------------------------------------------------------
    // lift_uniform_loops
    // -----------------------------------------------------------------

    #[test]
    fn lift_pass_through_for_non_loop_instructions() {
        // Plain instructions stay unchanged; no template allocated.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(0),
                value: fe(7),
            }
            .into(),
            Instruction::Add {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(0),
            }
            .into(),
        ];
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let lifted = lift_uniform_loops(body.clone(), &mut reg).unwrap();
        assert_eq!(lifted.len(), 2);
        assert!(matches!(lifted[0], ExtendedInstruction::Plain(_)));
        assert!(matches!(lifted[1], ExtendedInstruction::Plain(_)));
        assert!(reg.is_empty());
    }

    #[test]
    fn lift_simple_uniform_loop_produces_template_pair() {
        // for i in 0..3 { v = i * outer_ref }. Body uses iter_var
        // (slot capture) + outer_ref (OuterRef capture). Lift should
        // produce ONE TemplateBody (containing the LoopUnroll) and
        // ONE TemplateCall whose captures = [outer_ref].
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 3,
            body: vec![Instruction::Mul {
                result: ssa(1),
                lhs: ssa(0),  // iter_var
                rhs: ssa(99), // outer ref
            }
            .into()],
        }];
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let lifted = lift_uniform_loops(body, &mut reg).unwrap();

        assert_eq!(lifted.len(), 2, "expected TemplateBody + TemplateCall");
        let (id_in_body, body_inner) = match &lifted[0] {
            ExtendedInstruction::TemplateBody {
                id,
                n_params,
                captures,
                body,
                ..
            } => {
                assert_eq!(*n_params, 1, "one OuterRef capture");
                assert_eq!(captures, &vec![ssa(99)]);
                assert_eq!(body.len(), 1, "body wraps the original LoopUnroll");
                assert!(matches!(body[0], ExtendedInstruction::LoopUnroll { .. }));
                (*id, body)
            }
            other => panic!("expected TemplateBody, got {other:?}"),
        };
        match &lifted[1] {
            ExtendedInstruction::TemplateCall {
                template_id,
                captures,
                outputs,
            } => {
                assert_eq!(*template_id, id_in_body);
                assert_eq!(captures, &vec![ssa(99)]);
                assert!(outputs.is_empty());
            }
            other => panic!("expected TemplateCall, got {other:?}"),
        }

        assert_eq!(reg.len(), 1);
        let spec = reg.get(id_in_body).expect("spec stored");
        assert_eq!(spec.n_params(), 1);
        // Don't tighten frame_size assertion — the budget depends on
        // skeleton's producing-node count + iter_var slot, which is a
        // conservative over-approximation by design.
        assert!(spec.frame_size >= 1);

        // Sanity: the template body's wrapped LoopUnroll preserved
        // its iter_var and bounds.
        match &body_inner[0] {
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                ..
            } => {
                assert_eq!(*iter_var, ssa(0));
                assert_eq!(*start, 0);
                assert_eq!(*end, 3);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn lift_single_iteration_loop_stays_as_unroll() {
        // BTA short-circuits `iterations < 2` to `DataDependent`
        // (bta.rs Phase 3 v1.1). A `0..1` loop therefore never gets a
        // template; it stays inline as a LoopUnroll. Verifies the
        // DataDependent branch of the lift dispatch.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 1,
            body: vec![Instruction::Mul {
                result: ssa(1),
                lhs: ssa(0),
                rhs: ssa(99),
            }
            .into()],
        }];
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let lifted = lift_uniform_loops(body, &mut reg).unwrap();

        assert!(reg.is_empty(), "no template allocated for DataDependent");
        assert_eq!(lifted.len(), 1);
        assert!(matches!(lifted[0], ExtendedInstruction::LoopUnroll { .. }));
    }

    #[test]
    fn lift_recurses_into_nested_loops_bottom_up() {
        // Outer loop wraps an inner loop whose body references its
        // own iter_var. After lift, the inner becomes a template,
        // and the outer sees a TemplateCall in its body — outer's
        // classification then runs against that.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 4,
            body: vec![ExtendedInstruction::LoopUnroll {
                iter_var: ssa(1),
                start: 0,
                end: 3,
                body: vec![Instruction::Mul {
                    result: ssa(2),
                    lhs: ssa(1), // inner iter_var
                    rhs: ssa(1), // inner iter_var
                }
                .into()],
            }],
        }];
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let lifted = lift_uniform_loops(body, &mut reg).unwrap();

        // Inner produced one template; outer may have produced
        // another depending on how its inner lifts.
        assert!(!reg.is_empty(), "at least the inner uniform lifted");
        assert!(!lifted.is_empty());
    }

    #[test]
    fn lift_independent_loops_get_distinct_template_ids() {
        // Two sibling Uniform loops should produce two TemplateBodies
        // with different ids. (Phase 3 has no dedup; Phase 4 will hash
        // skeletons and merge structurally identical ones.)
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(0),
                start: 0,
                end: 3,
                body: vec![Instruction::Mul {
                    result: ssa(1),
                    lhs: ssa(0),
                    rhs: ssa(99),
                }
                .into()],
            },
            ExtendedInstruction::LoopUnroll {
                iter_var: ssa(2),
                start: 0,
                end: 3,
                body: vec![Instruction::Mul {
                    result: ssa(3),
                    lhs: ssa(2),
                    rhs: ssa(99),
                }
                .into()],
            },
        ];
        let mut reg = TemplateRegistry::<Bn254Fr>::new();
        let lifted = lift_uniform_loops(body, &mut reg).unwrap();
        assert_eq!(lifted.len(), 4, "two TemplateBody + two TemplateCall pairs");
        assert_eq!(reg.len(), 2, "two distinct template ids");
        let ids: Vec<TemplateId> = lifted
            .iter()
            .filter_map(|inst| match inst {
                ExtendedInstruction::TemplateBody { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
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
